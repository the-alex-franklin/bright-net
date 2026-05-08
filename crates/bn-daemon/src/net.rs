use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use bn_core::chain::AvatarChain;
use bn_handshake::handshake::{HandshakeOffer, HandshakeResponse};

// ── Wire protocol ─────────────────────────────────────────────────────────────
// Messages are framed as: 4-byte big-endian length + JSON bytes.

async fn read_msg(stream: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("reading message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.context("reading message body")?;
    Ok(buf)
}

async fn write_msg(stream: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await.context("writing message length")?;
    stream.write_all(data).await.context("writing message body")?;
    Ok(())
}

// ── TLS helpers ───────────────────────────────────────────────────────────────

fn self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["bright-net".into()])
        .context("generating self-signed cert")?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    Ok((vec![cert_der], key_der))
}

// The trust anchor for bright-net is the avatar chain, not the TLS certificate.
// For the POC, the server presents a self-signed cert; the client skips verification.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss, &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss, &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> Result<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("building rustls client config")?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| anyhow::anyhow!("QuicClientConfig: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Start a QUIC server, accept one inbound handshake, record it, return the peer's id.
pub async fn serve(chain: &mut AvatarChain, bind_addr: SocketAddr) -> Result<String> {
    let (cert_chain, key) = self_signed_cert()?;
    let server_config = quinn::ServerConfig::with_single_cert(cert_chain, key)
        .context("building server config")?;

    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .context("binding QUIC endpoint")?;
    println!("listening on {bind_addr}");

    let incoming = endpoint.accept().await.context("endpoint closed before any connection")?;
    let conn = incoming.await.context("connection failed")?;
    println!("connection from {}", conn.remote_address());

    let (mut send, mut recv) = conn.accept_bi().await.context("accepting stream")?;

    // Read offer
    let offer_bytes = read_msg(&mut recv).await?;
    let offer: HandshakeOffer = serde_json::from_slice(&offer_bytes).context("deserializing offer")?;

    // Build and send response
    let response = HandshakeResponse::create(chain, &offer)
        .map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;
    let response_bytes = serde_json::to_vec(&response).context("serializing response")?;
    write_msg(&mut send, &response_bytes).await?;
    send.finish().context("closing send stream")?;

    // Record the handshake in our chain
    let peer_key = offer.token.verifying_key()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let peer_tip = offer.token.chain_tip_hash_bytes()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    chain.record_handshake(&peer_key, peer_tip)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let peer_id = hex::encode(peer_key.to_bytes());
    Ok(peer_id)
}

/// Connect to a peer, perform a handshake, record it, return the peer's id.
pub async fn connect(chain: &mut AvatarChain, peer_addr: SocketAddr) -> Result<String> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)
        .context("creating client endpoint")?;
    endpoint.set_default_client_config(client_config()?);

    let conn = endpoint.connect(peer_addr, "bright-net")
        .context("initiating connection")?
        .await
        .context("connection failed")?;

    let (mut send, mut recv) = conn.open_bi().await.context("opening stream")?;

    // Send offer
    let offer = HandshakeOffer::create(chain)
        .map_err(|e| anyhow::anyhow!("creating offer: {e}"))?;
    let offer_bytes = serde_json::to_vec(&offer).context("serializing offer")?;
    write_msg(&mut send, &offer_bytes).await?;
    send.finish().context("closing send stream")?;

    // Read and verify response
    let response_bytes = read_msg(&mut recv).await?;
    let response: HandshakeResponse = serde_json::from_slice(&response_bytes)
        .context("deserializing response")?;
    response.verify(&offer).map_err(|e| anyhow::anyhow!("response verification failed: {e}"))?;

    // Record the handshake in our chain
    let peer_key = response.token.verifying_key()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let peer_tip = response.token.chain_tip_hash_bytes()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    chain.record_handshake(&peer_key, peer_tip)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let peer_id = hex::encode(peer_key.to_bytes());
    Ok(peer_id)
}

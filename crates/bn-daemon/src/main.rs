use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use bn_core::chain::AvatarChain;

mod net;
mod store;

#[derive(Parser)]
#[command(name = "bn-daemon", about = "Bright-net identity daemon")]
struct Cli {
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new identity on this device
    Init {
        #[arg(long)]
        label: Option<String>,
    },
    /// Show identity status
    Status,
    /// Listen for an inbound handshake
    Serve {
        /// Address to listen on (default: 0.0.0.0:4433)
        #[arg(default_value = "0.0.0.0:4433")]
        addr: SocketAddr,
    },
    /// Initiate a handshake with a peer
    Connect {
        /// Peer address (e.g. 192.168.1.1:4433)
        addr: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let base = cli.data_dir.unwrap_or_else(store::default_base_dir);

    match cli.command {
        Command::Init { label } => cmd_init(&base, label),
        Command::Status => cmd_status(&base),
        Command::Serve { addr } => cmd_serve(&base, addr).await,
        Command::Connect { addr } => cmd_connect(&base, addr).await,
    }
}

fn cmd_init(base: &Path, label: Option<String>) -> Result<()> {
    let key_path = store::key_path(base);
    if key_path.exists() {
        bail!(
            "identity already exists at {}. Use 'status' to inspect it.",
            base.display()
        );
    }

    let chain = AvatarChain::new(label).context("creating identity")?;
    let key_bytes = chain.signing_key_bytes();
    store::save_key(&key_bytes, &key_path).context("saving key")?;
    chain.save(&store::chain_path(base)).context("saving chain")?;

    let id = chain.id().context("computing id")?;
    println!("identity created");
    println!("id  {}", &id[..16]);
    Ok(())
}

fn cmd_status(base: &Path) -> Result<()> {
    let chain = load_chain(base)?;
    let id = chain.id().context("computing id")?;
    let tip = hex::encode(chain.tip_hash().context("computing tip")?);
    println!("id      {}", &id[..16]);
    println!("height  {}", chain.height());
    println!("tip     {}", &tip[..16]);
    Ok(())
}

async fn cmd_serve(base: &Path, addr: SocketAddr) -> Result<()> {
    let mut chain = load_chain(base)?;
    let peer_id = net::serve(&mut chain, addr).await?;
    save_chain(base, &chain)?;
    println!("handshake complete");
    println!("peer    {}", &peer_id[..16]);
    println!("height  {}", chain.height());
    Ok(())
}

async fn cmd_connect(base: &Path, addr: SocketAddr) -> Result<()> {
    let mut chain = load_chain(base)?;
    let peer_id = net::connect(&mut chain, addr).await?;
    save_chain(base, &chain)?;
    println!("handshake complete");
    println!("peer    {}", &peer_id[..16]);
    println!("height  {}", chain.height());
    Ok(())
}

fn load_chain(base: &Path) -> Result<AvatarChain> {
    let key = store::load_key(&store::key_path(base)).context("loading key")?;
    AvatarChain::load(&store::chain_path(base), key).context("loading chain")
}

fn save_chain(base: &Path, chain: &AvatarChain) -> Result<()> {
    chain.save(&store::chain_path(base)).context("saving chain")
}

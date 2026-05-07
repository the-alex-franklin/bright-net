use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use bn_core::tree::AvatarTree;

mod store;

#[derive(Parser)]
#[command(name = "bn-daemon", about = "Bright-net identity daemon")]
struct Cli {
    /// Base data directory (default: ~/.bright-net)
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
    /// Show identity and branch status
    Status,
    /// Manage avatar branches
    Branch {
        #[command(subcommand)]
        cmd: BranchCmd,
    },
}

#[derive(Subcommand)]
enum BranchCmd {
    /// Create a new avatar branch
    New {
        #[arg(long)]
        label: Option<String>,
    },
    /// List all avatar branches
    List,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let base = cli.data_dir.unwrap_or_else(store::default_base_dir);

    match cli.command {
        Command::Init { label } => cmd_init(&base, label),
        Command::Status => cmd_status(&base),
        Command::Branch { cmd } => match cmd {
            BranchCmd::New { label } => cmd_branch_new(&base, label),
            BranchCmd::List => cmd_branch_list(&base),
        },
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

    let tree = AvatarTree::new(label).context("creating identity")?;
    let key_bytes = tree.root_signing_key_bytes();
    store::save_key(&key_bytes, &key_path).context("saving root key")?;
    tree.save(base).context("saving identity")?;

    let root_id = tree.root_id().context("computing root id")?;
    println!("identity created");
    println!("root  {}", &root_id[..16]);
    Ok(())
}

fn cmd_status(base: &Path) -> Result<()> {
    let tree = load_tree(base)?;
    let root_id = tree.root_id().context("computing root id")?;

    println!("root  {}  branches={}", &root_id[..16], tree.branch_count());

    let mut ids: Vec<&str> = tree.branch_ids();
    ids.sort();
    for id in ids {
        let branch = tree.branch(id).unwrap();
        let label = branch.cert.label.as_deref().unwrap_or("(unlabeled)");
        let tip = hex::encode(branch.chain.tip_hash().context("computing tip")?);
        println!(
            "  branch {}  {}  height={}  tip={}",
            &id[..16],
            label,
            branch.chain.height(),
            &tip[..16],
        );
    }

    Ok(())
}

fn cmd_branch_new(base: &Path, label: Option<String>) -> Result<()> {
    let mut tree = load_tree(base)?;
    let branch_id = tree.new_branch(label.clone()).context("creating branch")?;
    tree.save(base).context("saving identity")?;

    let display_label = label.as_deref().unwrap_or("(unlabeled)");
    println!("branch created  {}  {}", &branch_id[..16], display_label);
    Ok(())
}

fn cmd_branch_list(base: &Path) -> Result<()> {
    let tree = load_tree(base)?;

    if tree.branch_count() == 0 {
        println!("no branches — use 'branch new' to create one");
        return Ok(());
    }

    let mut ids: Vec<&str> = tree.branch_ids();
    ids.sort();
    for id in ids {
        let branch = tree.branch(id).unwrap();
        let label = branch.cert.label.as_deref().unwrap_or("(unlabeled)");
        let tip = hex::encode(branch.chain.tip_hash().context("computing tip")?);
        println!(
            "{}  {}  height={}  tip={}",
            &id[..16],
            label,
            branch.chain.height(),
            &tip[..16],
        );
    }

    Ok(())
}

fn load_tree(base: &Path) -> Result<AvatarTree> {
    let key = store::load_key(&store::key_path(base)).context("loading root key")?;
    AvatarTree::load(base, key).context("loading identity")
}

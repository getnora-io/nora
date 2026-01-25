use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nora-cli")]
#[command(about = "CLI tool for Nora registry")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Login to a registry
    Login {
        #[arg(long)]
        registry: String,
        #[arg(short, long)]
        username: String,
    },
    /// Push an artifact
    Push {
        #[arg(long)]
        registry: String,
        path: String,
    },
    /// Pull an artifact
    Pull {
        #[arg(long)]
        registry: String,
        artifact: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Login { registry, username } => {
            println!("Logging in to {} as {}", registry, username);
            // TODO: implement
        }
        Commands::Push { registry, path } => {
            println!("Pushing {} to {}", path, registry);
            // TODO: implement
        }
        Commands::Pull { registry, artifact } => {
            println!("Pulling {} from {}", artifact, registry);
            // TODO: implement
        }
    }
}

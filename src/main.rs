use clap::{Parser, Subcommand};
use shadow_rs::shadow;

shadow!(build);

#[derive(Parser, Debug)]
#[command(name = "cloak")]
#[command(author = "Antony")]
#[command(version = build::CLAP_LONG_VERSION)]
#[command(about = "Secret operations made simple", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new age-compatible key pair
    Keygen,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            println!("keygen subcommand triggered!");
        }
    }
}
use clap::{Parser, Subcommand};
use shadow_rs::shadow;
use std::fs;
use std::path::PathBuf;
use age::x25519::Recipient;

mod config;
mod crypto;
mod keys;

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
    /// Initialize a .cloak config file in the current directory
    Init,

    /// Generate a new age-compatible key pair
    Keygen,

    /// Encrypt a file using the local public key
    Encrypt {
        /// The path to the file you want to encrypt
        file: PathBuf,
    },

    /// Decrypt a file using the local private key
    Decrypt {
        /// The path to the encrypted file
        file: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            // 1. Load the local recipient key
            let recipient = match keys::load_recipient() {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("Error loading key: {}\nHave you run `cloak keygen`?", err);
                    std::process::exit(1);
                }
            };

            // 2. Create the default .cloak file
            if let Err(err) = config::create_default_config(&recipient.to_string()) {
                eprintln!("Init error: {}", err);
                std::process::exit(1);
            }
        }

        Commands::Keygen => {
            if let Err(err) = keys::generate_key() {
                eprintln!("Error: {}", err);
                std::process::exit(1);
            }
        }

        Commands::Encrypt { file } => {
            if let Err(err) = run_encrypt(&file) {
                eprintln!("Encryption error: {}", err);
                std::process::exit(1);
            }
        }

        Commands::Decrypt { file } => {
            if let Err(err) = run_decrypt(&file) {
                eprintln!("Decryption error: {}", err);
                std::process::exit(1);
            }
        }
    }
}

/// Reads the file, encrypts it using recipients from .cloak (or local key fallback)
fn run_encrypt(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Determine recipients to encrypt to
    let recipients: Vec<Recipient> = match config::load_config()? {
        Some(cfg) if !cfg.recipients.is_empty() => {
            println!("Using recipients defined in .cloak");
            let mut list = Vec::new();
            for r_str in &cfg.recipients {
                list.push(keys::parse_recipient(r_str)?);
            }
            list
        }
        _ => {
            println!("No .cloak found (or no recipients in it); using local key");
            vec![keys::load_recipient()?]
        }
    };

    // 2. Read plaintext from disk
    let plaintext = fs::read(path)?;

    // 3. Encrypt to all recipients
    let encrypted_armored = crypto::encrypt_bytes(&plaintext, &recipients)?;

    // 4. Write output file
    let out_path = path.with_extension(format!(
        "{}.cloak",
        path.extension().unwrap_or_default().to_str().unwrap_or("")
    ));
    fs::write(&out_path, encrypted_armored)?;

    println!("Encrypted -> {}", out_path.display());
    Ok(())
}

fn run_decrypt(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let armored_ciphertext = fs::read_to_string(path)?;
    let identity = keys::load_identity()?;
    let decrypted_bytes = crypto::decrypt_bytes(&armored_ciphertext, &identity)?;

    let out_path = path.with_extension("decrypted");
    fs::write(&out_path, decrypted_bytes)?;

    println!("Decrypted -> {}", out_path.display());
    Ok(())
}
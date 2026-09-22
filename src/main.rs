use clap::{Parser, Subcommand};
use shadow_rs::shadow;
use std::fs;
use std::path::PathBuf;

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

/// Reads the file, encrypts it, and writes out a .cloak file
fn run_encrypt(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read plaintext from disk
    let plaintext = fs::read(path)?;

    // 2. Load the public key from our config directory
    let recipient = keys::load_recipient()?;

    // 3. Encrypt the data
    let encrypted_armored = crypto::encrypt_bytes(&plaintext, &recipient)?;

    // 4. Save to a new file named <original>.cloak
    let out_path = path.with_extension(format!(
        "{}.cloak",
        path.extension().unwrap_or_default().to_str().unwrap_or("")
    ));
    fs::write(&out_path, encrypted_armored)?;

    println!("Encrypted -> {}", out_path.display());
    Ok(())
}

/// Reads the .cloak file, decrypts it, and writes the plaintext
fn run_decrypt(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read armored ciphertext from disk
    let armored_ciphertext = fs::read_to_string(path)?;

    // 2. Load the private key from our config directory
    let identity = keys::load_identity()?;

    // 3. Decrypt the data
    let decrypted_bytes = crypto::decrypt_bytes(&armored_ciphertext, &identity)?;

    // 4. Save to a restored file name (or print to stdout)
    let out_path = path.with_extension("decrypted");
    fs::write(&out_path, decrypted_bytes)?;

    println!("Decrypted -> {}", out_path.display());
    Ok(())
}
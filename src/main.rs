use clap::{Parser, Subcommand};
use regex::Regex;
use shadow_rs::shadow;
use std::fs;
use std::path::{Path, PathBuf};

mod config;
mod crypto;
mod keys;
mod structured;

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

    /// Encrypt a file (structured in-place for YAML, or full file encryption)
    Encrypt {
        /// Modify the file in place instead of creating a .cloak copy
        #[arg(short, long)]
        in_place: bool,

        /// The path to the file you want to encrypt
        file: PathBuf,
    },

    /// Decrypt a file (structured in-place for YAML, or full file decryption)
    Decrypt {
        /// Modify the file in place
        #[arg(short, long)]
        in_place: bool,

        /// The path to the file you want to decrypt
        file: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let recipient = match keys::load_recipient() {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("Error loading key: {}\nHave you run `cloak keygen`?", err);
                    std::process::exit(1);
                }
            };

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

        Commands::Encrypt { in_place, file } => {
            if let Err(err) = run_encrypt(&file, in_place) {
                eprintln!("Encryption error: {}", err);
                std::process::exit(1);
            }
        }

        Commands::Decrypt { in_place, file } => {
            if let Err(err) = run_decrypt(&file, in_place) {
                eprintln!("Decryption error: {}", err);
                std::process::exit(1);
            }
        }
    }
}

/// Checks if a file path is a YAML file
fn is_yaml(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yaml") | Some("yml")
    )
}

fn run_encrypt(path: &PathBuf, in_place: bool) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load config and recipients
    let cloak_config = config::load_config()?;
    let recipients = match &cloak_config {
        Some(cfg) if !cfg.recipients.is_empty() => {
            let mut list = Vec::new();
            for r_str in &cfg.recipients {
                list.push(keys::parse_recipient(r_str)?);
            }
            list
        }
        _ => vec![keys::load_recipient()?],
    };

    // 2. Structured YAML mode
    if is_yaml(path) {
        println!("Detected YAML file: running structured encryption");
        let content = fs::read_to_string(path)?;
        let mut yaml_val: serde_yaml::Value = serde_yaml::from_str(&content)?;

        // Find matching key regex rule, or default to all keys matching (password|secret|token|key)
        let default_pattern = "^(password|secret|token|key)$".to_string();
        let regex_pattern = cloak_config
            .as_ref()
            .and_then(|cfg| cfg.rules.first())
            .and_then(|r| r.encrypted_regex.as_ref())
            .unwrap_or(&default_pattern);

        let key_regex = Regex::new(regex_pattern)?;

        // In-place encrypt the YAML tree
        structured::encrypt_tree(&mut yaml_val, &key_regex, &recipients)?;

        let out_content = serde_yaml::to_string(&yaml_val)?;
        let out_path = if in_place {
            path.clone()
        } else {
            path.with_extension("enc.yaml")
        };

        fs::write(&out_path, out_content)?;
        println!("Encrypted -> {}", out_path.display());
        return Ok(());
    }

    // 3. Fallback: Full File Age mode
    let plaintext = fs::read(path)?;
    let encrypted_armored = crypto::encrypt_bytes(&plaintext, &recipients)?;
    let out_path = path.with_extension(format!(
        "{}.cloak",
        path.extension().unwrap_or_default().to_str().unwrap_or("")
    ));
    fs::write(&out_path, encrypted_armored)?;
    println!("Encrypted -> {}", out_path.display());

    Ok(())
}

fn run_decrypt(path: &PathBuf, in_place: bool) -> Result<(), Box<dyn std::error::Error>> {
    let identity = keys::load_identity()?;

    // 1. Structured YAML mode
    if is_yaml(path) {
        println!("Detected YAML file: running structured decryption");
        let content = fs::read_to_string(path)?;
        let mut yaml_val: serde_yaml::Value = serde_yaml::from_str(&content)?;

        structured::decrypt_tree(&mut yaml_val, &identity)?;

        let out_content = serde_yaml::to_string(&yaml_val)?;
        let out_path = if in_place {
            path.clone()
        } else {
            path.with_extension("dec.yaml")
        };

        fs::write(&out_path, out_content)?;
        println!("Decrypted -> {}", out_path.display());
        return Ok(());
    }

    // 2. Fallback: Full File Age mode
    let armored_ciphertext = fs::read_to_string(path)?;
    let decrypted_bytes = crypto::decrypt_bytes(&armored_ciphertext, &identity)?;
    let out_path = path.with_extension("decrypted");
    fs::write(&out_path, decrypted_bytes)?;
    println!("Decrypted -> {}", out_path.display());

    Ok(())
}
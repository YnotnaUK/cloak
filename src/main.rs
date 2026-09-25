use age::x25519::{Identity, Recipient};
use clap::{Parser, Subcommand};
use regex::Regex;
use shadow_rs::shadow;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

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

    /// Encrypt a specific file, or all files matching rules in .cloak
    #[command(alias = "e")]
    Encrypt {
        /// Optional path to a specific file. If omitted, scans all files matching .cloak rules.
        file: Option<PathBuf>,
    },

    /// Decrypt a specific file, or all files matching rules in .cloak
    #[command(alias = "d")]
    Decrypt {
        /// Optional path to a specific file. If omitted, scans all files matching .cloak rules.
        file: Option<PathBuf>,
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

        Commands::Encrypt { file } => {
            if let Err(err) = handle_encrypt(file) {
                eprintln!("Encryption error: {}", err);
                std::process::exit(1);
            }
        }

        Commands::Decrypt { file } => {
            if let Err(err) = handle_decrypt(file) {
                eprintln!("Decryption error: {}", err);
                std::process::exit(1);
            }
        }
    }
}

/// Resolves recipients from .cloak (or falls back to local key)
fn resolve_recipients(cfg: &Option<config::CloakConfig>) -> Result<Vec<Recipient>, Box<dyn std::error::Error>> {
    match cfg {
        Some(c) if !c.recipients.is_empty() => {
            let mut list = Vec::new();
            for r_str in &c.recipients {
                list.push(keys::parse_recipient(r_str)?);
            }
            Ok(list)
        }
        _ => Ok(vec![keys::load_recipient()?]),
    }
}

fn handle_encrypt(file: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let cloak_config = config::load_config()?;
    let recipients = resolve_recipients(&cloak_config)?;

    if let Some(path) = file {
        // Single file mode
        encrypt_single_file(&path, &recipients, &cloak_config)?;
    } else {
        // Multi-file batch mode driven by .cloak
        let cfg = cloak_config.ok_or("No .cloak configuration file found. Run `cloak init` first.")?;
        println!("Scanning directory using .cloak rules...");

        for entry in WalkDir::new(".").into_iter().filter_entry(|e| !is_ignored(e)) {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                // Check if file matches any rule in .cloak
                for rule in &cfg.rules {
                    if rule.matches_path(path) {
                        println!("-> Encrypting: {}", path.display());
                        encrypt_with_rule(path, &recipients, rule)?;
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

fn handle_decrypt(file: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let identity = keys::load_identity()?;
    let cloak_config = config::load_config()?;

    if let Some(path) = file {
        decrypt_single_file(&path, &identity, &cloak_config)?;
    } else {
        let cfg = cloak_config.ok_or("No .cloak configuration file found. Run `cloak init` first.")?;
        println!("Scanning directory using .cloak rules...");

        for entry in WalkDir::new(".").into_iter().filter_entry(|e| !is_ignored(e)) {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                for rule in &cfg.rules {
                    if rule.matches_path(path) {
                        println!("-> Decrypting: {}", path.display());
                        decrypt_with_rule(path, &identity, rule)?;
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Skips target, .git, etc.
fn is_ignored(entry: &walkdir::DirEntry) -> bool {
    entry.file_name()
        .to_str()
        .map(|s| s == "target" || s == ".git" || s == ".cloak")
        .unwrap_or(false)
}

fn encrypt_with_rule(
    path: &Path,
    recipients: &[Recipient],
    rule: &config::Rule,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "yaml" | "yml" => {
            let content = fs::read_to_string(path)?;
            let mut val: serde_yaml::Value = serde_yaml::from_str(&content)?;
            let pattern = rule.encrypted_regex.as_deref().unwrap_or(".*");
            let key_regex = Regex::new(pattern)?;

            structured::encrypt_tree(&mut val, &key_regex, recipients)?;
            fs::write(path, serde_yaml::to_string(&val)?)?;
        }
        "json" => {
            let content = fs::read_to_string(path)?;
            let mut val: serde_json::Value = serde_json::from_str(&content)?;
            let pattern = rule.encrypted_regex.as_deref().unwrap_or(".*");
            let key_regex = Regex::new(pattern)?;

            structured::encrypt_json_tree(&mut val, &key_regex, recipients)?;
            fs::write(path, serde_json::to_string_pretty(&val)?)?;
        }
        _ => {
            // Full file encryption for raw files
            let plaintext = fs::read(path)?;
            let encrypted = crypto::encrypt_bytes(&plaintext, recipients)?;
            fs::write(path, encrypted)?;
        }
    }
    Ok(())
}

fn decrypt_with_rule(
    path: &Path,
    identity: &Identity,
    _rule: &config::Rule,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "yaml" | "yml" => {
            let content = fs::read_to_string(path)?;
            let mut val: serde_yaml::Value = serde_yaml::from_str(&content)?;
            structured::decrypt_tree(&mut val, identity)?;
            fs::write(path, serde_yaml::to_string(&val)?)?;
        }
        "json" => {
            let content = fs::read_to_string(path)?;
            let mut val: serde_json::Value = serde_json::from_str(&content)?;
            structured::decrypt_json_tree(&mut val, identity)?;
            fs::write(path, serde_json::to_string_pretty(&val)?)?;
        }
        _ => {
            // Full file decryption for raw files
            let armored = fs::read_to_string(path)?;
            let decrypted = crypto::decrypt_bytes(&armored, identity)?;
            fs::write(path, decrypted)?;
        }
    }
    Ok(())
}

fn encrypt_single_file(
    path: &Path,
    recipients: &[Recipient],
    cfg: &Option<config::CloakConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let default_rule = config::Rule {
        path_regex: ".*".to_string(),
        encrypted_regex: Some("^(password|secret|token|key)$".to_string()),
    };

    let rule = cfg.as_ref()
        .and_then(|c| c.rules.iter().find(|r| r.matches_path(path)))
        .unwrap_or(&default_rule);

    encrypt_with_rule(path, recipients, rule)
}

fn decrypt_single_file(
    path: &Path,
    identity: &Identity,
    cfg: &Option<config::CloakConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let default_rule = config::Rule {
        path_regex: ".*".to_string(),
        encrypted_regex: Some("^(password|secret|token|key)$".to_string()),
    };

    let rule = cfg.as_ref()
        .and_then(|c| c.rules.iter().find(|r| r.matches_path(path)))
        .unwrap_or(&default_rule);

    decrypt_with_rule(path, identity, rule)
}
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::env;
use std::fs;

pub const CONFIG_FILE_NAME: &str = ".cloak";

/// A rule specifying which files and which keys to encrypt
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    /// Regex pattern matching filenames this rule applies to
    pub path_regex: String,

    /// Regex pattern matching JSON/YAML keys to encrypt (e.g. ^(password|secret)$)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_regex: Option<String>,
}

/// The root structure of the .cloak file
#[derive(Debug, Serialize, Deserialize)]
pub struct CloakConfig {
    /// List of public recipient keys (e.g. age1...) allowed to decrypt
    pub recipients: Vec<String>,

    /// Rules for file/key targeting
    pub rules: Vec<Rule>,
}

/// Creates a starter .cloak config file in the current working directory
pub fn create_default_config(public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(CONFIG_FILE_NAME);

    // Prevent accidental overwriting of an existing .cloak file
    if path.exists() {
        return Err(format!(
            "'{}' already exists in this directory. Refusing to overwrite.",
            CONFIG_FILE_NAME
        )
        .into());
    }

    // Build the default configuration struct
    let config = CloakConfig {
        recipients: vec![public_key.to_string()],
        rules: vec![Rule {
            path_regex: ".*".to_string(),
            encrypted_regex: Some("^(password|secret|token|key)$".to_string()),
        }],
    };

    // Serialize the struct to a clean YAML string
    let yaml_string = serde_yaml::to_string(&config)?;

    // Add a helpful header comment
    let file_content = format!(
        "# Cloak configuration file\n# Run `cloak encrypt <file>` to encrypt using these recipients\n\n{}",
        yaml_string
    );

    // Write to disk
    std::fs::write(path, file_content)?;

    println!("Initialized configuration in {}", CONFIG_FILE_NAME);
    println!("Added default recipient: {}", public_key);

    Ok(())
}

/// Finds the nearest .cloak file by walking upwards from the current directory
pub fn find_config_file() -> Option<PathBuf> {
    let mut current_dir = env::current_dir().ok()?;

    loop {
        let config_path = current_dir.join(CONFIG_FILE_NAME);
        if config_path.is_file() {
            return Some(config_path);
        }

        // Move to parent folder; if there is no parent, stop searching
        if !current_dir.pop() {
            break;
        }
    }

    None
}

/// Loads and parses the nearest .cloak file if it exists
pub fn load_config() -> Result<Option<CloakConfig>, Box<dyn std::error::Error>> {
    let config_path = match find_config_file() {
        Some(path) => path,
        None => return Ok(None), // Not an error if no config exists, just return None
    };

    let content = fs::read_to_string(&config_path)?;
    let config: CloakConfig = serde_yaml::from_str(&content)?;

    Ok(Some(config))
}
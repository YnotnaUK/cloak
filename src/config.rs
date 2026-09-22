use regex::Regex;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const CONFIG_FILE_NAME: &str = ".cloak";

/// A rule specifying which files to target and which keys to encrypt
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rule {
    /// Regex pattern matching filenames this rule applies to (e.g. `.*\.yaml$`, `.*\.env$`)
    pub path_regex: String,

    /// Optional regex for JSON/YAML keys. If None, the entire file is encrypted (age mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_regex: Option<String>,
}

impl Rule {
    /// Checks if a file path matches this rule's path_regex
    pub fn matches_path(&self, path: &Path) -> bool {
        let path_str = path.to_str().unwrap_or("");
        if let Ok(re) = Regex::new(&self.path_regex) {
            re.is_match(path_str)
        } else {
            false
        }
    }
}

/// The root structure of the .cloak file
#[derive(Debug, Serialize, Deserialize)]
pub struct CloakConfig {
    /// List of public recipient keys (age1...) allowed to decrypt
    pub recipients: Vec<String>,

    /// Rules for file targeting
    pub rules: Vec<Rule>,
}

/// Creates a starter .cloak config file in the current working directory
pub fn create_default_config(public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(CONFIG_FILE_NAME);

    if path.exists() {
        return Err(format!(
            "'{}' already exists in this directory. Refusing to overwrite.",
            CONFIG_FILE_NAME
        )
        .into());
    }

    // Default configuration with examples of both structured and full-file rules
    let config = CloakConfig {
        recipients: vec![public_key.to_string()],
        rules: vec![
            Rule {
                path_regex: r".*\.(yaml|yml|json)$".to_string(),
                encrypted_regex: Some("^(password|secret|token|key)$".to_string()),
            },
            Rule {
                path_regex: r".*\.env$".to_string(),
                encrypted_regex: None, // No encrypted_regex means whole-file encryption
            },
        ],
    };

    let yaml_string = serde_yaml::to_string(&config)?;
    let file_content = format!(
        "# Cloak configuration file\n# Run `cloak encrypt` or `cloak decrypt` to process all matching files\n\n{}",
        yaml_string
    );

    fs::write(path, file_content)?;

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
        None => return Ok(None),
    };

    let content = fs::read_to_string(&config_path)?;
    let config: CloakConfig = serde_yaml::from_str(&content)?;

    Ok(Some(config))
}
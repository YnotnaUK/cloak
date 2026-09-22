use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::PathBuf;

/// Determines the standard config directory: ~/.config/cloak/
fn get_config_dir() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|path| path.join("cloak"))
        .ok_or_else(|| "Could not determine system configuration directory".to_string())
}

/// Generates a new key pair and saves the private key to the config folder
pub fn generate_key() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate an X25519 identity (private key)
    let identity = Identity::generate();
    
    // 2. Extract the public recipient (public key) from the private key
    let recipient = identity.to_public();

    // 3. Find ~/.config/cloak and make sure the folder exists
    let config_dir = get_config_dir()?;
    fs::create_dir_all(&config_dir)?;

    let key_file_path = config_dir.join("key.txt");

    // Check if a key already exists to prevent accidental overwriting
    if key_file_path.exists() {
        return Err(format!(
            "Key file already exists at: {}\nRefusing to overwrite.",
            key_file_path.display()
        )
        .into());
    }

    // 4. Format the file content (matches standard age format)
    // The secret string is wrapped in `ExposeSecret` to prevent accidental logging
    let content = format!(
        "# created by cloak\n# public key: {}\n{}\n",
        recipient,
        identity.to_string().expose_secret()
    );

    // 5. Write to the file
    let mut file = File::create(&key_file_path)?;
    file.write_all(content.as_bytes())?;

    // 6. Set Linux file permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&key_file_path, permissions)?;
    }

    // 7. Print the results to the user
    println!("Public key: {}", recipient);
    println!("Private key saved to: {}", key_file_path.display());

    Ok(())
}

/// Returns the path to the default key file (~/.config/cloak/key.txt)
pub fn get_default_key_path() -> Result<PathBuf, String> {
    let config_dir = get_config_dir()?;
    Ok(config_dir.join("key.txt"))
}

/// Loads the private identity from disk
pub fn load_identity() -> Result<Identity, Box<dyn std::error::Error>> {
    let path = get_default_key_path()?;

    if !path.exists() {
        return Err(format!(
            "No key found at: {}\nRun `cloak keygen` first!",
            path.display()
        )
        .into());
    }

    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);

    let identity_file = age::IdentityFile::from_buffer(&mut reader)
        .map_err(|e| format!("Failed to parse key file: {}", e))?;

    let identities = identity_file.into_identities();

    match identities.into_iter().next() {
        Some(age::IdentityFileEntry::Native(id)) => Ok(id),
        None => Err("No valid keys found in key file".into()),
    }
}

/// Loads the public recipient key matching our local identity
pub fn load_recipient() -> Result<Recipient, Box<dyn std::error::Error>> {
    let identity = load_identity()?;
    Ok(identity.to_public())
}
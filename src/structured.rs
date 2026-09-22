use age::x25519::{Identity, Recipient};
use regex::Regex;
use serde_yaml::{Mapping, Value};

use crate::crypto;

const ENC_PREFIX: &str = "ENC[AGE,";
const ENC_SUFFIX: &str = "]";

/// Checks if a string value is already encrypted
fn is_encrypted(s: &str) -> bool {
    s.starts_with(ENC_PREFIX) && s.ends_with(ENC_SUFFIX)
}

/// Encrypts a single string value into the ENC[AGE,<base64>] format
fn encrypt_value(
    val_str: &str,
    recipients: &[Recipient],
) -> Result<String, Box<dyn std::error::Error>> {
    let base64_ciphertext = crypto::encrypt_to_base64(val_str.as_bytes(), recipients)?;
    Ok(format!("{}{}{}", ENC_PREFIX, base64_ciphertext, ENC_SUFFIX))
}

/// Decrypts a single ENC[AGE,<base64>] string back to its plaintext
fn decrypt_value(
    enc_str: &str,
    identity: &Identity,
) -> Result<String, Box<dyn std::error::Error>> {
    let inner_base64 = &enc_str[ENC_PREFIX.len()..enc_str.len() - ENC_SUFFIX.len()];
    let decrypted_bytes = crypto::decrypt_from_base64(inner_base64, identity)?;
    let plaintext = String::from_utf8(decrypted_bytes)?;
    Ok(plaintext)
}

/// Recursively walks the YAML tree to encrypt values whose keys match the regex
pub fn encrypt_tree(
    value: &mut Value,
    key_regex: &Regex,
    recipients: &[Recipient],
) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        Value::Mapping(map) => {
            let mut new_map = Mapping::new();

            for (k, mut v) in map.clone().into_iter() {
                let key_name = k.as_str().unwrap_or("");
                let should_encrypt = key_regex.is_match(key_name);

                if should_encrypt {
                    // If it's a scalar value (string/number/bool), encrypt it
                    if let Some(s) = v.as_str() {
                        if !is_encrypted(s) {
                            let enc = encrypt_value(s, recipients)?;
                            v = Value::String(enc);
                        }
                    }
                } else {
                    // Otherwise, recurse deeper into nested structures
                    encrypt_tree(&mut v, key_regex, recipients)?;
                }

                new_map.insert(k, v);
            }

            *map = new_map;
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                encrypt_tree(item, key_regex, recipients)?;
            }
        }
        _ => {}
    }

    Ok(())
}

/// Recursively walks the YAML tree and decrypts any ENC[AGE,...] string values
pub fn decrypt_tree(
    value: &mut Value,
    identity: &Identity,
) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        Value::Mapping(map) => {
            for (_, v) in map.iter_mut() {
                decrypt_tree(v, identity)?;
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                decrypt_tree(item, identity)?;
            }
        }
        Value::String(s) => {
            if is_encrypted(s) {
                let decrypted = decrypt_value(s, identity)?;
                *s = decrypted;
            }
        }
        _ => {}
    }

    Ok(())
}
use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::x25519::{Identity, Recipient};
use std::io::{Read, Write};
use base64::prelude::*;

/// Encrypts bytes to one or more public recipients, returning an armored (ASCII) string
pub fn encrypt_bytes(
    plaintext: &[u8],
    recipients: &[Recipient],
) -> Result<String, Box<dyn std::error::Error>> {
    if recipients.is_empty() {
        return Err("Cannot encrypt without at least one recipient".into());
    }

    let mut encrypted_output = Vec::new();

    {
        // 1. Wrap the vector with an ASCII armor writer
        let armor_writer = ArmoredWriter::wrap_output(&mut encrypted_output, Format::AsciiArmor)?;

        // 2. Convert each Recipient into a Box<dyn age::Recipient>
        let recipient_boxes: Vec<Box<dyn age::Recipient + Send>> = recipients
            .iter()
            .map(|r| Box::new(r.clone()) as Box<dyn age::Recipient + Send>)
            .collect();

        // 3. Build the encryptor pointing to all recipients
        let encryptor = age::Encryptor::with_recipients(recipient_boxes)
            .ok_or("Failed to initialize encryptor with recipients")?;

        let mut age_writer = encryptor.wrap_output(armor_writer)?;

        // 4. Write plaintext
        age_writer.write_all(plaintext)?;

        // 5. Finish both streams cleanly
        let armor_writer = age_writer.finish()?;
        armor_writer.finish()?;
    }

    let armored_str = String::from_utf8(encrypted_output)?;
    Ok(armored_str)
}

/// Decrypts armored text using a private identity
pub fn decrypt_bytes(
    armored_ciphertext: &str,
    identity: &Identity,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cursor = std::io::Cursor::new(armored_ciphertext.as_bytes());

    let armor_reader = ArmoredReader::new(cursor);

    let decryptor = match age::Decryptor::new(armor_reader)? {
        age::Decryptor::Recipients(d) => d,
        _ => return Err("Passphrase encryption not supported, only key-based".into()),
    };

    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut decrypted_output = Vec::new();
    reader.read_to_end(&mut decrypted_output)?;

    Ok(decrypted_output)
}

/// Encrypts bytes directly to raw binary and encodes them as a clean Base64 string (no armor headers)
pub fn encrypt_to_base64(
    plaintext: &[u8],
    recipients: &[Recipient],
) -> Result<String, Box<dyn std::error::Error>> {
    if recipients.is_empty() {
        return Err("Cannot encrypt without at least one recipient".into());
    }

    let mut encrypted_bytes = Vec::new();

    let recipient_boxes: Vec<Box<dyn age::Recipient + Send>> = recipients
        .iter()
        .map(|r| Box::new(r.clone()) as Box<dyn age::Recipient + Send>)
        .collect();

    let encryptor = age::Encryptor::with_recipients(recipient_boxes)
        .ok_or("Failed to initialize encryptor with recipients")?;

    let mut age_writer = encryptor.wrap_output(&mut encrypted_bytes)?;
    age_writer.write_all(plaintext)?;
    age_writer.finish()?;

    // Standard URL/text safe base64 encoding without headers
    Ok(BASE64_STANDARD.encode(&encrypted_bytes))
}

/// Decodes a raw Base64 string and decrypts it with the private identity
pub fn decrypt_from_base64(
    base64_str: &str,
    identity: &Identity,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encrypted_bytes = BASE64_STANDARD.decode(base64_str.trim())?;
    let cursor = std::io::Cursor::new(encrypted_bytes);

    let decryptor = match age::Decryptor::new(cursor)? {
        age::Decryptor::Recipients(d) => d,
        _ => return Err("Passphrase encryption not supported, only key-based".into()),
    };

    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut decrypted_output = Vec::new();
    reader.read_to_end(&mut decrypted_output)?;

    Ok(decrypted_output)
}
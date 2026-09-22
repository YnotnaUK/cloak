use age::armor::{ArmoredWriter, Format};
use age::x25519::{Identity, Recipient};
use std::io::{Read, Write};
use age::armor::ArmoredReader;

/// Encrypts bytes to a public recipient, returning an armored (ASCII) string
pub fn encrypt_bytes(
    plaintext: &[u8],
    recipient: &Recipient,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut encrypted_output = Vec::new();

    {
        // 1. Wrap the vector with an ASCII armor writer
        let armor_writer = ArmoredWriter::wrap_output(&mut encrypted_output, Format::AsciiArmor)?;

        // 2. Wrap the armor writer with the age encryptor
        let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone())])
            .ok_or("Failed to initialize encryptor with recipient")?;

        let mut age_writer = encryptor.wrap_output(armor_writer)?;

        // 3. Write plaintext
        age_writer.write_all(plaintext)?;

        // 4. Explicitly finish both streams in correct order
        let armor_writer = age_writer.finish()?;
        armor_writer.finish()?;
    } // <- Scope ends here, releasing any mutable borrow on encrypted_output

    let armored_str = String::from_utf8(encrypted_output)?;
    Ok(armored_str)
}

/// Decrypts armored text using a private identity
pub fn decrypt_bytes(
    armored_ciphertext: &str,
    identity: &Identity,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cursor = std::io::Cursor::new(armored_ciphertext.as_bytes());

    // 1. Use ArmoredReader directly to unwrap the armor layer
    let armor_reader = ArmoredReader::new(cursor);

    // 2. Pass the unarmored reader to the age Decryptor
    let decryptor = match age::Decryptor::new(armor_reader)? {
        age::Decryptor::Recipients(d) => d,
        _ => return Err("Passphrase encryption not supported, only key-based".into()),
    };

    // 3. Decrypt with our private identity
    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut decrypted_output = Vec::new();
    reader.read_to_end(&mut decrypted_output)?;

    Ok(decrypted_output)
}
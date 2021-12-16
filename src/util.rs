use crate::other_io_error;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use bufstream::BufStream;
use oqs::kem::SharedSecret;
use rand::Rng;
use std::convert::TryInto;
use std::io::Read;
use std::{io::Write, net::TcpStream};

pub fn send_message(
    message: &[u8],
    shared_secret: &SharedSecret,
    stream: &mut BufStream<TcpStream>,
) -> std::io::Result<()> {
    // further communication is AES encrypted with the shared secret

    let key = shared_secret.clone().into_vec();
    let key = Key::from_slice(key.as_ref());
    let cipher = Aes256Gcm::new(key);

    let random_bytes = rand::thread_rng().gen::<[u8; 12]>(); // unique nonce per message
    let nonce = Nonce::from_slice(&random_bytes);

    let ciphertext = cipher
        .encrypt(nonce, message.as_ref())
        .map_err(|_| other_io_error("Couldn't encrypt message payload"))?; // TODO is this authentcated -> by the shared secret?

    match stream.write_all(&random_bytes) {
        Ok(_) => println!("Nonce sent"),
        Err(e) => println!("Failed sending nonce: {}", e),
    }
    match stream.write_all(&(ciphertext.len() as u64).to_be_bytes()) {
        Ok(_) => println!("Ciphertext length sent"),
        Err(e) => println!("Failed sending message: {}", e),
    }
    match stream.write_all(&ciphertext) {
        Ok(_) => println!("Encrypted message sent"),
        Err(e) => println!("Failed sending message: {}", e),
    }
    stream.flush()?;

    Ok(())
}

pub fn read_message(
    shared_secret: &SharedSecret,
    stream: &mut BufStream<TcpStream>,
) -> std::io::Result<()> {
    let key = shared_secret.clone().into_vec();
    let key = Key::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf)?;
    let nonce = Nonce::from_slice(&buf);

    let mut buf = [0u8; u64::BITS as usize / 8];
    stream.read_exact(&mut buf)?;
    let ciphertext_len = u64::from_be_bytes(buf)
        .try_into()
        .map_err(|_| other_io_error("Ciphertext length greater than usize::MAX"))?;
    let mut ciphertext = vec![0u8; ciphertext_len];
    stream.read_exact(&mut ciphertext)?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| other_io_error("Could not decrypt cipthertext"))?;

    let plaintext = String::from_utf8_lossy(&plaintext);
    println!("Received message: {:?}", plaintext);

    Ok(())
}

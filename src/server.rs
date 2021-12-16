use crate::{
    other_io_error,
    util::{read_message, send_message},
    SERVER_ADDRESS,
};
use bufstream::BufStream;
use oqs::{
    kem::Kem,
    sig::{self, Sig},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

pub fn listen_for_incoming_request(
    client_sig_pub: sig::PublicKey,
    server_sig_sec: sig::SecretKey,
    kemalg: &Kem,
    sigalg: &Sig,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(SERVER_ADDRESS).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New client connection");

                let client_sig_pub = client_sig_pub.clone();
                let server_sig_sec = server_sig_sec.clone();

                let mut stream = BufStream::new(stream);

                let shared_secret = server_handshake(
                    &client_sig_pub,
                    &server_sig_sec,
                    kemalg,
                    sigalg,
                    &mut stream,
                )
                .map_err(|_| other_io_error("Couldn't generate shared secret"))?;

                read_message(&shared_secret, &mut stream)?;
                send_message(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body>Hello world</body></html>\r\n", &shared_secret, &mut stream)?
            }
            Err(e) => {
                println!("Could not connect: {}", e);
            }
        }
    }
    Ok(())
}

fn server_handshake(
    client_sig_pub: &sig::PublicKey,
    server_sig_sec: &sig::SecretKey,
    kemalg: &Kem,
    sigalg: &Sig,
    stream: &mut BufStream<TcpStream>,
) -> Result<oqs::kem::SharedSecret, oqs::Error> {
    // Handshake Phase 2:
    // recieve client short term public key
    let mut buf = vec![0u8; kemalg.length_public_key()];
    stream.read_exact(&mut buf).map_err(|e| {
        println!("Couldn't read message: {}", e);
        oqs::Error::Error
    })?;
    let kem_pub = kemalg
        .public_key_from_bytes(&buf)
        .ok_or(oqs::Error::Error)?;

    let mut buf = vec![0u8; sigalg.length_signature()];
    stream.read_exact(&mut buf).map_err(|e| {
        println!("Couldn't read message: {}", e);
        oqs::Error::Error
    })?;
    let signature = sigalg.signature_from_bytes(&buf).ok_or(oqs::Error::Error)?;

    // verify client signature
    sigalg.verify(&kem_pub, signature, client_sig_pub)?;

    // create shared secret + ciphertext
    let (cipertext, shared_secret) = kemalg.encapsulate(&kem_pub)?;
    // send signed ciphertext
    let signed_ciphertext = sigalg.sign(cipertext.as_ref(), server_sig_sec)?;

    // send ciphertext
    match stream.write_all(cipertext.as_ref()) {
        Ok(_) => println!("Handshake Phase 2 ciphertext sent"),
        Err(e) => println!("Failed sending message: {}", e),
    }
    match stream.write_all(signed_ciphertext.as_ref()) {
        Ok(_) => println!("Handshake Phase 2 ciphertext sent"),
        Err(e) => println!("Failed sending message: {}", e),
    }
    stream.flush().map_err(|e| {
        println!("Failed to flush stream: {}", e);
        oqs::Error::Error
    })?;

    Ok(shared_secret)
}

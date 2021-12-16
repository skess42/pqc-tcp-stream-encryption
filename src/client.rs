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
use std::{fs::File, time::Instant};
use std::{
    io::{Read, Write},
    net::TcpStream,
};

pub fn http_request(
    client_sig_sec: &sig::SecretKey,
    server_sig_pub: &sig::PublicKey,
    kemalg: Kem,
    sigalg: Sig,
    handshake_measurement: &mut File,
    request_measurement: &mut File,
) -> std::io::Result<()> {
    if let Ok(stream) = TcpStream::connect(SERVER_ADDRESS) {
        println!("Connected to the server!");
        let mut stream = BufStream::new(stream);
        let shared_secret = handshake(
            &client_sig_sec,
            server_sig_pub,
            kemalg,
            sigalg,
            &mut stream,
            handshake_measurement,
        )
        .map_err(|_| other_io_error("Couldn't generate shared secret"))?;

        let before_request = Instant::now();
        if let Ok(_) = send_message(b"GET /HTTP /1.1 \r\n\r\n", &shared_secret, &mut stream) {
            read_message(&shared_secret, &mut stream)?;
            // until: receive response
        }
        let duration = before_request.elapsed();
        writeln!(request_measurement, "{:.3?}", duration)?;
    } else {
        println!("Couldn't connect to server...");
    }
    Ok(())
}

fn handshake(
    client_sig_sec: &sig::SecretKey,
    server_sig_pub: &sig::PublicKey,
    kemalg: Kem,
    sigalg: Sig,
    stream: &mut BufStream<TcpStream>,
    handshake_measurement: &mut File,
) -> Result<oqs::kem::SharedSecret, oqs::Error> {
    // gernerate short term key pair for agreeing on shared secret
    let (kem_pub, kem_sec) = kemalg.keypair()?;

    // Handshake Phase 1:
    // sign short term public key
    let signed_kem_pub = sigalg.sign(kem_pub.as_ref(), client_sig_sec)?;
    let signature = signed_kem_pub.as_ref();

    let before_handshake = Instant::now();
    // send: [short term public key][signature]
    match stream.write_all(kem_pub.as_ref()) {
        Ok(_) => println!("Handshake Phase 1 message sent"),
        Err(e) => println!("Failed sending message: {}", e),
    }
    match stream.write_all(signature) {
        Ok(_) => println!("Handshake Phase 1 signature sent"),
        Err(e) => println!("Failed sending message: {}", e),
    }
    stream.flush().map_err(|e| {
        println!("Failed to flush stream: {}", e);
        oqs::Error::Error
    })?;

    // Handshake Phase 3:
    // recieve Server response
    // read ciphertext
    let mut buf = vec![0u8; kemalg.length_ciphertext()];
    stream.read_exact(&mut buf).map_err(|e| {
        println!("Couldn't read message: {}", e);
        oqs::Error::Error
    })?;
    let ciphertext = kemalg
        .ciphertext_from_bytes(&buf)
        .ok_or(oqs::Error::Error)?;

    // read signature
    let mut buf = vec![0u8; sigalg.length_signature()];
    stream.read_exact(&mut buf).map_err(|e| {
        println!("Couldn't read message: {}", e);
        oqs::Error::Error
    })?;
    let duration = before_handshake.elapsed();
    writeln!(handshake_measurement, "{:.3?}", duration).unwrap();
    let signature = sigalg.signature_from_bytes(&buf).ok_or(oqs::Error::Error)?;

    // verify server signature
    sigalg.verify(&ciphertext, signature, server_sig_pub)?;

    // decrypt shared secret
    kemalg.decapsulate(&kem_sec, &ciphertext)
}

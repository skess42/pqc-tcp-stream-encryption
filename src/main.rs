use clap::{App, Arg};
use oqs::kem::Kem;
use oqs::sig::Sig;
use oqs::*;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Write};

mod client;
mod server;
mod util;

#[derive(Deserialize, Serialize)]
pub struct MyKeyPair {
    pub_key_bytes: Vec<u8>,
    sec_key_bytes: Vec<u8>,
}

static SERVER_ADDRESS: &str = "10.0.4.3:8080";

fn main() -> std::io::Result<()> {
    let matches = App::new("Bla")
        .version("1.0")
        .arg(
            Arg::with_name("mode")
                .long("mode")
                .required(true)
                .takes_value(true),
        )
        .get_matches();
    let mode = matches.value_of("mode").unwrap().to_string();

    oqs::init();
    let sigalg = Sig::new(sig::Algorithm::Dilithium2)
        .map_err(|_| other_io_error("Couldn't find signature algorithm"))?;
    // the chosen algorithm must generate a shared secret with 32 bytes
    let kemalg = Kem::new(kem::Algorithm::Saber)
        .map_err(|_| other_io_error("Couldn't find kem algorithm"))?;

    if mode == "key_gen".to_string() {
        generate_keys(&sigalg)?;
    } else {
        let (server_key, client_key) = read_keys()?;

        let server_sig_pub = try_read_public_key(&sigalg, &server_key)?;
        let client_sig_pub = try_read_public_key(&sigalg, &client_key)?;

        if mode == "server" {
            let server_sig_sec = try_read_private_key(&sigalg, &server_key)?;
            server::listen_for_incoming_request(client_sig_pub, server_sig_sec, &kemalg, &sigalg)?;
        } else {
            let client_sig_sec = try_read_private_key(&sigalg, &client_key)?;

            let mut handshake_measurement = OpenOptions::new()
                .write(true)
                .append(true)
                .open("handshake-measurement")
                .unwrap();

            let mut request_measurement = OpenOptions::new()
                .write(true)
                .append(true)
                .open("request-measurement")
                .unwrap();

            for _ in 0..1000 {
                // measure 1000 runs
                let sigalg = Sig::new(sig::Algorithm::Dilithium2)
                    .map_err(|_| other_io_error("Couldn't find signature algorithm"))?;
                let kemalg = Kem::new(kem::Algorithm::Saber)
                    .map_err(|_| other_io_error("Couldn't find kem algorithm"))?;
                client::http_request(
                    &client_sig_sec,
                    &server_sig_pub,
                    kemalg,
                    sigalg,
                    &mut handshake_measurement,
                    &mut request_measurement,
                )?;
            }
        }
    }

    Ok(())
}

fn generate_keys(sigalg: &Sig) -> std::io::Result<()> {
    // server's long-term secrets
    let (server_sig_pub, server_sig_sec) = sigalg
        .keypair()
        .map_err(|_| other_io_error("Couldn't generate server keypair"))?;
    let server_sig = MyKeyPair {
        pub_key_bytes: server_sig_pub.into_vec(),
        sec_key_bytes: server_sig_sec.into_vec(),
    };

    let server_sig_json = serde_json::to_string(&server_sig)?;
    let mut file = File::create("server_signature.txt")?;
    file.write_all(server_sig_json.as_bytes())?;

    // client's long-term secrets
    // Assumption: Authenticated public key exchange happened before
    let (client_sig_pub, client_sig_sec) = sigalg
        .keypair()
        .map_err(|_| other_io_error("Couldn't generate client keypair"))?;
    let client_sig = MyKeyPair {
        pub_key_bytes: client_sig_pub.into_vec(),
        sec_key_bytes: client_sig_sec.into_vec(),
    };

    let client_sig_json = serde_json::to_string(&client_sig)?;
    let mut file = File::create("client_signature.txt")?;
    file.write_all(client_sig_json.as_ref())?;
    Ok(())
}

fn read_keys() -> std::io::Result<(MyKeyPair, MyKeyPair)> {
    // load client keys
    let mut f = File::open("server_signature.txt")?;
    let mut key_json = String::new();
    f.read_to_string(&mut key_json)?;
    let srv_key: MyKeyPair = serde_json::from_str(&key_json)?;

    // load client keys
    let mut f = File::open("client_signature.txt")?;
    let mut client_key_json = String::new();
    f.read_to_string(&mut client_key_json)?;
    let cli_key: MyKeyPair = serde_json::from_str(&client_key_json)?;

    Ok((srv_key, cli_key))
}

fn try_read_public_key(sigalg: &Sig, maybe_key: &MyKeyPair) -> std::io::Result<sig::PublicKey> {
    match sigalg.public_key_from_bytes(maybe_key.pub_key_bytes.as_ref()) {
        Some(key) => Ok(key.to_owned()),
        None => Err(other_io_error("Couldn't read private key")),
    }
}

fn try_read_private_key(sigalg: &Sig, maybe_key: &MyKeyPair) -> std::io::Result<sig::SecretKey> {
    match sigalg.secret_key_from_bytes(maybe_key.sec_key_bytes.as_ref()) {
        Some(key) => Ok(key.to_owned()),
        None => Err(other_io_error("Couldn't read private key")),
    }
}

pub fn other_io_error(s: &str) -> std::io::Error {
    Error::new(ErrorKind::Other, s)
}

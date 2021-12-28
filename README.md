# pqc-tcp-stream-encryption

This is a proof-of-concept implementation of a post-quantum secure TCP stream encryption.

It is based on oqs-rs: https://github.com/thomwiggers/oqs-rs/tree/7356ebc96abf3e945e7f431c3ca5f0042b63bc9d

## Installation of oqs-rs

```
git clone https://github.com/thomwiggers/oqs-rs.git
cd oqs-rs
git checkout 7356ebc
cd oqs-sys
rm -r liboqs/
git clone https://github.com/thomwiggers/liboqs.git
cd liboqs
git checkout 1139feed
mkdir build && cd build
cmake -GNinja ..
ninja
```

## Usage

Note: The repositories oqs-rs and pqc-tcp-stream-encryption must be in the same directory.

### Precondition

The client's public key has to be available on the server VM in a file named client_signature.txt
The server's public and secret key has to be available on the server VM in a file named server_signature.txt
The server's public key has to be available on the client VM in a file named server_signature.txt
The client's public and secret key has to be available on the client VM in a file named client_signature.txt
By running `cargo run -- --mode key_gen` you can generate those files each containing a public and a private key.
Example keys are also available in this repository.

### Server

Ensure that the key files are available in `~/pqc-tcp-stream-encryption/`.
Update the path in `Cargo.toml` of oqs-sys and oqs according to their installation location.

In `~/pqc-tcp-stream-encryption/` run:

```
cargo build
./target/debug/pqc-tcp-stream-encryption --mode server
```

### Client

Ensure that the key files are available in `~/pqc-tcp-stream-encryption/`.
Update the path in `Cargo.toml` of oqs-sys and oqs according to their installation location.

In `~/pqc-tcp-stream-encryption/` run:

```
cargo build
./target/debug/pqc-tcp-stream-encryption --mode client
```
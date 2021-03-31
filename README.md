# rust-openssl-kdf
Wrappers for the EVP_KDF functionality of OpenSSL.

*NOTE: Once OpenSSL 3.0 has been released and support for KDF has been added to [rust-openssl](https://github.com/sfackler/rust-openssl), this crate will likely be deprecated.*

This implements Rust wrappers for the EVP_KDF functionality in OpenSSL, among which is KBKDF, as specified in [NIST SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf).

This functionality is currently only available in OpenSSL 3.0, and has been backported to Fedora/RHEL.
Unfortunately, the API is somewhat different between those two versions: right now, this crate is aimed at the backported API.


## Example use (KBKDF in Counter mode with HMAC-SHA256 as PRF)
```
use openssl_kdf::{Kdf, KdfKbMode, KdfMacType, KdfType};
use openssl::hash::MessageDigest;

let kdf = Kdf::new(KdfType::KeyBased).unwrap();
kdf.set_kb_mode(KdfKbMode::Counter).unwrap();

// Use Hmac-SHA256
kdf.set_kb_mac_type(KdfMacType::Hmac).unwrap();
kdf.set_digest(MessageDigest::sha256()).unwrap();
// Set the salt (called "Label" in SP800-108)
kdf.set_salt(&[0x12, 0x34]).unwrap();
// Set the kb info (called "Context" in SP800-108)
kdf.set_kb_info(&[0x56, 0x78]).unwrap();
// Set the key (called "Ki" in SP800-108)
kdf.set_key(&[0x9a, 0xbc]).unwrap();

// Derive 20 bytes worth of key material
let key_out = kdf.derive(20).unwrap();
```

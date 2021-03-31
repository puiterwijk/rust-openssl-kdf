pub mod sys;
#[macro_use]
mod utils;
use utils::{cvt, cvt_p};

use openssl::hash::MessageDigest;

type Result<T> = core::result::Result<T, openssl::error::ErrorStack>;

foreign_type_and_impl_send_sync! {
    type CType = sys::KDF;
    fn drop = sys::EVP_KDF_CTX_free;

    pub struct Kdf;

    pub struct KdfRef;
}

#[allow(unused)]
#[derive(Debug)]
#[repr(i32)]
enum KdfControlOption {
    SetPass = 0x01,
    SetSalt = 0x02,
    SetIter = 0x03,
    SetMd = 0x04,
    SetKey = 0x05,
    SetMaxmemBytes = 0x06,
    SetTlsSecret = 0x07,
    ResetTlsSeed = 0x08,
    AddTlsSeed = 0x09,
    ResetHkdfInfo = 0x0a,
    AddHkdfInfo = 0x0b,
    SetHkdfMode = 0x0c,
    SetScryptN = 0x0d,
    SetScryptR = 0x0e,
    SetScryptP = 0x0f,
    SetSshkdfXcghash = 0x10,
    SetSshkdfSessionId = 0x11,
    SetSshkdfType = 0x12,
    SetKbMode = 0x13,
    SetKbMacType = 0x14,
    SetCipher = 0x15,
    SetKbInfo = 0x16,
    SetKbSeed = 0x17,
    SetKrb5kdfConstant = 0x18,
    SetSskdfInfo = 0x19,
}

#[derive(Debug)]
#[repr(i32)]
pub enum KdfKbMode {
    Counter = 0,
    Feedback = 1,
}

#[derive(Debug)]
pub enum KdfType {
    //PBKDF2,
    //SCRYPT,
    //TLS1_PRF,
    //HKDF,
    //SSHKDF,
    KeyBased,
    //KRB5KDF,
    //SS,
}

impl KdfType {
    fn type_id(&self) -> i32 {
        match self {
            KdfType::KeyBased => 1204,
        }
    }
}

#[derive(Debug)]
#[repr(i32)]
pub enum KdfMacType {
    Hmac = 0,
    Cmac = 1,
}

impl Kdf {
    pub fn new(type_: KdfType) -> Result<Self> {
        unsafe {
            let kdf = Kdf::from_ptr(cvt_p(sys::EVP_KDF_CTX_new_id(type_.type_id()))?);
            Ok(kdf)
        }
    }

    pub fn reset(&self) {
        unsafe { sys::EVP_KDF_reset(self.as_ptr()) }
    }

    pub fn set_kb_mode(&self, mode: KdfKbMode) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbMode as i32,
                mode as i32,
            ))
        }
    }

    pub fn set_kb_mac_type(&self, mac_type: KdfMacType) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbMacType as i32,
                mac_type as i32,
            ))
        }
    }

    pub fn set_salt(&self, salt: &[u8]) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetSalt as i32,
                salt.as_ptr(),
                salt.len(),
            ))
        }
    }

    pub fn set_kb_info(&self, context: &[u8]) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbInfo as i32,
                context.as_ptr(),
                context.len(),
            ))
        }
    }

    pub fn set_key(&self, key: &[u8]) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKey as i32,
                key.as_ptr(),
                key.len(),
            ))
        }
    }

    pub fn set_digest(&self, digest: MessageDigest) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetMd as i32,
                digest.as_ptr(),
            ))
        }
    }

    pub fn derive(&self, key_len: usize) -> Result<Vec<u8>> {
        unsafe {
            let mut key_out: Vec<u8> = vec![0; key_len];
            cvt(sys::EVP_KDF_derive(
                self.as_ptr(),
                key_out.as_mut_ptr(),
                key_len,
            ))?;
            Ok(key_out)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Kdf, KdfKbMode, KdfMacType, KdfType};
    use openssl::hash::MessageDigest;

    #[test]
    fn it_works() {
        let deadbeef = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let kdf = Kdf::new(KdfType::KeyBased).unwrap();
        kdf.set_kb_mode(KdfKbMode::Counter).unwrap();
        kdf.set_kb_mac_type(KdfMacType::Hmac).unwrap();
        kdf.set_salt(&deadbeef).unwrap();
        kdf.set_kb_info(&deadbeef).unwrap();
        kdf.set_key(&deadbeef).unwrap();
        kdf.set_digest(MessageDigest::sha256()).unwrap();

        let key_out = kdf.derive(20).unwrap();

        assert_eq!(
            key_out,
            vec![
                0x76, 0xF4, 0x63, 0xE2, 0xDF, 0x22, 0xD3, 0xDE, 0x02, 0xFD, 0x02, 0xCA, 0x59, 0x58,
                0x16, 0xBD, 0xCE, 0x3D, 0x19, 0xB0
            ],
        );
    }
}

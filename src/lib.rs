#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum KdfKbMode {
    Counter,
    Feedback,
}

#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum KdfMacType {
    Hmac(openssl::hash::MessageDigest),
    Cmac(openssl::symm::Cipher),
}

impl KdfMacType {
    fn has_md(&self) -> bool {
        matches!(self, KdfMacType::Hmac(_))
    }

    fn get_md(&self) -> Option<&openssl::hash::MessageDigest> {
        match self {
            KdfMacType::Hmac(md) => Some(md),
            KdfMacType::Cmac(_) => None,
        }
    }

    fn has_cipher(&self) -> bool {
        matches!(self, KdfMacType::Cmac(_))
    }

    fn get_cipher(&self) -> Option<&openssl::symm::Cipher> {
        match self {
            KdfMacType::Cmac(cipher) => Some(cipher),
            KdfMacType::Hmac(_) => None,
        }
    }
}

impl std::fmt::Debug for KdfMacType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KdfMacType::Hmac(md) => write!(f, "Hmac({:?})", md.type_().long_name()),
            KdfMacType::Cmac(cipher) => write!(f, "Cmac({:?})", cipher.nid().long_name()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum KdfType {
    KeyBased,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KdfArgument<'a> {
    Key(&'a [u8]),
    // Called "Label" in SP800-108
    Salt(&'a [u8]),
    // Called "Context" in SP800-108
    KbInfo(&'a [u8]),

    KbSeed(&'a [u8]),

    Mac(KdfMacType),
    KbMode(KdfKbMode),
}

pub fn perform_kdf<'a>(
    type_: KdfType,
    args: &[&'a KdfArgument],
    length: usize,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    #[cfg(feature = "ossl11")]
    ossl11::perform(type_, args, length)
}

#[cfg(feature = "ossl11")]
mod ossl11;

#[cfg(feature = "ossl3")]
compile_error!("ossl3 is not yet done");

#[cfg(feature = "custom")]
compile_error!("Custom is not yet done");

#[cfg(not(any(feature = "ossl11", feature = "ossl3", feature = "custom")))]
compile_error!("No usable implementation detected, and custom not enabled");

#[cfg(test)]
mod test;

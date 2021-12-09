use openssl::{hash::MessageDigest, nid::Nid, pkey::PKey, sign::Signer};

use crate::{KdfArgument, KdfError, KdfKbMode, KdfMacType, KdfType};

fn get_digest_length_bytes(digest_method: MessageDigest) -> Result<usize, KdfError> {
    match digest_method.type_() {
        Nid::SHA256 => Ok(32),
        Nid::SHA384 => Ok(48),
        Nid::SHA512 => Ok(64),
        _ => Err(KdfError::Unimplemented("Invalid digest method")),
    }
}

pub(crate) fn perform<'a>(
    type_: crate::KdfType,
    args: &[&'a KdfArgument],
    length: usize,
) -> Result<Vec<u8>, KdfError> {
    if !matches!(type_, KdfType::KeyBased) {
        return Err(KdfError::Unimplemented("Non-keybased KDF"));
    }

    let mut use_separator = true;
    let mut use_l = true;
    let mut r: u64 = 32;
    let mut lbits: u8 = 32;
    let mut key: Option<&'a [u8]> = None;
    let mut label: Option<&'a [u8]> = None;
    let mut context: Option<&'a [u8]> = None;
    let mut md: Option<MessageDigest> = None;

    for arg in args {
        match arg {
            KdfArgument::Key(new_key) => {
                key = Some(new_key);
            }
            KdfArgument::Salt(new_salt) => {
                label = Some(new_salt);
            }
            KdfArgument::KbInfo(new_kb_info) => {
                context = Some(new_kb_info);
            }
            KdfArgument::R(new_r) => {
                r = *new_r as u64;
            }
            KdfArgument::LBits(new_lbits) => {
                lbits = *new_lbits;
            }
            KdfArgument::UseL(new_use_l) => {
                use_l = *new_use_l;
            }
            KdfArgument::UseSeparator(new_use_separator) => {
                use_separator = *new_use_separator;
            }
            KdfArgument::Mac(mac) => match mac {
                KdfMacType::Hmac(new_md) => {
                    md = Some(*new_md);
                }
                KdfMacType::Cmac(_) => return Err(KdfError::Unimplemented("CMAC")),
            },
            KdfArgument::KbMode(mode) => match mode {
                KdfKbMode::Counter => {}
                KdfKbMode::Feedback => {
                    return Err(KdfError::Unimplemented("Feedback mode"));
                }
            },
            KdfArgument::KbSeed(_) => {
                return Err(KdfError::Unimplemented("KB-Seed"));
            }
        }
    }

    let key = key.ok_or(KdfError::MissingArgument("Key"))?;
    let md = md.ok_or(KdfError::MissingArgument("Digest method"))?;

    let h = get_digest_length_bytes(md)? * 8;
    let n = ((length * 8) as f32 / h as f32).ceil() as u64;

    if n > ((2 ^ r) - 1) {
        return Err(KdfError::InvalidOption("length too long for r"));
    }
    // This is the place where to start in the counter buffer (which is always be u64)
    let start_pos: usize = 8 - (r / 8) as usize;

    let lstart = ((64 - lbits) / 8) as usize;
    let l2 = &((length * 8) as u64).to_be_bytes()[lstart..];

    let hmac_key = PKey::hmac(key)?;
    let mut output = Vec::new();

    for i in 1..=n {
        let mut signer = Signer::new(md, &hmac_key)?;

        let i2 = &i.to_be_bytes()[start_pos..];
        signer.update(i2)?;
        if let Some(label) = label {
            signer.update(label)?;
        }
        if use_separator {
            signer.update(&[0x00])?;
        }
        if let Some(context) = context {
            signer.update(context)?;
        }
        if use_l {
            signer.update(l2)?;
        }

        output.extend_from_slice(signer.sign_to_vec()?.as_slice());
    }

    output.truncate(length);
    Ok(output)
}

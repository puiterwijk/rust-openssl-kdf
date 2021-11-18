#[cfg(test)]
mod tests {
    use crate::{KdfArgument, KdfKbMode, KdfMacType, KdfType};
    use openssl::{hash::MessageDigest, nid::Nid, symm::Cipher};

    #[test]
    fn hmac_sha256_deadbeef() {
        let deadbeef = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(MessageDigest::sha256())),
            &KdfArgument::Salt(&deadbeef),
            &KdfArgument::Key(&deadbeef),
            &KdfArgument::KbInfo(&deadbeef),
        ];

        let key_out = crate::perform_kdf(KdfType::KeyBased, &args, 20).unwrap();

        assert_eq!(
            key_out,
            vec![
                0x76, 0xF4, 0x63, 0xE2, 0xDF, 0x22, 0xD3, 0xDE, 0x02, 0xFD, 0x02, 0xCA, 0x59, 0x58,
                0x16, 0xBD, 0xCE, 0x3D, 0x19, 0xB0
            ],
        );
    }

    // Tests from OpenSSL 1.1
    #[test]
    fn test_kdf_kbkdf_6803_128() {
        let input_key: [u8; 16] = [
            0x57, 0xD0, 0x29, 0x72, 0x98, 0xFF, 0xD9, 0xD3, 0x5D, 0xE5, 0xA4, 0x7F, 0xB4, 0xBD,
            0xE2, 0x4B,
        ];
        let iv: [u8; 16] = [0; 16];
        let in_out: [([u8; 5], [u8; 16]); 3] = [
            (
                [0x00, 0x00, 0x00, 0x02, 0x99],
                [
                    0xD1, 0x55, 0x77, 0x5A, 0x20, 0x9D, 0x05, 0xF0, 0x2B, 0x38, 0xD4, 0x2A, 0x38,
                    0x9E, 0x5A, 0x56,
                ],
            ),
            (
                [0x00, 0x00, 0x00, 0x02, 0xaa],
                [
                    0x64, 0xDF, 0x83, 0xF8, 0x5A, 0x53, 0x2F, 0x17, 0x57, 0x7D, 0x8C, 0x37, 0x03,
                    0x57, 0x96, 0xAB,
                ],
            ),
            (
                [0x00, 0x00, 0x00, 0x02, 0x55],
                [
                    0x3E, 0x4F, 0xBD, 0xF3, 0x0F, 0xB8, 0x25, 0x9C, 0x42, 0x5C, 0xB6, 0xC9, 0x6F,
                    0x1F, 0x46, 0x35,
                ],
            ),
        ];

        for (constant, output) in in_out {
            let args = [
                &KdfArgument::KbMode(KdfKbMode::Feedback),
                &KdfArgument::Mac(KdfMacType::Cmac(
                    Cipher::from_nid(Nid::CAMELLIA_128_CBC).unwrap(),
                )),
                &KdfArgument::Key(&input_key),
                &KdfArgument::Salt(&constant),
                &KdfArgument::KbSeed(&iv),
            ];

            let key_out = crate::perform_kdf(KdfType::KeyBased, &args, 16).unwrap();

            assert_eq!(key_out, output,);
        }
    }
}

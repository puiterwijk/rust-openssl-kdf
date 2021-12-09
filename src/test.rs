#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use crate::{KdfArgument, KdfError, KdfKbMode, KdfMacType, KdfType};
    #[allow(unused_imports)]
    use openssl::{hash::MessageDigest, nid::Nid, symm::Cipher};

    // Test cases from the CAVP
    #[cfg(all(
        supported_arg = "r",
        supported_arg = "use_separator",
        supported_arg = "use_l"
    ))]
    fn cavp_perform(r: u8, md: MessageDigest, ki: &[u8], fixed: &[u8], expected: &[u8]) {
        let args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(md)),
            &KdfArgument::Salt(&fixed),
            &KdfArgument::Key(&ki),
            &KdfArgument::UseSeparator(false),
            &KdfArgument::UseL(false),
            &KdfArgument::R(r),
        ];
        let key_out = crate::perform_kdf(KdfType::KeyBased, &args, expected.len());
        if let Err(e) = key_out {
            if let KdfError::UnsupportedOption(options) = e {
                eprintln!("\tUnsupported options: {:?}", options);
                // Allowing
            } else {
                panic!("error during derivation: {:?}", e);
            }
        } else {
            assert_eq!(
                key_out.unwrap(),
                expected,
                "CAVP test case failed: {:?}",
                args
            );
        }
    }

    #[test]
    #[cfg(all(
        supported_arg = "r",
        supported_arg = "use_separator",
        supported_arg = "use_l"
    ))]
    fn cavp_hmac_sha256_8bit() {
        let ki = hex::decode("3edc6b5b8f7aadbd713732b482b8f979286e1ea3b8f8f99c30c884cfe3349b83")
            .unwrap();
        let fixed_input = hex::decode("98e9988bb4cc8b34d7922e1c68ad692ba2a1d9ae15149571675f17a77ad49e80c8d2a85e831a26445b1f0ff44d7084a17206b4896c8112daad18605a").unwrap();
        let ko = hex::decode("6c037652990674a07844732d0ad985f9").unwrap();
        cavp_perform(8, MessageDigest::sha256(), &ki, &fixed_input, &ko);
    }

    #[test]
    #[cfg(all(
        supported_arg = "r",
        supported_arg = "use_separator",
        supported_arg = "use_l"
    ))]
    fn cavp_hmac_sha256_16bit() {
        let ki = hex::decode("743434c930fe923c350ec202bef28b768cd6062cf233324e21a86c31f9406583")
            .unwrap();
        let fixed_input = hex::decode("9bdb8a454bd55ab30ced3fd420fde6d946252c875bfe986ed34927c7f7f0b106dab9cc85b4c702804965eb24c37ad883a8f695587a7b6094d3335bbc").unwrap();
        let ko = hex::decode("19c8a56db1d2a9afb793dc96fbde4c31").unwrap();
        cavp_perform(16, MessageDigest::sha256(), &ki, &fixed_input, &ko);
    }

    #[test]
    #[cfg(all(
        supported_arg = "r",
        supported_arg = "use_separator",
        supported_arg = "use_l"
    ))]
    fn cavp_hmac_sha256_24bit() {
        let ki = hex::decode("388e93e0273e62f086f52f6f5369d9e4626d143dce3b6afc7caf2c6e7344276b")
            .unwrap();
        let fixed_input = hex::decode("697bb34b3fbe6853864cac3e1bc6c8c44a4335565479403d949fcbb5e2c1795f9a3849df743389d1a99fe75ef566e6227c591104122a6477dd8e8c8e").unwrap();
        let ko = hex::decode("d697442b3dd51f96cae949586357b9a6").unwrap();
        cavp_perform(24, MessageDigest::sha256(), &ki, &fixed_input, &ko);
    }

    #[test]
    #[cfg(all(
        supported_arg = "r",
        supported_arg = "use_separator",
        supported_arg = "use_l"
    ))]
    fn cavp_hmac_sha256_32bit() {
        let ki = hex::decode("dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0")
            .unwrap();
        let fixed_input = hex::decode("01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac").unwrap();
        let ko = hex::decode("10621342bfb0fd40046c0e29f2cfdbf0").unwrap();
        cavp_perform(32, MessageDigest::sha256(), &ki, &fixed_input, &ko);
    }

    #[test]
    fn hmac_sha256_test() {
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
    #[cfg(any(implementation = "ossl11", implementation = "ossl3"))]
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

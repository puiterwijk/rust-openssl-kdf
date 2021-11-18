#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
enum Implementation {
    Ossl11,
    Ossl3,
    Custom,
}

impl ToString for Implementation {
    fn to_string(&self) -> String {
        match self {
            Implementation::Ossl11 => "ossl11",
            Implementation::Ossl3 => "ossl3",
            Implementation::Custom => "custom",
        }
        .to_string()
    }
}

#[allow(unreachable_code)]
fn main() {
    let implementation: Implementation;

    #[cfg(not(feature = "force_custom"))]
    {
        let openssl = pkg_config::probe_library("openssl").unwrap();
        let openssl_version = openssl.version;
        if openssl_version.starts_with("1.") {
            // Determine if this version of OpenSSL has the requisite patch backported
            let kdf_h_cts = std::fs::read_to_string("/usr/include/openssl/kdf.h").unwrap();
            if kdf_h_cts.contains("KDF_CTX_new_id") {
                implementation = Implementation::Ossl11;
            } else {
                #[cfg(not(feature = "allow_custom"))]
                panic!(
                    "This version of OpenSSL does not have the necessary patch backported.\n\
                    Please use a version of OpenSSL that has the necessary patch backported, or\n\
                    use the `allow_custom` feature to allow the use of the custom implementation."
                );

                implementation = Implementation::Custom;
            }
        } else if openssl_version.starts_with("3.") {
            implementation = Implementation::Ossl3;
        } else {
            panic!("No usable OpenSSL version detected in {}. You can enable the 'allow_custom' feature.", openssl_version);
        }
    }
    #[cfg(feature = "force_custom")]
    {
        #[cfg(not(feature = "allow_custom"))]
        panic!("Forcing custom without allowing custom");

        eprintln!("WARNING: The `force_custom` feature is enabled. This will cause the custom implementation to be used.");
        implementation = Implementation::Custom;
    }

    #[cfg(feature = "deny_custom")]
    if implementation == Implementation::Custom {
        panic!("The 'custom' implementation is not allowed");
    }

    println!(
        "cargo:rustc-cfg=implementation=\"{}\"",
        implementation.to_string()
    );
    println!("cargo::rustc-link-lib=crypto");
}

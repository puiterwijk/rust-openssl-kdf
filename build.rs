#[allow(unreachable_code)]
fn main() {
    let implementation: &str;

    #[cfg(not(feature = "force_custom"))]
    {
        let openssl = pkg_config::probe_library("openssl").unwrap();
        let openssl_version = openssl.version;
        if openssl_version.starts_with("1.") {
            // Determine if this version of OpenSSL has the requisite patch backported
            let kdf_h_cts = std::fs::read_to_string("/usr/include/openssl/kdf.h").unwrap();
            if kdf_h_cts.contains("KDF_CTX_new_id") {
                implementation = "ossl11";
            } else {
                #[cfg(not(feature = "allow_custom"))]
                panic!(
                    "This version of OpenSSL does not have the necessary patch backported.\n\
                    Please use a version of OpenSSL that has the necessary patch backported, or\n\
                    use the `allow_custom` feature to allow the use of the custom implementation."
                );

                implementation = "custom";
            }
        } else if openssl_version.starts_with("3.") {
            implementation = "ossl3";
        } else {
            panic!("No usable OpenSSL version detected in {}. You can enable the 'allow_custom' feature.", openssl_version);
        }
    }
    #[cfg(feature = "force_custom")]
    {
        #[cfg(not(feature = "allow_custom"))]
        panic!("Forcing custom without allowing custom");

        implementation = "custom";
    }

    #[cfg(feature = "deny_custom")]
    if implementation == "custom" {
        panic!("The 'custom' implementation is not allowed");
    }

    println!("cargo:rustc-cfg=implementation=\"{}\"", implementation);
    println!("cargo::rustc-link-lib=crypto");
}

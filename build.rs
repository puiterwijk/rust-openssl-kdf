fn main() {
    let implementation: &str;

    #[cfg(not(feature = "force_custom"))]
    {
        let openssl_version = pkg_config::probe_library("openssl").unwrap().version;
        if openssl_version.starts_with("1.") {
            implementation = "ossl11";
        } else if openssl_version.starts_with("3.") {
            implementation = "ossl3";
        } else {
            panic!("No usable OpenSSL version detected in {}. You can enable the 'allow_custom' feature.", openssl_version);
        }
    }
    #[cfg(feature = "force_custom")]
    {
        #[cfg(not(feature = "allow_custom"))]
        compile_error!("Forcing custom without allowing custom");

        implementation = "custom";
    }

    println!("cargo:rustc-cfg=implementation=\"{}\"", implementation);
    println!("cargo::rustc-link-lib=crypto");
}

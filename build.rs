fn main() {
    #[cfg(not(feature = "custom"))]
    {
        let openssl_version = pkg_config::probe_library("openssl").unwrap().version;
        if openssl_version.starts_with("1.") {
            println!("cargo:rustc-cfg=feature=\"ossl11\"");
        } else if openssl_version.starts_with("3.") {
            println!("cargo:rustc-cfg=feature=\"ossl3\"");
        } else {
            panic!("No usable OpenSSL version detected in {}", openssl_version);
        }
    }

    //println!("cargo:rustc-link-lib=ssl");
    println!("cargo::rustc-link-lib=crypto");
}

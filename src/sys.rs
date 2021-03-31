pub enum KDF {}

use libc::c_int;
use std::os::raw::c_char;

#[link(name = "crypto")]
extern "C" {
    pub fn EVP_KDF_CTX_new_id(_type: c_int) -> *mut KDF;
    pub fn EVP_KDF_CTX_free(ctx: *mut KDF);

    pub fn EVP_KDF_reset(ctx: *mut KDF);
    pub fn EVP_KDF_ctrl(ctx: *mut KDF, cmd: c_int, ...) -> c_int;
    pub fn EVP_KDF_ctrl_str(ctx: *mut KDF, type_: *const c_char, value: *const c_char) -> c_int;
    pub fn EVP_KDF_size(ctx: *mut KDF) -> libc::size_t;
    pub fn EVP_KDF_derive(ctx: *mut KDF, key: *mut libc::c_uchar, keylen: libc::size_t) -> c_int;
}

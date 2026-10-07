//! `aws-lc-rs` drop-in replacement backed by `package:boring` (`libbssl_dart`).
//!
//! # Overview for Dart Developers
//!
//! `sigstore-rust` (`sigstore-crypto`) and `rustls-webpki` (used for X.509 certificate chain
//! validation) both depend on the [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) crate, which
//! exposes the `ring`-style Rust cryptography API (`digest`, `signature`, `rand`, `pkcs8`, `error`).
//!
//! Upstream `aws-lc-rs` compiles and statically links `aws-lc-sys` (Amazon's C/C++/ASM fork of
//! BoringSSL), which adds ~2.4 MB to the native library and requires CMake/C++ build tools.
//! Because `package:sigstore` already depends on `package:boring` (which bundles BoringSSL via
//! Dart Native Assets), `rust/Cargo.toml` uses `[patch.crates-io]` to redirect all `aws-lc-rs`
//! imports to this pure-Rust crate.
//!
//! ## How Function Pointer Dispatch Works
//!
//! Instead of linking against `libbssl_dart` at Rust compile time (which would complicate OS
//! dynamic linker paths across separate native asset build hooks and defeat `package:boring`'s
//! `record_use` symbol tree-shaking):
//! 1. Dart resolves the addresses of the 28 required BoringSSL functions via
//!    `Native.addressOf(...)` in `lib/src/boring_init.dart`.
//! 2. Dart passes those 28 addresses as a `UintPtr` list to `SigstoreVerifier.initBoring(...)`,
//!    which calls [`init_boring_symbols_from_slice`] to populate [`BORING_SYMBOLS`].
//! 3. All `digest` and `signature` calls in this crate invoke the C functions through [`bssl()`].

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::{c_int, c_uint, c_void};
use std::sync::OnceLock;

/// Opaque C struct types representing BoringSSL pointers (`EVP_MD*`, `EVP_PKEY*`, etc.).
/// Equivalent to `final class EVP_MD extends Opaque {}` in `dart:ffi`.
pub mod FFI {
    use std::ffi::c_void;

    #[repr(C)]
    pub struct EVP_MD(c_void);
    #[repr(C)]
    pub struct EVP_MD_CTX(c_void);
    #[repr(C)]
    pub struct EVP_PKEY(c_void);
    #[repr(C)]
    pub struct EVP_PKEY_CTX(c_void);
    #[repr(C)]
    pub struct EVP_PKEY_ALG(c_void);
}

use FFI::*;

// BoringSSL `<openssl/rsa.h>` padding constants.
const RSA_PKCS1_PADDING: c_int = 1;
const RSA_PKCS1_PSS_PADDING: c_int = 6;
const RSA_PSS_SALTLEN_DIGEST: c_int = -1;

/// Exact number of BoringSSL C function pointers in [`BoringSymbols`].
/// Must stay in sync with `_boringSymbolAddresses()` in `lib/src/boring_init.dart`.
pub const BORING_SYMBOL_COUNT: usize = 28;

/// Function pointer table populated from `package:boring` at startup.
///
/// **Important:** The field order here MUST exactly match the list order in
/// `_boringSymbolAddresses()` in `lib/src/boring_init.dart`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BoringSymbols {
    // Error queue cleanup (called after failed verifications so thread-local error state doesn't leak)
    pub ERR_clear_error: unsafe extern "C" fn(),

    // Hash algorithm descriptors (SHA-256, SHA-384, SHA-512)
    pub EVP_sha256: unsafe extern "C" fn() -> *const EVP_MD,
    pub EVP_sha384: unsafe extern "C" fn() -> *const EVP_MD,
    pub EVP_sha512: unsafe extern "C" fn() -> *const EVP_MD,

    // Streaming message digest (`EVP_MD_CTX`) lifecycle and one-shot message verification
    pub EVP_MD_CTX_new: unsafe extern "C" fn() -> *mut EVP_MD_CTX,
    pub EVP_MD_CTX_free: unsafe extern "C" fn(*mut EVP_MD_CTX),
    pub EVP_MD_CTX_copy_ex: unsafe extern "C" fn(*mut EVP_MD_CTX, *const EVP_MD_CTX) -> c_int,
    pub EVP_DigestInit_ex:
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const EVP_MD, *mut c_void) -> c_int,
    pub EVP_DigestUpdate: unsafe extern "C" fn(*mut EVP_MD_CTX, *const c_void, usize) -> c_int,
    pub EVP_DigestFinal_ex: unsafe extern "C" fn(*mut EVP_MD_CTX, *mut u8, *mut c_uint) -> c_int,
    pub EVP_DigestVerifyInit: unsafe extern "C" fn(
        *mut EVP_MD_CTX,
        *mut *mut EVP_PKEY_CTX,
        *const EVP_MD,
        *mut c_void,
        *mut EVP_PKEY,
    ) -> c_int,
    pub EVP_DigestVerify:
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const u8, usize, *const u8, usize) -> c_int,

    // Public key (`EVP_PKEY`) lifecycle and key size inspection
    pub EVP_PKEY_free: unsafe extern "C" fn(*mut EVP_PKEY),
    pub EVP_PKEY_bits: unsafe extern "C" fn(*const EVP_PKEY) -> c_int,

    // Pre-hashed digest signature verification (`EVP_PKEY_CTX`) and RSA padding configuration
    pub EVP_PKEY_CTX_new: unsafe extern "C" fn(*mut EVP_PKEY, *mut c_void) -> *mut EVP_PKEY_CTX,
    pub EVP_PKEY_CTX_free: unsafe extern "C" fn(*mut EVP_PKEY_CTX),
    pub EVP_PKEY_verify_init: unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> c_int,
    pub EVP_PKEY_verify:
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *const u8, usize, *const u8, usize) -> c_int,
    pub EVP_PKEY_CTX_set_rsa_padding: unsafe extern "C" fn(*mut EVP_PKEY_CTX, c_int) -> c_int,
    pub EVP_PKEY_CTX_set_rsa_pss_saltlen: unsafe extern "C" fn(*mut EVP_PKEY_CTX, c_int) -> c_int,
    pub EVP_PKEY_CTX_set_signature_md:
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *const EVP_MD) -> c_int,

    // Modern BoringSSL key algorithm descriptors for parsing SPKI and raw public keys
    pub EVP_pkey_ec_p256: unsafe extern "C" fn() -> *const EVP_PKEY_ALG,
    pub EVP_pkey_ec_p384: unsafe extern "C" fn() -> *const EVP_PKEY_ALG,
    pub EVP_pkey_ec_p521: unsafe extern "C" fn() -> *const EVP_PKEY_ALG,
    pub EVP_pkey_ed25519: unsafe extern "C" fn() -> *const EVP_PKEY_ALG,
    pub EVP_pkey_rsa: unsafe extern "C" fn() -> *const EVP_PKEY_ALG,

    // Public key parsers (Ed25519 raw 32-byte key and X.509 SubjectPublicKeyInfo DER)
    pub EVP_PKEY_from_raw_public_key:
        unsafe extern "C" fn(*const EVP_PKEY_ALG, *const u8, usize) -> *mut EVP_PKEY,
    pub EVP_PKEY_from_subject_public_key_info:
        unsafe extern "C" fn(*const u8, usize, *const *const EVP_PKEY_ALG, usize) -> *mut EVP_PKEY,
}

/// Global write-once storage for the BoringSSL function pointer table (similar to `late final` in Dart).
static BORING_SYMBOLS: OnceLock<BoringSymbols> = OnceLock::new();

/// Initialize the BoringSSL function pointer table from an array of 28 symbol addresses.
///
/// # Safety
/// Every element in `addrs` must be a valid non-null function pointer matching the
/// exact layout and calling convention of `BoringSymbols`.
pub unsafe fn init_boring_symbols_from_slice(addrs: &[usize]) -> Result<(), &'static str> {
    if addrs.len() != BORING_SYMBOL_COUNT {
        return Err("invalid BoringSSL symbol table length");
    }
    if addrs.contains(&0) {
        return Err("null function pointer in BoringSSL symbol table");
    }
    let ptrs: [usize; BORING_SYMBOL_COUNT] = addrs
        .try_into()
        .map_err(|_| "invalid BoringSSL symbol table length")?;
    // Reinterpret the 28 `usize` addresses as the 28 `extern "C" fn` fields in `BoringSymbols`.
    let syms: BoringSymbols = unsafe { std::mem::transmute(ptrs) };
    let _ = BORING_SYMBOLS.set(syms);
    Ok(())
}

/// Returns the initialized BoringSSL function table, or panics if `init_boring` was not called.
#[inline]
pub(crate) fn bssl() -> &'static BoringSymbols {
    BORING_SYMBOLS.get().expect(
        "package:boring symbols not initialized! Call SigstoreClient.create() or ensureBoringInitialized() before using sigstore.",
    )
}

/// Clears BoringSSL's thread-local error queue so failed verification checks don't leave stale errors behind.
#[inline]
pub(crate) fn clear_error() {
    if let Some(s) = BORING_SYMBOLS.get() {
        unsafe { (s.ERR_clear_error)() };
    }
}

/// Stub for `aws_lc_rs::try_fips_mode` (unused in Dart builds).
#[inline]
pub fn try_fips_mode() -> Result<(), error::Unspecified> {
    Err(error::Unspecified)
}

/// RAII wrapper around a BoringSSL `*mut EVP_PKEY` pointer that automatically calls
/// `EVP_PKEY_free` when dropped (when it goes out of scope).
pub(crate) struct EvpPkey(*mut EVP_PKEY);

unsafe impl Send for EvpPkey {}
unsafe impl Sync for EvpPkey {}

impl EvpPkey {
    #[inline]
    pub(crate) fn from_ptr(ptr: *mut EVP_PKEY) -> Result<Self, error::Unspecified> {
        if ptr.is_null() {
            clear_error();
            Err(error::Unspecified)
        } else {
            Ok(Self(ptr))
        }
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *mut EVP_PKEY {
        self.0
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let s = bssl();
            unsafe { (s.EVP_PKEY_free)(self.0) };
        }
    }
}

// ============================================================================
// ASN.1 DER Conversion Helpers
// ============================================================================
//
// `aws-lc-rs` (following `ring`'s API) passes *unwrapped* public key bytes to
// `UnparsedPublicKey::verify` (e.g., raw EC point `0x04 || X || Y`, or raw PKCS#1 `RSAPublicKey`
// sequence), whereas BoringSSL's modern `EVP_PKEY_from_subject_public_key_info` expects a full
// X.509 `SubjectPublicKeyInfo` (SPKI) DER structure:
//
//   SubjectPublicKeyInfo ::= SEQUENCE {
//       algorithm         AlgorithmIdentifier,
//       subjectPublicKey  BIT STRING
//   }
//
// Similarly, `aws-lc-rs` supports fixed-width `(r || s)` ECDSA signatures (IEEE P1363), whereas
// BoringSSL's `EVP_DigestVerify` / `EVP_PKEY_verify` always expects ASN.1 DER-encoded ECDSA
// signatures (`SEQUENCE { r INTEGER, s INTEGER }`). The helpers below bridge these formats in
// pure Rust without needing extra BoringSSL `EC_KEY` or `BIGNUM` C symbols.

/// Wraps an ASN.1 `AlgorithmIdentifier` DER slice and raw public key bytes into a DER
/// `SubjectPublicKeyInfo` (`SEQUENCE { AlgorithmIdentifier, BIT STRING }`).
pub(crate) fn wrap_spki(alg_id_der: &[u8], pub_key_bytes: &[u8]) -> Vec<u8> {
    let bit_string_content_len = 1 + pub_key_bytes.len();
    let mut bit_string = Vec::with_capacity(4 + bit_string_content_len);
    bit_string.push(0x03); // ASN.1 tag: BIT STRING
    encode_der_length(&mut bit_string, bit_string_content_len);
    bit_string.push(0x00); // 0 unused bits in final byte
    bit_string.extend_from_slice(pub_key_bytes);

    let seq_len = alg_id_der.len() + bit_string.len();
    let mut spki = Vec::with_capacity(4 + seq_len);
    spki.push(0x30); // ASN.1 tag: SEQUENCE
    encode_der_length(&mut spki, seq_len);
    spki.extend_from_slice(alg_id_der);
    spki.extend_from_slice(&bit_string);
    spki
}

/// Converts a minimal positive ASN.1 `INTEGER` byte slice into a fixed-length big-endian
/// coordinate, validating DER minimal-encoding rules.
pub(crate) fn asn1_uint_to_fixed(
    bytes: &[u8],
    fixed_len: usize,
) -> Result<Vec<u8>, error::Unspecified> {
    if bytes.is_empty() {
        return Err(error::Unspecified);
    }
    let stripped = if bytes.len() > 1 && bytes[0] == 0 {
        if (bytes[1] & 0x80) == 0 {
            return Err(error::Unspecified);
        }
        &bytes[1..]
    } else {
        if (bytes[0] & 0x80) != 0 {
            return Err(error::Unspecified);
        }
        bytes
    };
    if stripped.len() > fixed_len {
        return Err(error::Unspecified);
    }
    let mut out = vec![0u8; fixed_len];
    let offset = fixed_len - stripped.len();
    out[offset..].copy_from_slice(stripped);
    Ok(out)
}

/// Converts a fixed-width IEEE P1363 `(r || s)` ECDSA signature into ASN.1 DER
/// (`SEQUENCE { r INTEGER, s INTEGER }`) for BoringSSL.
pub(crate) fn fixed_ecdsa_sig_to_der(
    sig: &[u8],
    coord_len: usize,
) -> Result<Vec<u8>, error::Unspecified> {
    if sig.len() != coord_len * 2 {
        return Err(error::Unspecified);
    }
    let r = encode_asn1_uint(&sig[..coord_len])?;
    let s = encode_asn1_uint(&sig[coord_len..])?;
    let seq_len = r.len() + s.len();
    let mut der = Vec::with_capacity(4 + seq_len);
    der.push(0x30); // ASN.1 tag: SEQUENCE
    encode_der_length(&mut der, seq_len);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    Ok(der)
}

/// Encodes a big-endian unsigned integer slice (`r` or `s`) as a positive ASN.1 DER `INTEGER`.
fn encode_asn1_uint(raw: &[u8]) -> Result<Vec<u8>, error::Unspecified> {
    let first_non_zero = raw.iter().position(|&b| b != 0);
    let Some(idx) = first_non_zero else {
        // Zero is not a valid ECDSA signature component (r > 0, s > 0).
        return Err(error::Unspecified);
    };
    let significant = &raw[idx..];
    // In two's-complement ASN.1 INTEGER, if the high bit is 1, prepend a 0x00 byte so it isn't
    // interpreted as a negative number.
    let needs_leading_zero = (significant[0] & 0x80) != 0;
    let content_len = significant.len() + usize::from(needs_leading_zero);
    let mut out = Vec::with_capacity(2 + content_len);
    out.push(0x02); // ASN.1 tag: INTEGER
    encode_der_length(&mut out, content_len);
    if needs_leading_zero {
        out.push(0x00);
    }
    out.extend_from_slice(significant);
    Ok(out)
}

/// Appends an ASN.1 DER length field (short form `< 128`, or 1–2 byte long form).
pub(crate) fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

/// Error types matching `aws_lc_rs::error` (`Unspecified` and `KeyRejected`).
pub mod error {
    use std::fmt;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Unspecified;

    impl fmt::Display for Unspecified {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("error::Unspecified")
        }
    }

    impl std::error::Error for Unspecified {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct KeyRejected(&'static str);

    impl KeyRejected {
        pub fn into_unspecified(self) -> Unspecified {
            Unspecified
        }

        pub(crate) fn inconsistent_components() -> Self {
            Self("InconsistentComponents")
        }

        pub(crate) fn invalid_encoding() -> Self {
            Self("InvalidEncoding")
        }

        pub(crate) fn unexpected_error() -> Self {
            Self("UnexpectedError")
        }
    }

    impl fmt::Display for KeyRejected {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for KeyRejected {}

    impl From<Unspecified> for KeyRejected {
        fn from(_: Unspecified) -> Self {
            Self::invalid_encoding()
        }
    }
}

/// Stub implementation of `aws_lc_rs::rand`.
///
/// `sigstore-crypto` imports `aws_lc_rs::rand::SystemRandom` in its signing module, so these
/// types must exist for `sigstore-crypto` to compile. Because `package:sigstore` only performs
/// verification (which is deterministic and never generates random bytes), `fill` returns
/// `Err(Unspecified)` rather than pulling `RAND_bytes` into our BoringSSL symbol table.
pub mod rand {
    use crate::error;

    pub trait SecureRandom: sealed::SecureRandom {
        fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified>;
    }

    mod sealed {
        pub trait SecureRandom {}
    }

    #[derive(Clone, Copy, Debug)]
    pub struct SystemRandom(());

    impl SystemRandom {
        #[inline]
        pub fn new() -> Self {
            Self(())
        }
    }

    impl Default for SystemRandom {
        fn default() -> Self {
            Self::new()
        }
    }

    impl sealed::SecureRandom for SystemRandom {}

    impl SecureRandom for SystemRandom {
        fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
            fill(dest)
        }
    }

    pub fn fill(_dest: &mut [u8]) -> Result<(), error::Unspecified> {
        Err(error::Unspecified)
    }
}

/// SHA-256, SHA-384, and SHA-512 hashing (`aws_lc_rs::digest`), backed by BoringSSL's `EVP_MD_CTX`.
///
/// Used by `sigstore-verify` (artifact hashing), `sigstore-merkle` (Rekor RFC 6962 Merkle tree
/// inclusion proofs), and `sigstore-tuf` (TUF metadata and target hash verification).
pub mod digest {
    use crate::bssl;
    use crate::FFI::{EVP_MD, EVP_MD_CTX};
    use std::ffi::{c_uint, c_void};
    use std::fmt;
    use std::ptr;

    pub const SHA256_OUTPUT_LEN: usize = 32;
    pub const SHA384_OUTPUT_LEN: usize = 48;
    pub const SHA512_OUTPUT_LEN: usize = 64;
    pub const MAX_OUTPUT_LEN: usize = 64;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum DigestId {
        Sha256,
        Sha384,
        Sha512,
    }

    impl DigestId {
        /// Returns BoringSSL's singleton `const EVP_MD*` descriptor for this hash algorithm.
        pub(crate) fn evp_md(self) -> *const EVP_MD {
            let s = bssl();
            unsafe {
                match self {
                    DigestId::Sha256 => (s.EVP_sha256)(),
                    DigestId::Sha384 => (s.EVP_sha384)(),
                    DigestId::Sha512 => (s.EVP_sha512)(),
                }
            }
        }
    }

    #[derive(PartialEq, Eq)]
    pub struct Algorithm {
        pub output_len: usize,
        pub chaining_len: usize,
        pub block_len: usize,
        pub(crate) id: DigestId,
    }

    impl fmt::Debug for Algorithm {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Algorithm")
                .field("output_len", &self.output_len)
                .field("id", &self.id)
                .finish()
        }
    }

    pub static SHA256: Algorithm = Algorithm {
        output_len: SHA256_OUTPUT_LEN,
        chaining_len: SHA256_OUTPUT_LEN,
        block_len: 64,
        id: DigestId::Sha256,
    };

    pub static SHA384: Algorithm = Algorithm {
        output_len: SHA384_OUTPUT_LEN,
        chaining_len: SHA512_OUTPUT_LEN,
        block_len: 128,
        id: DigestId::Sha384,
    };

    pub static SHA512: Algorithm = Algorithm {
        output_len: SHA512_OUTPUT_LEN,
        chaining_len: SHA512_OUTPUT_LEN,
        block_len: 128,
        id: DigestId::Sha512,
    };

    /// A computed (or imported pre-computed) message digest (`SHA-256`, `SHA-384`, or `SHA-512`).
    #[derive(Clone, Copy)]
    pub struct Digest {
        algorithm: &'static Algorithm,
        bytes: [u8; MAX_OUTPUT_LEN],
    }

    impl Digest {
        /// Wraps an already-computed hash byte slice into a [`Digest`] so it can be passed to
        /// `UnparsedPublicKey::verify_digest` (used when verifying Sigstore bundles against a
        /// precomputed 32-byte artifact digest).
        pub fn import_less_safe(
            slice: &[u8],
            algorithm: &'static Algorithm,
        ) -> Result<Self, crate::error::Unspecified> {
            if slice.len() != algorithm.output_len {
                return Err(crate::error::Unspecified);
            }
            let mut bytes = [0u8; MAX_OUTPUT_LEN];
            bytes[..slice.len()].copy_from_slice(slice);
            Ok(Self { algorithm, bytes })
        }

        #[inline]
        pub fn algorithm(&self) -> &'static Algorithm {
            self.algorithm
        }
    }

    impl AsRef<[u8]> for Digest {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            &self.bytes[..self.algorithm.output_len]
        }
    }

    impl fmt::Debug for Digest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}:", self.algorithm)?;
            for b in self.as_ref() {
                write!(f, "{b:02x}")?;
            }
            Ok(())
        }
    }

    /// Streaming hash state wrapping a BoringSSL `EVP_MD_CTX*`.
    pub struct Context {
        algorithm: &'static Algorithm,
        ctx: *mut EVP_MD_CTX,
    }

    unsafe impl Send for Context {}
    unsafe impl Sync for Context {}

    impl Context {
        pub fn new(algorithm: &'static Algorithm) -> Self {
            let s = bssl();
            unsafe {
                let ctx = (s.EVP_MD_CTX_new)();
                assert!(!ctx.is_null(), "EVP_MD_CTX_new failed");
                let md = algorithm.id.evp_md();
                let rc = (s.EVP_DigestInit_ex)(ctx, md, ptr::null_mut());
                assert_eq!(rc, 1, "EVP_DigestInit_ex failed");
                Self { algorithm, ctx }
            }
        }

        pub fn update(&mut self, data: &[u8]) {
            if data.is_empty() {
                return;
            }
            let s = bssl();
            unsafe {
                let rc = (s.EVP_DigestUpdate)(self.ctx, data.as_ptr() as *const c_void, data.len());
                assert_eq!(rc, 1, "EVP_DigestUpdate failed");
            }
        }

        pub fn finish(self) -> Digest {
            let s = bssl();
            let mut bytes = [0u8; MAX_OUTPUT_LEN];
            let mut out_len: c_uint = 0;
            unsafe {
                let rc = (s.EVP_DigestFinal_ex)(self.ctx, bytes.as_mut_ptr(), &mut out_len);
                assert_eq!(rc, 1, "EVP_DigestFinal_ex failed");
                assert_eq!(out_len as usize, self.algorithm.output_len);
            }
            Digest {
                algorithm: self.algorithm,
                bytes,
            }
        }

        #[inline]
        pub fn algorithm(&self) -> &'static Algorithm {
            self.algorithm
        }
    }

    impl Clone for Context {
        fn clone(&self) -> Self {
            let s = bssl();
            unsafe {
                let new_ctx = (s.EVP_MD_CTX_new)();
                assert!(!new_ctx.is_null(), "EVP_MD_CTX_new failed");
                let rc = (s.EVP_MD_CTX_copy_ex)(new_ctx, self.ctx);
                assert_eq!(rc, 1, "EVP_MD_CTX_copy_ex failed");
                Self {
                    algorithm: self.algorithm,
                    ctx: new_ctx,
                }
            }
        }
    }

    impl Drop for Context {
        fn drop(&mut self) {
            if !self.ctx.is_null() {
                let s = bssl();
                unsafe { (s.EVP_MD_CTX_free)(self.ctx) };
            }
        }
    }

    impl fmt::Debug for Context {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Context")
                .field("algorithm", &self.algorithm)
                .finish()
        }
    }

    /// Computes a one-shot digest of `data` using `algorithm`.
    pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest {
        let mut ctx = Context::new(algorithm);
        ctx.update(data);
        ctx.finish()
    }
}

/// Stub PKCS#8 types required for `sigstore-crypto`'s signing module to compile.
pub mod pkcs8 {
    use crate::error;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Version {
        V1Only,
        V1OrV2,
    }

    pub struct Document {
        pub(crate) bytes: Vec<u8>,
    }

    impl AsRef<[u8]> for Document {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    pub(crate) fn unwrap_pkcs8(version: Version, input: &[u8]) -> Result<(), error::KeyRejected> {
        let _ = version;
        if input.is_empty() {
            return Err(error::KeyRejected::invalid_encoding());
        }
        Ok(())
    }
}

/// Digital signature verification (`aws_lc_rs::signature`) for ECDSA (P-256, P-384, P-521),
/// Ed25519, and RSA (PKCS#1 v1.5 and PSS), backed by BoringSSL's `EVP_PKEY` API.
pub mod signature {
    use crate::digest::DigestId;
    use crate::FFI::{EVP_PKEY_ALG, EVP_PKEY_CTX};
    use crate::{
        bssl, clear_error, error, fixed_ecdsa_sig_to_der, pkcs8, rand, wrap_spki, EvpPkey,
        RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST,
    };
    use std::fmt;
    use std::ptr;

    pub const MAX_LEN: usize = 1024;

    // Pre-encoded ASN.1 DER `AlgorithmIdentifier` headers used by `wrap_spki` to wrap raw
    // `ring`/`aws-lc-rs` public key bytes into a full X.509 `SubjectPublicKeyInfo` (SPKI)
    // structure that BoringSSL's `EVP_PKEY_from_subject_public_key_info` can parse:
    // - `id-ecPublicKey` (1.2.840.10045.2.1) + `prime256v1` (1.2.840.10045.3.1.7)
    const ALG_ID_EC_P256: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    // - `id-ecPublicKey` (1.2.840.10045.2.1) + `secp384r1` (1.3.132.0.34)
    const ALG_ID_EC_P384: &[u8] = &[
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
        0x04, 0x00, 0x22,
    ];
    // - `id-ecPublicKey` (1.2.840.10045.2.1) + `secp521r1` (1.3.132.0.35)
    const ALG_ID_EC_P521: &[u8] = &[
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
        0x04, 0x00, 0x23,
    ];
    // - `rsaEncryption` (1.2.840.113549.1.1.1) + NULL parameters
    const ALG_ID_RSA_ENCRYPTION: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];

    #[derive(Clone, Copy)]
    pub struct Signature {
        pub(crate) bytes: [u8; MAX_LEN],
        pub(crate) len: usize,
    }

    impl Signature {
        pub(crate) fn from_slice(slice: &[u8]) -> Result<Self, error::Unspecified> {
            if slice.len() > MAX_LEN {
                return Err(error::Unspecified);
            }
            let mut bytes = [0u8; MAX_LEN];
            bytes[..slice.len()].copy_from_slice(slice);
            Ok(Self {
                bytes,
                len: slice.len(),
            })
        }
    }

    impl AsRef<[u8]> for Signature {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    impl fmt::Debug for Signature {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Signature").field(&self.as_ref()).finish()
        }
    }

    pub trait KeyPair: fmt::Debug + Send + Sync {
        type PublicKey: AsRef<[u8]> + fmt::Debug + Clone + Send + Sync;
        fn public_key(&self) -> &Self::PublicKey;
    }

    /// Trait implemented by all signature verification parameter sets (`ECDSA_*`, `ED25519`, `RSA_*`).
    pub trait VerificationAlgorithm: fmt::Debug + Sync {
        /// Hashes `msg` and verifies `signature` against `public_key`.
        fn verify_sig(
            &self,
            public_key: &[u8],
            msg: &[u8],
            signature: &[u8],
        ) -> Result<(), error::Unspecified>;

        /// Verifies `signature` against a precomputed `digest` (supported for ECDSA and RSA;
        /// Ed25519 does not support pre-hashed digests in PureEdDSA mode).
        fn verify_digest_sig(
            &self,
            _public_key: &[u8],
            _digest: &crate::digest::Digest,
            _signature: &[u8],
        ) -> Result<(), error::Unspecified> {
            Err(error::Unspecified)
        }
    }

    // Post-quantum ML-DSA algorithm constants referenced by `rustls-webpki` 0.103+.
    // Sigstore bundles do not currently use ML-DSA, so verification returns `Err(Unspecified)`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MlDsaAlg {
        MlDsa44,
        MlDsa65,
        MlDsa87,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct MlDsaVerificationAlgorithm(pub(crate) MlDsaAlg);

    pub static ML_DSA_44: MlDsaVerificationAlgorithm =
        MlDsaVerificationAlgorithm(MlDsaAlg::MlDsa44);
    pub static ML_DSA_65: MlDsaVerificationAlgorithm =
        MlDsaVerificationAlgorithm(MlDsaAlg::MlDsa65);
    pub static ML_DSA_87: MlDsaVerificationAlgorithm =
        MlDsaVerificationAlgorithm(MlDsaAlg::MlDsa87);

    impl VerificationAlgorithm for MlDsaVerificationAlgorithm {
        fn verify_sig(
            &self,
            _public_key: &[u8],
            _msg: &[u8],
            _signature: &[u8],
        ) -> Result<(), error::Unspecified> {
            Err(error::Unspecified)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EcdsaCurve {
        P256,
        P384,
        P521,
    }

    impl EcdsaCurve {
        /// Size in bytes of a single field coordinate (`X`, `Y`, `r`, or `s`) on this curve.
        pub(crate) fn coord_len(self) -> usize {
            match self {
                EcdsaCurve::P256 => 32,
                EcdsaCurve::P384 => 48,
                EcdsaCurve::P521 => 66,
            }
        }

        /// Expected byte length of an SEC1 uncompressed EC point (`0x04 || X || Y`).
        pub(crate) fn uncompressed_pub_len(self) -> usize {
            1 + 2 * self.coord_len()
        }

        /// Expected byte length of an SEC1 compressed EC point (`0x02/0x03 || X`).
        pub(crate) fn compressed_pub_len(self) -> usize {
            1 + self.coord_len()
        }

        pub(crate) fn alg_id_der(self) -> &'static [u8] {
            match self {
                EcdsaCurve::P256 => ALG_ID_EC_P256,
                EcdsaCurve::P384 => ALG_ID_EC_P384,
                EcdsaCurve::P521 => ALG_ID_EC_P521,
            }
        }

        pub(crate) fn evp_alg(self) -> *const EVP_PKEY_ALG {
            let s = bssl();
            unsafe {
                match self {
                    EcdsaCurve::P256 => (s.EVP_pkey_ec_p256)(),
                    EcdsaCurve::P384 => (s.EVP_pkey_ec_p384)(),
                    EcdsaCurve::P521 => (s.EVP_pkey_ec_p521)(),
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EcdsaSigFormat {
        /// Standard ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }`.
        Asn1,
        /// IEEE P1363 fixed-width `r || s` concatenation.
        Fixed,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct EcdsaVerificationAlgorithm {
        pub(crate) curve: EcdsaCurve,
        pub(crate) digest: DigestId,
        pub(crate) format: EcdsaSigFormat,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct EcdsaSigningAlgorithm {
        pub(crate) curve: EcdsaCurve,
        pub(crate) digest: DigestId,
        pub(crate) format: EcdsaSigFormat,
    }

    pub static ECDSA_P256_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P256,
        digest: DigestId::Sha256,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P256_SHA256_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P256,
        digest: DigestId::Sha256,
        format: EcdsaSigFormat::Fixed,
    };

    pub static ECDSA_P256_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P256,
        digest: DigestId::Sha384,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P256_SHA512_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P256,
        digest: DigestId::Sha512,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P384_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P384,
        digest: DigestId::Sha256,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P384_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P384,
        digest: DigestId::Sha384,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P384_SHA512_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P384,
        digest: DigestId::Sha512,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P384_SHA384_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P384,
        digest: DigestId::Sha384,
        format: EcdsaSigFormat::Fixed,
    };

    pub static ECDSA_P521_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P521,
        digest: DigestId::Sha256,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P521_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P521,
        digest: DigestId::Sha384,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P521_SHA512_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P521,
        digest: DigestId::Sha512,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P521_SHA512_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
        curve: EcdsaCurve::P521,
        digest: DigestId::Sha512,
        format: EcdsaSigFormat::Fixed,
    };

    pub static ECDSA_P256_SHA256_ASN1_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
        curve: EcdsaCurve::P256,
        digest: DigestId::Sha256,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P256_SHA256_FIXED_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
        curve: EcdsaCurve::P256,
        digest: DigestId::Sha256,
        format: EcdsaSigFormat::Fixed,
    };

    pub static ECDSA_P384_SHA384_ASN1_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
        curve: EcdsaCurve::P384,
        digest: DigestId::Sha384,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P384_SHA384_FIXED_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
        curve: EcdsaCurve::P384,
        digest: DigestId::Sha384,
        format: EcdsaSigFormat::Fixed,
    };

    pub static ECDSA_P521_SHA512_ASN1_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
        curve: EcdsaCurve::P521,
        digest: DigestId::Sha512,
        format: EcdsaSigFormat::Asn1,
    };

    pub static ECDSA_P521_SHA512_FIXED_SIGNING: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
        curve: EcdsaCurve::P521,
        digest: DigestId::Sha512,
        format: EcdsaSigFormat::Fixed,
    };

    /// Parses an SEC1-encoded EC public point (`0x04 || X || Y` or compressed `0x02/0x03 || X`)
    /// into a BoringSSL `EVP_PKEY*` by wrapping it in an SPKI DER header.
    fn parse_ec_public_key(
        curve: EcdsaCurve,
        public_key: &[u8],
    ) -> Result<EvpPkey, error::Unspecified> {
        let valid_uncompressed =
            public_key.len() == curve.uncompressed_pub_len() && public_key.first() == Some(&0x04);
        let valid_compressed = public_key.len() == curve.compressed_pub_len()
            && matches!(public_key.first(), Some(0x02 | 0x03));
        if !valid_uncompressed && !valid_compressed {
            return Err(error::Unspecified);
        }
        let s = bssl();
        let spki = wrap_spki(curve.alg_id_der(), public_key);
        let algs = [curve.evp_alg()];
        let ptr = unsafe {
            (s.EVP_PKEY_from_subject_public_key_info)(
                spki.as_ptr(),
                spki.len(),
                algs.as_ptr(),
                algs.len(),
            )
        };
        EvpPkey::from_ptr(ptr)
    }

    /// Hashes `msg` with `md` and verifies `sig` against `pkey` using BoringSSL's
    /// `EVP_DigestVerifyInit` + `EVP_DigestVerify`.
    ///
    /// `configure_pctx` is used by RSA verification to configure PKCS#1 v1.5 or PSS padding on
    /// the underlying `EVP_PKEY_CTX*` before verification runs.
    pub(crate) fn evp_digest_verify(
        pkey: &EvpPkey,
        md: *const crate::FFI::EVP_MD,
        msg: &[u8],
        sig: &[u8],
        configure_pctx: impl FnOnce(*mut EVP_PKEY_CTX) -> Result<(), error::Unspecified>,
    ) -> Result<(), error::Unspecified> {
        let s = bssl();
        unsafe {
            let mctx = (s.EVP_MD_CTX_new)();
            if mctx.is_null() {
                clear_error();
                return Err(error::Unspecified);
            }
            let mut pctx: *mut EVP_PKEY_CTX = ptr::null_mut();
            let init_rc =
                (s.EVP_DigestVerifyInit)(mctx, &mut pctx, md, ptr::null_mut(), pkey.as_ptr());
            if init_rc != 1 {
                (s.EVP_MD_CTX_free)(mctx);
                clear_error();
                return Err(error::Unspecified);
            }
            if let Err(e) = configure_pctx(pctx) {
                (s.EVP_MD_CTX_free)(mctx);
                clear_error();
                return Err(e);
            }
            let rc = (s.EVP_DigestVerify)(mctx, sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len());
            (s.EVP_MD_CTX_free)(mctx);
            if rc == 1 {
                Ok(())
            } else {
                clear_error();
                Err(error::Unspecified)
            }
        }
    }

    /// Verifies `sig` against an *already-computed* hash (`digest_bytes`) using BoringSSL's
    /// `EVP_PKEY_verify_init` + `EVP_PKEY_CTX_set_signature_md` + `EVP_PKEY_verify`.
    ///
    /// Used when verifying a Sigstore bundle against a precomputed SHA-256 artifact digest
    /// (`SigstoreClient.verify(artifactDigest: ...)`).
    pub(crate) fn evp_pkey_verify_digest(
        pkey: &EvpPkey,
        md: *const crate::FFI::EVP_MD,
        digest_bytes: &[u8],
        sig: &[u8],
        configure_pctx: impl FnOnce(*mut EVP_PKEY_CTX) -> Result<(), error::Unspecified>,
    ) -> Result<(), error::Unspecified> {
        let s = bssl();
        unsafe {
            let pctx = (s.EVP_PKEY_CTX_new)(pkey.as_ptr(), ptr::null_mut());
            if pctx.is_null() {
                clear_error();
                return Err(error::Unspecified);
            }
            if (s.EVP_PKEY_verify_init)(pctx) != 1 {
                (s.EVP_PKEY_CTX_free)(pctx);
                clear_error();
                return Err(error::Unspecified);
            }
            if (s.EVP_PKEY_CTX_set_signature_md)(pctx, md) != 1 {
                (s.EVP_PKEY_CTX_free)(pctx);
                clear_error();
                return Err(error::Unspecified);
            }
            if let Err(e) = configure_pctx(pctx) {
                (s.EVP_PKEY_CTX_free)(pctx);
                clear_error();
                return Err(e);
            }
            let rc = (s.EVP_PKEY_verify)(
                pctx,
                sig.as_ptr(),
                sig.len(),
                digest_bytes.as_ptr(),
                digest_bytes.len(),
            );
            (s.EVP_PKEY_CTX_free)(pctx);
            if rc == 1 {
                Ok(())
            } else {
                clear_error();
                Err(error::Unspecified)
            }
        }
    }

    impl VerificationAlgorithm for EcdsaVerificationAlgorithm {
        fn verify_sig(
            &self,
            public_key: &[u8],
            msg: &[u8],
            signature: &[u8],
        ) -> Result<(), error::Unspecified> {
            let pkey = parse_ec_public_key(self.curve, public_key)?;
            let der_cow: Vec<u8>;
            let der_sig = match self.format {
                EcdsaSigFormat::Asn1 => signature,
                EcdsaSigFormat::Fixed => {
                    der_cow = fixed_ecdsa_sig_to_der(signature, self.curve.coord_len())?;
                    &der_cow
                }
            };
            evp_digest_verify(&pkey, self.digest.evp_md(), msg, der_sig, |_| Ok(()))
        }

        fn verify_digest_sig(
            &self,
            public_key: &[u8],
            digest: &crate::digest::Digest,
            signature: &[u8],
        ) -> Result<(), error::Unspecified> {
            if digest.algorithm().id != self.digest {
                return Err(error::Unspecified);
            }
            let pkey = parse_ec_public_key(self.curve, public_key)?;
            let der_cow: Vec<u8>;
            let der_sig = match self.format {
                EcdsaSigFormat::Asn1 => signature,
                EcdsaSigFormat::Fixed => {
                    der_cow = fixed_ecdsa_sig_to_der(signature, self.curve.coord_len())?;
                    &der_cow
                }
            };
            evp_pkey_verify_digest(
                &pkey,
                self.digest.evp_md(),
                digest.as_ref(),
                der_sig,
                |_| Ok(()),
            )
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct EdDSAParameters;

    pub static ED25519: EdDSAParameters = EdDSAParameters;
    pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

    impl VerificationAlgorithm for EdDSAParameters {
        fn verify_sig(
            &self,
            public_key: &[u8],
            msg: &[u8],
            signature: &[u8],
        ) -> Result<(), error::Unspecified> {
            if public_key.len() != ED25519_PUBLIC_KEY_LEN || signature.len() != 64 {
                return Err(error::Unspecified);
            }
            let s = bssl();
            let alg = unsafe { (s.EVP_pkey_ed25519)() };
            let ptr = unsafe {
                (s.EVP_PKEY_from_raw_public_key)(alg, public_key.as_ptr(), public_key.len())
            };
            let pkey = EvpPkey::from_ptr(ptr)?;
            // Ed25519 (PureEdDSA) hashes the message internally in two passes, so `md` MUST be null.
            evp_digest_verify(&pkey, ptr::null(), msg, signature, |_| Ok(()))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RsaPadding {
        Pkcs1,
        Pss,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct RsaParameters {
        pub(crate) digest: DigestId,
        pub(crate) padding: RsaPadding,
        pub(crate) min_bits: usize,
        pub(crate) max_bits: usize,
    }

    pub static RSA_PKCS1_2048_8192_SHA256: RsaParameters = RsaParameters {
        digest: DigestId::Sha256,
        padding: RsaPadding::Pkcs1,
        min_bits: 2048,
        max_bits: 8192,
    };

    pub static RSA_PKCS1_2048_8192_SHA384: RsaParameters = RsaParameters {
        digest: DigestId::Sha384,
        padding: RsaPadding::Pkcs1,
        min_bits: 2048,
        max_bits: 8192,
    };

    pub static RSA_PKCS1_2048_8192_SHA512: RsaParameters = RsaParameters {
        digest: DigestId::Sha512,
        padding: RsaPadding::Pkcs1,
        min_bits: 2048,
        max_bits: 8192,
    };

    pub static RSA_PKCS1_3072_8192_SHA384: RsaParameters = RsaParameters {
        digest: DigestId::Sha384,
        padding: RsaPadding::Pkcs1,
        min_bits: 3072,
        max_bits: 8192,
    };

    pub static RSA_PSS_2048_8192_SHA256: RsaParameters = RsaParameters {
        digest: DigestId::Sha256,
        padding: RsaPadding::Pss,
        min_bits: 2048,
        max_bits: 8192,
    };

    pub static RSA_PSS_2048_8192_SHA384: RsaParameters = RsaParameters {
        digest: DigestId::Sha384,
        padding: RsaPadding::Pss,
        min_bits: 2048,
        max_bits: 8192,
    };

    pub static RSA_PSS_2048_8192_SHA512: RsaParameters = RsaParameters {
        digest: DigestId::Sha512,
        padding: RsaPadding::Pss,
        min_bits: 2048,
        max_bits: 8192,
    };

    #[derive(Debug, PartialEq, Eq)]
    pub struct RsaEncoding {
        pub(crate) digest: DigestId,
        pub(crate) padding: RsaPadding,
    }

    pub static RSA_PKCS1_SHA256: RsaEncoding = RsaEncoding {
        digest: DigestId::Sha256,
        padding: RsaPadding::Pkcs1,
    };

    pub static RSA_PKCS1_SHA384: RsaEncoding = RsaEncoding {
        digest: DigestId::Sha384,
        padding: RsaPadding::Pkcs1,
    };

    pub static RSA_PKCS1_SHA512: RsaEncoding = RsaEncoding {
        digest: DigestId::Sha512,
        padding: RsaPadding::Pkcs1,
    };

    pub static RSA_PSS_SHA256: RsaEncoding = RsaEncoding {
        digest: DigestId::Sha256,
        padding: RsaPadding::Pss,
    };

    pub static RSA_PSS_SHA384: RsaEncoding = RsaEncoding {
        digest: DigestId::Sha384,
        padding: RsaPadding::Pss,
    };

    pub static RSA_PSS_SHA512: RsaEncoding = RsaEncoding {
        digest: DigestId::Sha512,
        padding: RsaPadding::Pss,
    };

    /// Parses a PKCS#1 `RSAPublicKey` DER sequence (`SEQUENCE { n INTEGER, e INTEGER }`) into a
    /// BoringSSL `EVP_PKEY*` by wrapping it in an SPKI DER header, and checks that the modulus bit
    /// length falls within `[min_bits, max_bits]`.
    fn parse_rsa_public_key(
        public_key: &[u8],
        min_bits: usize,
        max_bits: usize,
    ) -> Result<EvpPkey, error::Unspecified> {
        let s = bssl();
        let spki = wrap_spki(ALG_ID_RSA_ENCRYPTION, public_key);
        let algs = unsafe { [(s.EVP_pkey_rsa)()] };
        let ptr = unsafe {
            (s.EVP_PKEY_from_subject_public_key_info)(
                spki.as_ptr(),
                spki.len(),
                algs.as_ptr(),
                algs.len(),
            )
        };
        let pkey = EvpPkey::from_ptr(ptr)?;
        let bits = unsafe { (s.EVP_PKEY_bits)(pkey.as_ptr()) } as usize;
        if bits < min_bits || bits > max_bits {
            return Err(error::Unspecified);
        }
        Ok(pkey)
    }

    impl VerificationAlgorithm for RsaParameters {
        fn verify_sig(
            &self,
            public_key: &[u8],
            msg: &[u8],
            signature: &[u8],
        ) -> Result<(), error::Unspecified> {
            let s = bssl();
            let pkey = parse_rsa_public_key(public_key, self.min_bits, self.max_bits)?;
            let md = self.digest.evp_md();
            let padding = self.padding;
            evp_digest_verify(&pkey, md, msg, signature, |pctx| unsafe {
                match padding {
                    RsaPadding::Pkcs1 => {
                        if (s.EVP_PKEY_CTX_set_rsa_padding)(pctx, RSA_PKCS1_PADDING) != 1 {
                            return Err(error::Unspecified);
                        }
                    }
                    RsaPadding::Pss => {
                        if (s.EVP_PKEY_CTX_set_rsa_padding)(pctx, RSA_PKCS1_PSS_PADDING) != 1 {
                            return Err(error::Unspecified);
                        }
                        if (s.EVP_PKEY_CTX_set_rsa_pss_saltlen)(pctx, RSA_PSS_SALTLEN_DIGEST) != 1 {
                            return Err(error::Unspecified);
                        }
                    }
                }
                Ok(())
            })
        }

        fn verify_digest_sig(
            &self,
            public_key: &[u8],
            digest: &crate::digest::Digest,
            signature: &[u8],
        ) -> Result<(), error::Unspecified> {
            if digest.algorithm().id != self.digest {
                return Err(error::Unspecified);
            }
            let s = bssl();
            let pkey = parse_rsa_public_key(public_key, self.min_bits, self.max_bits)?;
            let md = self.digest.evp_md();
            let padding = self.padding;
            evp_pkey_verify_digest(&pkey, md, digest.as_ref(), signature, |pctx| unsafe {
                match padding {
                    RsaPadding::Pkcs1 => {
                        if (s.EVP_PKEY_CTX_set_rsa_padding)(pctx, RSA_PKCS1_PADDING) != 1 {
                            return Err(error::Unspecified);
                        }
                    }
                    RsaPadding::Pss => {
                        if (s.EVP_PKEY_CTX_set_rsa_padding)(pctx, RSA_PKCS1_PSS_PADDING) != 1 {
                            return Err(error::Unspecified);
                        }
                        if (s.EVP_PKEY_CTX_set_rsa_pss_saltlen)(pctx, RSA_PSS_SALTLEN_DIGEST) != 1 {
                            return Err(error::Unspecified);
                        }
                    }
                }
                Ok(())
            })
        }
    }

    /// Primary verification entry point in the `ring`/`aws-lc-rs` API: pairs a
    /// [`VerificationAlgorithm`] with raw public key bytes (`B`).
    #[derive(Clone)]
    pub struct UnparsedPublicKey<B> {
        algorithm: &'static dyn VerificationAlgorithm,
        bytes: B,
    }

    impl<B: Copy> Copy for UnparsedPublicKey<B> {}

    impl<B> UnparsedPublicKey<B> {
        #[inline]
        pub fn new(algorithm: &'static dyn VerificationAlgorithm, bytes: B) -> Self {
            Self { algorithm, bytes }
        }
    }

    impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), error::Unspecified> {
            self.algorithm
                .verify_sig(self.bytes.as_ref(), message, signature)
        }

        pub fn verify_digest(
            &self,
            digest: &crate::digest::Digest,
            signature: &[u8],
        ) -> Result<(), error::Unspecified> {
            self.algorithm
                .verify_digest_sig(self.bytes.as_ref(), digest, signature)
        }
    }

    impl<B: fmt::Debug> fmt::Debug for UnparsedPublicKey<B> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("UnparsedPublicKey")
                .field("algorithm", &self.algorithm)
                .field("bytes", &self.bytes)
                .finish()
        }
    }

    #[derive(Clone)]
    pub struct PublicKey {
        bytes: Vec<u8>,
    }

    impl AsRef<[u8]> for PublicKey {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl fmt::Debug for PublicKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("PublicKey").field(&self.bytes).finish()
        }
    }

    // ========================================================================
    // Stub Signing KeyPair Types (`EcdsaKeyPair`, `Ed25519KeyPair`, `RsaKeyPair`)
    // ========================================================================
    // `sigstore-crypto` defines signing helpers in the same crate as its verification helpers.
    // Even though `package:sigstore` only calls verification functions (and LTO dead-code
    // eliminates the unused signing functions from the final binary), the key-pair structs and
    // their method signatures must exist here so `sigstore-crypto` compiles cleanly.

    pub struct EcdsaKeyPair {
        alg: &'static EcdsaSigningAlgorithm,
        pub_key: PublicKey,
    }

    impl fmt::Debug for EcdsaKeyPair {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("EcdsaKeyPair")
                .field("alg", &self.alg)
                .field("public_key", &self.pub_key)
                .finish()
        }
    }

    impl EcdsaKeyPair {
        pub fn generate_pkcs8(
            _alg: &'static EcdsaSigningAlgorithm,
            _rng: &dyn rand::SecureRandom,
        ) -> Result<pkcs8::Document, error::Unspecified> {
            Err(error::Unspecified)
        }

        pub fn from_pkcs8(
            _alg: &'static EcdsaSigningAlgorithm,
            _pkcs8: &[u8],
        ) -> Result<Self, error::KeyRejected> {
            Err(error::KeyRejected::unexpected_error())
        }

        pub fn from_private_key_and_public_key(
            _alg: &'static EcdsaSigningAlgorithm,
            _private_key: &[u8],
            _public_key: &[u8],
        ) -> Result<Self, error::KeyRejected> {
            Err(error::KeyRejected::unexpected_error())
        }

        pub fn sign(
            &self,
            _rng: &dyn rand::SecureRandom,
            _message: &[u8],
        ) -> Result<Signature, error::Unspecified> {
            Err(error::Unspecified)
        }
    }

    impl KeyPair for EcdsaKeyPair {
        type PublicKey = PublicKey;

        #[inline]
        fn public_key(&self) -> &Self::PublicKey {
            &self.pub_key
        }
    }

    pub struct Ed25519KeyPair {
        pub_key: PublicKey,
    }

    impl fmt::Debug for Ed25519KeyPair {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Ed25519KeyPair")
                .field("public_key", &self.pub_key)
                .finish()
        }
    }

    impl Ed25519KeyPair {
        pub fn generate_pkcs8(
            _rng: &dyn rand::SecureRandom,
        ) -> Result<pkcs8::Document, error::Unspecified> {
            Err(error::Unspecified)
        }

        pub fn from_pkcs8(_pkcs8: &[u8]) -> Result<Self, error::KeyRejected> {
            Err(error::KeyRejected::unexpected_error())
        }

        pub fn from_pkcs8_maybe_unchecked(_pkcs8: &[u8]) -> Result<Self, error::KeyRejected> {
            Err(error::KeyRejected::unexpected_error())
        }

        pub fn from_seed_unchecked(_seed: &[u8]) -> Result<Self, error::KeyRejected> {
            Err(error::KeyRejected::unexpected_error())
        }

        pub fn from_seed_and_public_key(
            _seed: &[u8],
            _public_key: &[u8],
        ) -> Result<Self, error::KeyRejected> {
            Err(error::KeyRejected::unexpected_error())
        }

        pub fn sign(&self, _msg: &[u8]) -> Signature {
            Signature {
                bytes: [0u8; MAX_LEN],
                len: 0,
            }
        }
    }

    impl KeyPair for Ed25519KeyPair {
        type PublicKey = PublicKey;

        #[inline]
        fn public_key(&self) -> &Self::PublicKey {
            &self.pub_key
        }
    }

    pub struct RsaKeyPair {
        pub_key: PublicKey,
        modulus_len: usize,
    }

    impl fmt::Debug for RsaKeyPair {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("RsaKeyPair")
                .field("modulus_len", &self.modulus_len)
                .finish()
        }
    }

    impl RsaKeyPair {
        pub fn from_pkcs8(_pkcs8: &[u8]) -> Result<Self, error::KeyRejected> {
            Err(error::KeyRejected::unexpected_error())
        }

        pub fn from_der(_der: &[u8]) -> Result<Self, error::KeyRejected> {
            Err(error::KeyRejected::unexpected_error())
        }

        #[inline]
        pub fn public_modulus_len(&self) -> usize {
            self.modulus_len
        }

        pub fn sign(
            &self,
            _padding_alg: &'static RsaEncoding,
            _rng: &dyn rand::SecureRandom,
            _msg: &[u8],
            _signature: &mut [u8],
        ) -> Result<(), error::Unspecified> {
            Err(error::Unspecified)
        }
    }

    impl KeyPair for RsaKeyPair {
        type PublicKey = PublicKey;

        #[inline]
        fn public_key(&self) -> &Self::PublicKey {
            &self.pub_key
        }
    }
}

/// Re-export matching `aws_lc_rs::rsa::KeyPair`.
pub mod rsa {
    pub use crate::signature::RsaKeyPair as KeyPair;
}

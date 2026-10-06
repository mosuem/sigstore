use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Default Sigstore production TUF repository URL
pub const DEFAULT_TUF_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// Sigstore staging TUF repository URL
pub const STAGING_TUF_URL: &str = "https://tuf-repo-cdn.sigstage.dev";

/// GitHub artifact attestation TUF repository URL
pub const GITHUB_TUF_URL: &str = "https://tuf-repo.github.com";

/// Embedded root.json for production TUF instance
pub const PRODUCTION_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_root.json");

/// Embedded root.json for staging TUF instance
pub const STAGING_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_staging_root.json");

/// Embedded root.json for GitHub's artifact attestation TUF instance
pub const GITHUB_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_github_root.json");

pub(crate) struct TufBridgeState {
    pub pending_url: Option<String>,
    pub pending_max_length: u64,
    pub response: Option<sigstore_tuf::Result<Option<Vec<u8>>>>,
}

struct BridgeFetchFuture {
    state: Arc<Mutex<TufBridgeState>>,
    url: String,
    max_length: u64,
    registered: bool,
}

impl Future for BridgeFetchFuture {
    type Output = sigstore_tuf::Result<Option<Vec<u8>>>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        let mut st = this.state.lock().unwrap();
        if !this.registered {
            st.pending_url = Some(this.url.clone());
            st.pending_max_length = this.max_length;
            this.registered = true;
            return Poll::Pending;
        }
        if let Some(res) = st.response.take() {
            if let Ok(Some(ref body)) = res {
                if body.len() as u64 > this.max_length {
                    return Poll::Ready(Err(sigstore_tuf::Error::Transport(format!(
                        "{}: response exceeds max length {}",
                        this.url, this.max_length
                    ))));
                }
            }
            return Poll::Ready(res);
        }
        st.pending_url = Some(this.url.clone());
        st.pending_max_length = this.max_length;
        Poll::Pending
    }
}

struct BridgeRepository {
    base_url: String,
    state: Arc<Mutex<TufBridgeState>>,
}

impl sigstore_tuf::Repository for BridgeRepository {
    fn fetch_metadata<'a>(
        &'a self,
        name: &'a str,
        max_length: u64,
    ) -> sigstore_tuf::transport::FetchFuture<'a> {
        let base = self.base_url.trim_end_matches('/');
        let rel = name.trim_start_matches('/');
        let url = format!("{base}/{rel}");
        Box::pin(BridgeFetchFuture {
            state: self.state.clone(),
            url,
            max_length,
            registered: false,
        })
    }

    fn fetch_target<'a>(
        &'a self,
        path: &'a str,
        max_length: u64,
    ) -> sigstore_tuf::transport::FetchFuture<'a> {
        let base = self.base_url.trim_end_matches('/');
        let rel = path.trim_start_matches('/');
        let url = format!("{base}/targets/{rel}");
        Box::pin(BridgeFetchFuture {
            state: self.state.clone(),
            url,
            max_length,
            registered: false,
        })
    }
}

type TufRefreshFuture = Pin<Box<dyn Future<Output = Result<String, Error>>>>;

pub struct TufUpdaterInner {
    pub(crate) state: Arc<Mutex<TufBridgeState>>,
    pub(crate) fut: Mutex<TufRefreshFuture>,
    pub(crate) result: Mutex<Option<String>>,
}

#[diplomat::bridge]
#[diplomat::abi_rename = "sigstore_{0}_mv1"]
pub mod ffi {
    use diplomat_runtime::{DiplomatStr, DiplomatWrite};
    use std::fmt::Write as _;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    /// Errors that can occur during Sigstore bundle parsing, verification, or root refresh.
    #[diplomat::enum_convert(crate::Error)]
    pub enum SigstoreError {
        /// The bundle is structurally invalid, cannot be parsed from JSON, or contains malformed verification material.
        InvalidBundle,
        /// Cryptographic verification failed.
        ///
        /// This can happen if the signature does not match, the certificate does not chain to the trusted root,
        /// the identity or issuer does not match policy expectations, or transparency log proofs fail.
        VerificationFailed,
        /// An internal error occurred during verification or cryptographic operations.
        InternalError,
    }

    /// A Sigstore bundle containing signature material, verification material (such as X.509 certificates
    /// or public key hints), and transparency log inclusion proofs.
    #[diplomat::opaque]
    pub struct SigstoreBundle(pub sigstore_types::Bundle);

    /// Client for verifying Sigstore signatures and managing trusted root material.
    #[diplomat::opaque]
    pub struct SigstoreClient(pub ());

    /// State machine driving the `sigstore-tuf` verification workflow over an external HTTP client.
    #[diplomat::opaque]
    pub struct SigstoreTufUpdater(pub crate::TufUpdaterInner);

    /// The result of verifying an artifact against a Sigstore bundle and verification policy.
    #[diplomat::opaque]
    pub struct SigstoreVerificationResult {
        pub is_valid: bool,
        pub identity: String,
        pub issuer: String,
    }

    /// Policy configuration specifying expected signing identity, issuer, trusted root, and network options for verification.
    #[diplomat::opaque]
    pub struct SigstoreVerificationPolicy {
        pub expected_identity: Option<String>,
        pub expected_issuer: Option<String>,
        pub offline: bool,
        pub is_staging: bool,
        pub custom_trusted_root: Option<String>,
        pub public_key_pem: Option<String>,
    }

    fn opt_str(s: &DiplomatStr) -> Option<String> {
        std::str::from_utf8(s)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    impl SigstoreVerificationPolicy {
        /// Creates a new verification policy.
        ///
        /// - `expected_identity`: Expected certificate subject (SAN email or URI). If empty, identity is not restricted.
        /// - `expected_issuer`: Expected OIDC issuer URL (e.g. `https://token.actions.githubusercontent.com`). If empty, issuer is not restricted.
        /// - `offline`: Whether to perform verification offline without network access.
        /// - `is_staging`: Whether to verify against Sigstore's staging environment instead of production.
        /// - `trusted_root_json`: Optional custom trusted root JSON string. If empty, the default Sigstore root is used.
        /// - `public_key_pem`: Optional PEM-encoded public key for verifying bundles created with pre-shared keys.
        pub fn create(
            expected_identity: &DiplomatStr,
            expected_issuer: &DiplomatStr,
            offline: bool,
            is_staging: bool,
            trusted_root_json: &DiplomatStr,
            public_key_pem: &DiplomatStr,
        ) -> Result<Box<SigstoreVerificationPolicy>, SigstoreError> {
            Ok(Box::new(SigstoreVerificationPolicy {
                expected_identity: opt_str(expected_identity),
                expected_issuer: opt_str(expected_issuer),
                offline,
                is_staging,
                custom_trusted_root: opt_str(trusted_root_json),
                public_key_pem: opt_str(public_key_pem),
            }))
        }
    }

    impl SigstoreBundle {
        fn cert_info(&self) -> Result<sigstore_verify::crypto::CertificateInfo, SigstoreError> {
            let cert_der = match &self.0.verification_material.content {
                sigstore_types::bundle::VerificationMaterialContent::X509CertificateChain {
                    certificates,
                } => certificates.first().map(|c| c.raw_bytes.as_ref()),
                sigstore_types::bundle::VerificationMaterialContent::Certificate(cert) => {
                    Some(cert.raw_bytes.as_ref())
                }
                _ => None,
            };
            let der = cert_der.ok_or(SigstoreError::InvalidBundle)?;
            sigstore_verify::crypto::parse_certificate_info(der)
                .map_err(|_| SigstoreError::InvalidBundle)
        }

        /// Parses a Sigstore bundle from a JSON string.
        pub fn from_json(json: &DiplomatStr) -> Result<Box<SigstoreBundle>, SigstoreError> {
            let json_str = std::str::from_utf8(json).map_err(|_| SigstoreError::InvalidBundle)?;
            let bundle: sigstore_types::Bundle =
                serde_json::from_str(json_str).map_err(|_| SigstoreError::InvalidBundle)?;
            Ok(Box::new(SigstoreBundle(bundle)))
        }

        /// Serializes the Sigstore bundle to a JSON string.
        pub fn to_json(&self, write: &mut DiplomatWrite) -> Result<(), SigstoreError> {
            let json = serde_json::to_string(&self.0).map_err(|_| SigstoreError::InternalError)?;
            write!(write, "{}", json).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }

        /// Returns the certificate subject (subject alternative name email or URI) from the signing certificate.
        pub fn get_certificate_subject(
            &self,
            write: &mut DiplomatWrite,
        ) -> Result<(), SigstoreError> {
            let info = self.cert_info()?;
            let subject = info.identity.unwrap_or_default();
            write!(write, "{}", subject).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }

        /// Returns the OIDC issuer URL from the signing certificate extensions.
        pub fn get_certificate_issuer(
            &self,
            write: &mut DiplomatWrite,
        ) -> Result<(), SigstoreError> {
            let info = self.cert_info()?;
            let issuer = info.issuer.unwrap_or_default();
            write!(write, "{}", issuer).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }

        /// Returns the Rekor transparency log index if present, or `-1` if no log entry is present.
        pub fn get_rekor_log_index(&self) -> i64 {
            self.0
                .verification_material
                .tlog_entries
                .first()
                .map_or(-1, |e| e.log_index.value())
        }
    }

    impl SigstoreClient {
        /// Initializes the BoringSSL function pointer table from `package:boring` (`libbssl_dart`).
        ///
        /// `symbol_addrs` must contain the exact 28 function pointers defined by `BoringSymbols`.
        pub fn init_boring(symbol_addrs: &[usize]) -> Result<(), SigstoreError> {
            unsafe {
                aws_lc_rs::init_boring_symbols_from_slice(symbol_addrs)
                    .map_err(|_| SigstoreError::InternalError)
            }
        }

        /// Creates a new Sigstore client instance.
        pub fn create() -> Box<SigstoreClient> {
            Box::new(SigstoreClient(()))
        }

        /// Verifies an artifact against a Sigstore bundle and verification policy.
        ///
        /// - `artifact_bytes`: Raw artifact bytes, or precomputed SHA-256 digest bytes if `is_digest` is true.
        /// - `is_digest`: Set to `true` if `artifact_bytes` contains the precomputed SHA-256 digest (32 bytes).
        /// - `bundle`: The parsed bundle containing signatures and verification material.
        /// - `policy`: The verification policy specifying expected identity, issuer, and trusted root.
        pub fn verify(
            &self,
            artifact_bytes: &[u8],
            is_digest: bool,
            bundle: &SigstoreBundle,
            policy: &SigstoreVerificationPolicy,
        ) -> Result<Box<SigstoreVerificationResult>, SigstoreError> {
            let trusted_root = if let Some(ref custom_json) = policy.custom_trusted_root {
                sigstore_trust_root::TrustedRoot::from_json(custom_json)
                    .map_err(|_| SigstoreError::InvalidBundle)?
            } else if policy.is_staging {
                sigstore_trust_root::TrustedRoot::from_json(
                    sigstore_trust_root::SIGSTORE_STAGING_TRUSTED_ROOT,
                )
                .map_err(|_| SigstoreError::InternalError)?
            } else {
                sigstore_trust_root::TrustedRoot::from_json(
                    sigstore_trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT,
                )
                .map_err(|_| SigstoreError::InternalError)?
            };

            let artifact = if is_digest {
                sigstore_types::Artifact::from_digest(artifact_bytes)
            } else {
                sigstore_types::Artifact::from_bytes(artifact_bytes)
            };

            let res = if let Some(ref key_pem) = policy.public_key_pem {
                let public_key = sigstore_types::DerPublicKey::from_pem(key_pem)
                    .map_err(|_| SigstoreError::VerificationFailed)?;
                sigstore_verify::verify_with_key(artifact, &bundle.0, &public_key, &trusted_root)
            } else {
                let mut v_policy = sigstore_verify::VerificationPolicy::default();
                if let Some(ref id) = policy.expected_identity {
                    v_policy = v_policy.require_identity(id.clone());
                }
                if let Some(ref iss) = policy.expected_issuer {
                    v_policy = v_policy.require_issuer(iss.clone());
                }

                sigstore_verify::verify(artifact, &bundle.0, &v_policy, &trusted_root)
            }
            .map_err(|_| SigstoreError::VerificationFailed)?;

            Ok(Box::new(SigstoreVerificationResult {
                is_valid: true,
                identity: res.identity.unwrap_or_default(),
                issuer: res.issuer.unwrap_or_default(),
            }))
        }
    }

    impl SigstoreTufUpdater {
        /// Creates a new TUF refresh state machine for `tuf_mirror_url` and `cache_dir`.
        pub fn create(
            tuf_mirror_url: &DiplomatStr,
            cache_dir: &DiplomatStr,
        ) -> Result<Box<SigstoreTufUpdater>, SigstoreError> {
            let mirror_str =
                std::str::from_utf8(tuf_mirror_url).map_err(|_| SigstoreError::InternalError)?;
            let cache_str =
                std::str::from_utf8(cache_dir).map_err(|_| SigstoreError::InternalError)?;

            let base_url = if mirror_str.is_empty() {
                crate::DEFAULT_TUF_URL.to_string()
            } else {
                mirror_str.to_string()
            };
            let normalized_url = base_url.trim_end_matches('/');

            if !normalized_url.starts_with("http://") && !normalized_url.starts_with("https://") {
                return Err(SigstoreError::VerificationFailed);
            }

            let root_bytes: Vec<u8> = if normalized_url == crate::DEFAULT_TUF_URL {
                crate::PRODUCTION_TUF_ROOT.to_vec()
            } else if normalized_url == crate::STAGING_TUF_URL {
                crate::STAGING_TUF_ROOT.to_vec()
            } else if normalized_url == crate::GITHUB_TUF_URL {
                crate::GITHUB_TUF_ROOT.to_vec()
            } else if !cache_str.is_empty() {
                let cached_root = PathBuf::from(cache_str).join("root.json");
                std::fs::read(&cached_root).unwrap_or_else(|_| crate::PRODUCTION_TUF_ROOT.to_vec())
            } else {
                crate::PRODUCTION_TUF_ROOT.to_vec()
            };

            let state = Arc::new(Mutex::new(crate::TufBridgeState {
                pending_url: None,
                pending_max_length: 0,
                response: None,
            }));

            let repo = crate::BridgeRepository {
                base_url,
                state: state.clone(),
            };

            let mut updater = sigstore_tuf::Updater::new(repo, &root_bytes)
                .map_err(|_| SigstoreError::VerificationFailed)?;

            if !cache_str.is_empty() {
                let cache_path = PathBuf::from(cache_str);
                std::fs::create_dir_all(&cache_path)
                    .map_err(|_| SigstoreError::VerificationFailed)?;
                updater = updater.with_store(sigstore_tuf::FileStore::new(cache_path));
            }

            let fut = Box::pin(async move {
                let now = jiff::Timestamp::now();
                updater
                    .refresh(now)
                    .await
                    .map_err(|_| crate::Error::VerificationFailed)?;
                let target_bytes = updater
                    .get_target("trusted_root.json", now)
                    .await
                    .map_err(|_| crate::Error::VerificationFailed)?;
                let target_str = std::str::from_utf8(&target_bytes)
                    .map_err(|_| crate::Error::VerificationFailed)?;
                let trusted_root = sigstore_trust_root::TrustedRoot::from_json(target_str)
                    .map_err(|_| crate::Error::VerificationFailed)?;
                serde_json::to_string(&trusted_root).map_err(|_| crate::Error::InternalError)
            });

            Ok(Box::new(SigstoreTufUpdater(crate::TufUpdaterInner {
                state,
                fut: Mutex::new(fut),
                result: Mutex::new(None),
            })))
        }

        /// Advances the TUF state machine until it either completes (writing an empty string)
        /// or requests an HTTP GET (writing the pending URL to `write`).
        pub fn poll(&self, write: &mut DiplomatWrite) -> Result<(), SigstoreError> {
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let mut fut = self.0.fut.lock().unwrap();
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(Ok(trusted_root_json)) => {
                    *self.0.result.lock().unwrap() = Some(trusted_root_json);
                    Ok(())
                }
                Poll::Ready(Err(e)) => Err(e.into()),
                Poll::Pending => {
                    let st = self.0.state.lock().unwrap();
                    let url = st
                        .pending_url
                        .as_deref()
                        .ok_or(SigstoreError::InternalError)?;
                    write!(write, "{}", url).map_err(|_| SigstoreError::InternalError)?;
                    Ok(())
                }
            }
        }

        /// Returns the maximum allowed response size in bytes for the currently pending HTTP GET.
        pub fn max_response_bytes(&self) -> usize {
            self.0.state.lock().unwrap().pending_max_length as usize
        }

        /// Supplies the HTTP status code and response body for the currently pending HTTP GET.
        pub fn provide_response(&self, status_code: u16, body: &[u8]) {
            let mut st = self.0.state.lock().unwrap();
            st.pending_url = None;
            st.response = Some(match status_code {
                200..=299 => Ok(Some(body.to_vec())),
                403 | 404 => Ok(None),
                _ => Err(sigstore_tuf::Error::Transport(format!(
                    "HTTP status {status_code}"
                ))),
            });
        }

        /// Supplies a transport error for the currently pending HTTP GET.
        pub fn provide_error(&self, message: &DiplomatStr) {
            let msg = std::str::from_utf8(message).unwrap_or("HTTP transport error");
            let mut st = self.0.state.lock().unwrap();
            st.pending_url = None;
            st.response = Some(Err(sigstore_tuf::Error::Transport(msg.to_string())));
        }

        /// Writes the verified `trusted_root.json` string after `poll` returns `true`.
        pub fn take_result(&self, write: &mut DiplomatWrite) -> Result<(), SigstoreError> {
            let res_guard = self.0.result.lock().unwrap();
            let res = res_guard.as_deref().ok_or(SigstoreError::InternalError)?;
            write!(write, "{}", res).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }
    }

    impl SigstoreVerificationResult {
        /// Returns `true` if the artifact signature and verification materials are valid.
        pub fn is_valid(&self) -> bool {
            self.is_valid
        }

        /// Returns the verified signing identity (subject alternative name email or URI) from the certificate.
        pub fn verified_identity(&self, write: &mut DiplomatWrite) -> Result<(), SigstoreError> {
            write!(write, "{}", self.identity).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }

        /// Returns the verified OIDC issuer URL from the signing certificate extensions.
        pub fn verified_issuer(&self, write: &mut DiplomatWrite) -> Result<(), SigstoreError> {
            write!(write, "{}", self.issuer).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid bundle")]
    InvalidBundle,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Internal error")]
    InternalError,
}

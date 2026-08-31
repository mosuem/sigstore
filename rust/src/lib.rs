#[diplomat::bridge]
#[diplomat::abi_rename = "sigstore_{0}_mv1"]
pub mod ffi {
    use diplomat_runtime::{DiplomatStr, DiplomatWrite};
    use std::fmt::Write as _;

    #[diplomat::enum_convert(crate::Error)]
    pub enum SigstoreError {
        InvalidBundle,
        VerificationFailed,
        InternalError,
    }

    #[diplomat::opaque]
    pub struct SigstoreBundle(pub sigstore_types::Bundle);

    #[diplomat::opaque]
    pub struct SigstoreClient(pub ());

    #[diplomat::opaque]
    pub struct SigstoreVerificationResult {
        pub is_valid: bool,
        pub identity: String,
        pub issuer: String,
    }

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

    fn validate_trusted_root(root: &sigstore_trust_root::TrustedRoot) -> Result<(), SigstoreError> {
        let tlog_valid = root.tlogs.iter().all(|t| {
            t.public_key
                .valid_for
                .as_ref()
                .is_none_or(|v| v.start.is_some())
        });
        let ctlog_valid = root.ctlogs.iter().all(|t| {
            t.public_key
                .valid_for
                .as_ref()
                .is_none_or(|v| v.start.is_some())
        });
        let ca_valid = root
            .certificate_authorities
            .iter()
            .all(|ca| ca.valid_for.as_ref().is_none_or(|v| v.start.is_some()));
        let tsa_valid = root
            .timestamp_authorities
            .iter()
            .all(|tsa| tsa.valid_for.as_ref().is_none_or(|v| v.start.is_some()));

        if tlog_valid && ctlog_valid && ca_valid && tsa_valid {
            Ok(())
        } else {
            Err(SigstoreError::InvalidBundle)
        }
    }

    impl SigstoreVerificationPolicy {
        /// Create a new verification policy.
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

        /// Parse a Sigstore bundle from JSON string.
        pub fn from_json(json: &DiplomatStr) -> Result<Box<SigstoreBundle>, SigstoreError> {
            let json_str = std::str::from_utf8(json).map_err(|_| SigstoreError::InvalidBundle)?;
            let bundle: sigstore_types::Bundle =
                serde_json::from_str(json_str).map_err(|_| SigstoreError::InvalidBundle)?;
            Ok(Box::new(SigstoreBundle(bundle)))
        }

        /// Export the Sigstore bundle to JSON string.
        pub fn to_json(&self, write: &mut DiplomatWrite) -> Result<(), SigstoreError> {
            let json = serde_json::to_string(&self.0).map_err(|_| SigstoreError::InternalError)?;
            write!(write, "{}", json).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }

        /// Get certificate subject (SAN email/URI).
        pub fn get_certificate_subject(
            &self,
            write: &mut DiplomatWrite,
        ) -> Result<(), SigstoreError> {
            let info = self.cert_info()?;
            let subject = info.identity.unwrap_or_default();
            write!(write, "{}", subject).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }

        /// Get certificate OIDC issuer.
        pub fn get_certificate_issuer(
            &self,
            write: &mut DiplomatWrite,
        ) -> Result<(), SigstoreError> {
            let info = self.cert_info()?;
            let issuer = info.issuer.unwrap_or_default();
            write!(write, "{}", issuer).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }

        /// Get Rekor log index if present.
        pub fn get_rekor_log_index(&self) -> i64 {
            self.0
                .verification_material
                .tlog_entries
                .first()
                .map_or(-1, |e| e.log_index.value())
        }
    }

    impl SigstoreClient {
        /// Create a Sigstore client.
        pub fn create() -> Box<SigstoreClient> {
            Box::new(SigstoreClient(()))
        }

        /// Verify an artifact against a Sigstore bundle and verification policy.
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

            validate_trusted_root(&trusted_root)?;

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

                let verifier = sigstore_verify::Verifier::new(&trusted_root);
                verifier.verify(artifact, &bundle.0, &v_policy)
            }
            .map_err(|_| SigstoreError::VerificationFailed)?;

            Ok(Box::new(SigstoreVerificationResult {
                is_valid: true,
                identity: res.identity.unwrap_or_default(),
                issuer: res.issuer.unwrap_or_default(),
            }))
        }

        /// Refresh the TUF trusted root from the Sigstore TUF mirror into [cache_dir]
        /// using full TUF verification. Returns the verified `trusted_root.json` string.
        pub fn refresh_trusted_root(
            &self,
            tuf_mirror_url: &DiplomatStr,
            cache_dir: &DiplomatStr,
            write: &mut DiplomatWrite,
        ) -> Result<(), SigstoreError> {
            let mirror_str =
                std::str::from_utf8(tuf_mirror_url).map_err(|_| SigstoreError::InternalError)?;
            let cache_str =
                std::str::from_utf8(cache_dir).map_err(|_| SigstoreError::InternalError)?;

            let config =
                if mirror_str.is_empty() || mirror_str == sigstore_trust_root::DEFAULT_TUF_URL {
                    let mut c = sigstore_trust_root::TufConfig::production();
                    if !cache_str.is_empty() {
                        c = c.with_cache_dir(std::path::PathBuf::from(cache_str));
                    }
                    c
                } else if mirror_str == sigstore_trust_root::STAGING_TUF_URL {
                    let mut c = sigstore_trust_root::TufConfig::staging();
                    if !cache_str.is_empty() {
                        c = c.with_cache_dir(std::path::PathBuf::from(cache_str));
                    }
                    c
                } else {
                    let mut c = sigstore_trust_root::TufConfig::custom(mirror_str);
                    if !cache_str.is_empty() {
                        c = c.with_cache_dir(std::path::PathBuf::from(cache_str));
                    }
                    c
                };

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| SigstoreError::InternalError)?;

            let (trusted_root, _) = rt
                .block_on(async { sigstore_trust_root::fetch_trust_material(config).await })
                .map_err(|_| SigstoreError::VerificationFailed)?;

            let trusted_root_str =
                serde_json::to_string(&trusted_root).map_err(|_| SigstoreError::InternalError)?;

            write!(write, "{}", trusted_root_str).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }
    }

    impl SigstoreVerificationResult {
        pub fn is_valid(&self) -> bool {
            self.is_valid
        }

        pub fn verified_identity(&self, write: &mut DiplomatWrite) -> Result<(), SigstoreError> {
            write!(write, "{}", self.identity).map_err(|_| SigstoreError::InternalError)?;
            Ok(())
        }

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

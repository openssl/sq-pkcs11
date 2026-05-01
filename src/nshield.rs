/// nShield-specific PKCS#11 extension functions.
///
/// C_LoginBegin / C_LoginNext / C_LoginEnd replace the standard C_Login when
/// an Operator Card Set has K > 1 (quorum).  They are not part of the PKCS#11
/// standard and are not exposed by the `cryptoki` crate; we load them by
/// symbol name directly from the already-loaded nShield module.
use std::path::Path;

use anyhow::{Context, Result};
use libloading::Library;

// Raw PKCS#11 types (defined here to avoid depending on cryptoki-sys directly).
// PKCS#11 defines all of these as CK_ULONG = unsigned long.
#[allow(non_camel_case_types)]
type CK_ULONG = std::os::raw::c_ulong;
#[allow(non_camel_case_types)]
type CK_RV = CK_ULONG;
#[allow(non_camel_case_types)]
type CK_SESSION_HANDLE = CK_ULONG;
#[allow(non_camel_case_types)]
type CK_USER_TYPE = CK_ULONG;

// CKU_USER is 1 in the PKCS#11 spec.
const CKU_USER: CK_USER_TYPE = 1;

// nShield vendor CKR_ values (from pkcs11/pkcs11t.h, CKR_VENDOR_DEFINED | offset).
// Exposed for callers that want to match on specific nShield error conditions.
#[allow(dead_code)]
pub const CKR_FIPS_TOKEN_NOT_PRESENT: CK_RV = 0x8000_0001;
#[allow(dead_code)]
pub const CKR_FIPS_MECHANISM_INVALID: CK_RV = 0x8000_0002;
#[allow(dead_code)]
pub const CKR_FIPS_FUNCTION_NOT_SUPPORTED: CK_RV = 0x8000_0003;

// Raw function types matching the nShield prototypes.
type FnLoginBegin = unsafe extern "C" fn(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pk_out: *mut CK_ULONG,  // K (shares required)
    pn_out: *mut CK_ULONG,  // N (total shares in set)
) -> CK_RV;

type FnLoginNext = unsafe extern "C" fn(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: *const u8,
    pin_len: CK_ULONG,
    shares_left: *mut CK_ULONG,
) -> CK_RV;

type FnLoginEnd = unsafe extern "C" fn(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
) -> CK_RV;

/// Loaded handles to the three nShield quorum login functions.
pub struct NshieldQuorumLogin {
    // The Library must be kept alive for the function pointers to remain valid.
    _lib: Library,
    login_begin: FnLoginBegin,
    login_next: FnLoginNext,
    login_end: FnLoginEnd,
}

impl NshieldQuorumLogin {
    /// Load the quorum login symbols from `module_path`.
    pub fn load(module_path: &Path) -> Result<Self> {
        // SAFETY: loading a shared library is inherently unsafe.
        let lib = unsafe { Library::new(module_path) }
            .with_context(|| format!("loading nShield module {}", module_path.display()))?;

        // SAFETY: we store `_lib` in the struct, keeping the library loaded for
        // as long as `NshieldQuorumLogin` lives, so the function pointers remain valid.
        let login_begin: FnLoginBegin = unsafe {
            *lib.get::<FnLoginBegin>(b"C_LoginBegin\0")
                .context("C_LoginBegin not found — is this an nShield PKCS#11 module?")?
        };
        let login_next: FnLoginNext = unsafe {
            *lib.get::<FnLoginNext>(b"C_LoginNext\0")
                .context("C_LoginNext not found")?
        };
        let login_end: FnLoginEnd = unsafe {
            *lib.get::<FnLoginEnd>(b"C_LoginEnd\0")
                .context("C_LoginEnd not found")?
        };

        Ok(Self {
            _lib: lib,
            login_begin,
            login_next,
            login_end,
        })
    }

    /// Perform a K/N quorum login on `session`.
    ///
    /// `prompt` is called once per required card with the card index (1-based)
    /// and the remaining shares count, and must return the card passphrase
    /// (empty slice if the card has no passphrase).
    pub fn quorum_login<F>(
        &self,
        session: CK_SESSION_HANDLE,
        mut prompt: F,
    ) -> Result<()>
    where
        F: FnMut(/*card_n:*/ u64, /*k_required:*/ u64, /*n_total:*/ u64) -> Result<String>,
    {
        let mut k: CK_ULONG = 0;
        let mut n: CK_ULONG = 0;

        let rv = unsafe { (self.login_begin)(session, CKU_USER, &mut k, &mut n) };
        ck_ok(rv, "C_LoginBegin")?;

        eprintln!(
            "OCS quorum login: need {k} of {n} cards.",
        );

        let mut shares_left: CK_ULONG = k;
        let mut card_index: u64 = 1;

        while shares_left > 0 {
            let pin = prompt(card_index, k as u64, n as u64)?;
            let pin_bytes = pin.as_bytes();

            let rv = unsafe {
                (self.login_next)(
                    session,
                    CKU_USER,
                    pin_bytes.as_ptr(),
                    pin_bytes.len() as CK_ULONG,
                    &mut shares_left,
                )
            };
            ck_ok(rv, &format!("C_LoginNext (card {card_index})"))?;
            card_index += 1;
        }

        let rv = unsafe { (self.login_end)(session, CKU_USER) };
        ck_ok(rv, "C_LoginEnd")?;

        Ok(())
    }
}

fn ck_ok(rv: CK_RV, call: &str) -> Result<()> {
    if rv == 0 {
        return Ok(());
    }
    let msg = match rv {
        0x0000_0001 => "CKR_CANCEL",
        0x0000_0002 => "CKR_HOST_MEMORY",
        0x0000_0003 => "CKR_SLOT_ID_INVALID",
        0x0000_0005 => "CKR_GENERAL_ERROR",
        0x0000_0006 => "CKR_FUNCTION_FAILED",
        0x0000_0030 => "CKR_PIN_INCORRECT",
        0x0000_0031 => "CKR_PIN_INVALID",
        0x0000_0032 => "CKR_PIN_LEN_RANGE",
        0x0000_0100 => "CKR_SESSION_HANDLE_INVALID",
        0x0000_0101 => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        0x0000_00E0 => "CKR_TOKEN_NOT_PRESENT",
        0x0000_00E1 => "CKR_TOKEN_NOT_RECOGNIZED",
        0x8000_0001 => "CKR_FIPS_TOKEN_NOT_PRESENT (nShield)",
        0x8000_0002 => "CKR_FIPS_MECHANISM_INVALID (nShield)",
        0x8000_0003 => "CKR_FIPS_FUNCTION_NOT_SUPPORTED (nShield)",
        _ => "unknown CKR error",
    };
    anyhow::bail!("{call} returned {rv:#010x} ({msg})")
}

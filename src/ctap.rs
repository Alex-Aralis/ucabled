// SPDX-License-Identifier: GPL-3.0-or-later

use std::borrow::Cow;

use crate::cbor;
use rand::RngCore;
use rand::rngs::OsRng;

/// Stable AAGUID reported by getInfo. A fixed value keeps the authenticator
/// identity consistent across daemon restarts; the real attestation AAGUID
/// still comes from the phone.
pub const AAGUID: [u8; 16] = *b"ucabled-aaguid01";

// CTAP2 command bytes (CTAP 2.2 §6).
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;

// CTAP status bytes (CTAP 2.2 §8.2) used on this relay.
pub const CTAP2_OK: u8 = 0x00;
pub const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
pub const CTAP1_ERR_TIMEOUT: u8 = 0x05;
pub const CTAP1_ERR_CHANNEL_BUSY: u8 = 0x06;
pub const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
pub const CTAP2_ERR_INVALID_OPTION: u8 = 0x2c;
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2d;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
pub const CTAP2_ERR_NOT_ALLOWED: u8 = 0x32;
pub const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;

// Map keys of the CTAP2 requests parsed locally (CTAP 2.2 §6.1/§6.2).
const MC_KEY_RP: u64 = 2;
const MC_KEY_USER: u64 = 3;
const MC_KEY_EXCLUDE_LIST: u64 = 5;
const GA_KEY_RPID: u64 = 1;
const GA_KEY_ALLOW_LIST: u64 = 3;
const GA_KEY_OPTIONS: u64 = 5;

// Map keys of the getInfo response built locally (CTAP 2.2 §6.4).
const GETINFO_KEY_VERSIONS: u64 = 1;
const GETINFO_KEY_EXTENSIONS: u64 = 2;
const GETINFO_KEY_AAGUID: u64 = 3;
const GETINFO_KEY_OPTIONS: u64 = 4;
const GETINFO_KEY_MAX_MSG_SIZE: u64 = 5;
const GETINFO_KEY_MAX_CRED_COUNT_IN_LIST: u64 = 7;
const GETINFO_KEY_MAX_CRED_ID_LENGTH: u64 = 8;
const GETINFO_KEY_TRANSPORTS: u64 = 9;

// Map keys of the getAssertion response built locally (CTAP 2.2 §6.2).
const GA_RESP_KEY_CREDENTIAL: u64 = 1;
const GA_RESP_KEY_AUTH_DATA: u64 = 2;
const GA_RESP_KEY_SIGNATURE: u64 = 3;
const GA_RESP_KEY_NUMBER_OF_CREDENTIALS: u64 = 5;

// Synthetic assertion fields (see `answer_silent_probe`).
/// authData flags byte: user presence and user verification unset.
const AUTH_DATA_FLAGS: u8 = 0x00;
/// Signature counter width in authData.
const AUTH_DATA_SIGN_COUNTER_LEN: usize = 4;
/// Placeholder (all-zero) signature length.
const DUMMY_SIGNATURE_LEN: usize = 8;

/// GetInfo advertises this maxMsgSize (CTAP 2.2 §6.4 default upper bound).
pub const MAX_MSG_SIZE: u64 = 7609;

/// Advertised `maxCredentialCountInList`. Firefox/Chromium use this to decide
/// how many credential descriptors to put in one preflight `getAssertion` (and
/// to chunk the allowList). Relaying means there is no real per-authenticator
/// limit, so advertise a value large enough to keep a typical RP's whole
/// allowList in one request: chunking would let Firefox keep only the first
/// chunk (see `answer_silent_probe`).
pub const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = 64;

/// Advertised `maxCredentialIdLength`: Firefox drops allowList entries longer
/// than this before the preflight, so keep it generous.
pub const MAX_CREDENTIAL_ID_LENGTH: u64 = 1024;

/// authenticatorGetInfo response (status byte + canonical CBOR map).
///
/// Advertised per FR-5: FIDO_2_0 only (no U2F_V2), the `credProtect`
/// extension, rk/up/uv, no clientPin, maxMsgSize [`MAX_MSG_SIZE`], the
/// credential-list limits ([`MAX_CREDENTIAL_COUNT_IN_LIST`],
/// [`MAX_CREDENTIAL_ID_LENGTH`]) and transports ["hybrid"].
///
/// `credProtect` is advertised because OpenSSH refuses to create resident or
/// verify-required `sk` keys unless the authenticator reports it; the actual
/// credential (and its protection) is created by the phone, which receives
/// the extension in the relayed makeCredential.
pub fn getinfo_response(aaguid: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![CTAP2_OK];

    cbor::map(&mut out, 8);

    cbor::uint(&mut out, GETINFO_KEY_VERSIONS);
    cbor::array(&mut out, 1);
    cbor::text(&mut out, "FIDO_2_0");

    cbor::uint(&mut out, GETINFO_KEY_EXTENSIONS);
    cbor::array(&mut out, 1);
    cbor::text(&mut out, "credProtect");

    cbor::uint(&mut out, GETINFO_KEY_AAGUID);
    cbor::bytes(&mut out, aaguid);

    cbor::uint(&mut out, GETINFO_KEY_OPTIONS);
    cbor::map(&mut out, 3);
    for key in ["rk", "up", "uv"] {
        cbor::text(&mut out, key);
        out.push(cbor::TRUE);
    }

    // Must be minimally encoded: Chromium's CBOR reader rejects non-minimal
    // integers and would drop the whole device on a bad getInfo.
    cbor::uint(&mut out, GETINFO_KEY_MAX_MSG_SIZE);
    cbor::uint(&mut out, MAX_MSG_SIZE);

    // Without these, Firefox/Chromium preflight the allowList one credential at
    // a time; because the faked silent answer below always reports success,
    // only the first credential would survive into the real getAssertion.
    cbor::uint(&mut out, GETINFO_KEY_MAX_CRED_COUNT_IN_LIST);
    cbor::uint(&mut out, MAX_CREDENTIAL_COUNT_IN_LIST);
    cbor::uint(&mut out, GETINFO_KEY_MAX_CRED_ID_LENGTH);
    cbor::uint(&mut out, MAX_CREDENTIAL_ID_LENGTH);

    cbor::uint(&mut out, GETINFO_KEY_TRANSPORTS);
    cbor::array(&mut out, 1);
    cbor::text(&mut out, "hybrid");

    out
}

/// Minimal getInfo-shaped response ({versions, aaguid}) used only by the mock
/// phone and local relay tests, not by the real device.
pub fn mock_getinfo_response() -> Vec<u8> {
    let mut out = vec![CTAP2_OK];
    cbor::map(&mut out, 2);
    cbor::uint(&mut out, GETINFO_KEY_VERSIONS);
    cbor::array(&mut out, 1);
    cbor::text(&mut out, "FIDO_2_0");
    cbor::uint(&mut out, GETINFO_KEY_AAGUID);
    cbor::bytes(&mut out, &[0u8; 16]);
    out
}

/// Extract the RP ID from a makeCredential (key 2 -> rp map -> "id") or
/// getAssertion (key 1 -> string) request payload. Used for UI display, and
/// to tell a U2F AppID probe apart from a normal one via [`is_u2f_appid`].
/// Returns None on any parse irregularity; callers must tolerate that.
pub fn extract_rp_id(command: &[u8]) -> Option<String> {
    let (&cmd, params) = command.split_first()?;
    let mut c = cbor::Decoder::new(params);
    let pairs = c.map_header()?;
    // makeCredential: key 2 = rp entity map; getAssertion: key 1 = rpId.
    let wanted = match cmd {
        CMD_MAKE_CREDENTIAL => MC_KEY_RP,
        CMD_GET_ASSERTION => GA_KEY_RPID,
        _ => return None,
    };
    let mut rp_id = None;
    for _ in 0..pairs {
        let key = c.uint()?;
        if key == wanted && cmd == CMD_MAKE_CREDENTIAL {
            let inner_pairs = c.map_header()?;
            for _ in 0..inner_pairs {
                let k = c.text_str()?;
                if k == "id" {
                    rp_id = Some(c.text()?);
                } else {
                    c.skip_value()?;
                }
            }
        } else if key == wanted && cmd == CMD_GET_ASSERTION {
            rp_id = Some(c.text()?);
        } else {
            c.skip_value()?;
        }
    }
    rp_id
}

/// Whether a getAssertion RP ID is a legacy U2F AppID rather than a WebAuthn
/// RP ID.
///
/// WebAuthn RP IDs are bare domains (`x.com`); U2F AppIDs are URLs
/// (`https://api.x.com/1.1/onboarding/x_u2f_trusted_facets.json`). When a site
/// requests the `appid` client extension, Firefox probes an up=false
/// getAssertion with the AppID *as the RP ID* to discover U2F credentials and,
/// if the device reports one, rewrites the real request to address the AppID
/// instead of the WebAuthn RP ID (see `sign` in Mozilla's authenticator-rs).
/// The phone stores passkeys under the WebAuthn RP ID only, so such a probe
/// must be declined; otherwise Firefox switches to the AppID and the phone
/// finds no passkey ("no passkeys for this website").
pub fn is_u2f_appid(rp_id: &str) -> bool {
    rp_id.starts_with("https://") || rp_id.starts_with("http://")
}

/// Rebuild a CBOR map of text keys adding `add_key`/`add_value` if absent,
/// keeping canonical key order (length first, then lexicographic).
/// `data` must start exactly at the map header. Returns the rebuilt map and
/// the number of input bytes consumed.
fn patch_text_map<'a>(
    data: &'a [u8],
    add_key: &'a str,
    add_value: &str,
) -> Option<(Vec<u8>, usize)> {
    let mut c = cbor::Decoder::new(data);
    let pairs = c.map_header()?;

    let mut entries: Vec<(&str, std::ops::Range<usize>)> = Vec::new();
    let mut have_key = false;
    for _ in 0..pairs {
        let k = c.text_str()?;
        if k == add_key {
            have_key = true;
        }
        let start = c.pos();
        c.skip_value()?;
        entries.push((k, start..c.pos()));
    }
    if have_key {
        return None;
    }

    entries.push((add_key, 0..0)); // placeholder span
    entries.sort_by(|a, b| (a.0.len(), a.0).cmp(&(b.0.len(), b.0)));

    let mut out = Vec::new();
    cbor::map(&mut out, entries.len() as u64);
    for (k, span) in entries {
        cbor::text(&mut out, k);
        if k == add_key {
            cbor::text(&mut out, add_value);
        } else {
            out.extend_from_slice(&data[span]);
        }
    }
    Some((out, c.pos()))
}

/// Parse a getAssertion request into `(rpId, credential ids, up == false)`,
/// collecting *every* allowList credential (not just the first). The single
/// parse behind [`answer_silent_probe`]; returns None on any parse
/// irregularity. A missing or empty allowList yields an empty credential
/// list.
fn parse_get_assertion(command: &[u8]) -> Option<(String, Vec<Vec<u8>>, bool)> {
    let (&CMD_GET_ASSERTION, params) = command.split_first()? else {
        return None;
    };
    let mut c = cbor::Decoder::new(params);
    let pairs = c.map_header()?;

    let mut rp_id: Option<String> = None;
    let mut creds: Vec<Vec<u8>> = Vec::new();
    let mut up_false = false;
    for _ in 0..pairs {
        let key = c.uint()?;
        match key {
            GA_KEY_RPID => rp_id = Some(c.text()?),
            GA_KEY_ALLOW_LIST => {
                // allowList: array of credential descriptor maps
                let b = c.byte()?;
                if b >> 5 != cbor::MAJOR_ARRAY {
                    return None;
                }
                let n = c.argument(b & cbor::ARG_MASK)?;
                for _ in 0..n {
                    let entries = c.map_header()?;
                    let mut cred_id = None;
                    for _ in 0..entries {
                        let k = c.text_str()?;
                        if k == "id" {
                            let b = c.byte()?;
                            if b >> 5 != cbor::MAJOR_BYTES {
                                return None;
                            }
                            let len = c.argument(b & cbor::ARG_MASK)? as usize;
                            cred_id = Some(c.take(len)?.to_vec());
                        } else {
                            c.skip_value()?;
                        }
                    }
                    creds.push(cred_id?);
                }
            }
            GA_KEY_OPTIONS => {
                let inner = c.map_header()?;
                for _ in 0..inner {
                    let k = c.text_str()?;
                    if k == "up" {
                        up_false = c.byte()? == cbor::FALSE;
                    } else {
                        c.skip_value()?;
                    }
                }
            }
            _ => c.skip_value()?,
        }
    }

    Some((rp_id?, creds, up_false))
}

/// Detect Firefox's silent getAssertion probe (`options.up == false` **and**
/// a non-empty allowList) and, in the same parse, build the local answer.
/// Returns `(rpId, first response, remaining credential ids)`; the caller
/// serves the remainder from `authenticatorGetNextAssertion` with
/// [`fake_next_assertion`]. Firefox sends these probes (with an empty
/// clientDataHash) to filter the allowList to credentials present on this
/// device; a phone cannot answer silently, so the daemon answers locally.
/// Firefox only extracts the credential descriptors from these; the real
/// interactive request still goes to the phone with the whole allowList
/// intact, and the fake signatures never leave the browser's local
/// filtering code.
///
/// The allowList is required. A `up=false` assertion without one is a
/// discoverable (resident) getAssertion — `ssh-keygen -t ecdsa-sk -O resident`
/// sends one with rpId `ssh:` — which has nothing to filter and must be
/// relayed to the phone instead, as must any request that does not parse.
pub fn answer_silent_probe(command: &[u8]) -> Option<(String, Vec<u8>, Vec<Vec<u8>>)> {
    let (rp_id, creds, up_false) = parse_get_assertion(command)?;
    if !up_false || creds.is_empty() {
        return None;
    }
    let (first, rest) = creds.split_first().expect("creds is checked non-empty");
    let response = fake_assertion_response(&rp_id, first, creds.len());
    Some((rp_id, response, rest.to_vec()))
}

/// Build one structurally valid getAssertion "success" response echoing
/// `cred_id`, for answering Firefox's silent preflight probe (up=false) without
/// bothering the phone. When `total > 1`, the `numberOfCredentials` field is
/// set so the client fetches the rest with `authenticatorGetNextAssertion`;
/// the daemon serves those from [`fake_next_assertion`]. Firefox only extracts
/// the credential descriptors from these; the real interactive request still
/// goes to the phone with the whole allowList intact. The fake signatures never
/// leave the browser's local filtering code.
fn fake_assertion_response(rp_id: &str, cred_id: &[u8], total: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    // authData = rpIdHash || flags(0) || counter(0)
    let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
    auth_data.push(AUTH_DATA_FLAGS); // no UP/UV bits
    auth_data.extend_from_slice(&[0u8; AUTH_DATA_SIGN_COUNTER_LEN]);

    let mut out = vec![CTAP2_OK];
    cbor::map(&mut out, if total > 1 { 4 } else { 3 });
    // credential descriptor {"id": cred_id, "type": "public-key"}
    cbor::uint(&mut out, GA_RESP_KEY_CREDENTIAL);
    cbor::map(&mut out, 2);
    cbor::text(&mut out, "id");
    cbor::bytes(&mut out, cred_id);
    cbor::text(&mut out, "type");
    cbor::text(&mut out, "public-key");
    cbor::uint(&mut out, GA_RESP_KEY_AUTH_DATA);
    cbor::bytes(&mut out, &auth_data);
    cbor::uint(&mut out, GA_RESP_KEY_SIGNATURE);
    cbor::bytes(&mut out, &[0u8; DUMMY_SIGNATURE_LEN]);
    if total > 1 {
        cbor::uint(&mut out, GA_RESP_KEY_NUMBER_OF_CREDENTIALS);
        cbor::uint(&mut out, total as u64);
    }
    out
}

/// Build the faked response for one `authenticatorGetNextAssertion` follow-up
/// to [`answer_silent_probe`].
pub fn fake_next_assertion(rp_id: &str, cred_id: &[u8]) -> Vec<u8> {
    fake_assertion_response(rp_id, cred_id, 1)
}

/// Detect Firefox's "make me blink" dummy makeCredential, which Firefox sends
/// to physically identify the selected authenticator (a real key would flash).
/// There is nothing to blink on a phone; the daemon answers locally.
pub fn is_blink_probe(command: &[u8]) -> bool {
    extract_rp_id(command).as_deref() == Some("make.me.blink")
}

/// iOS requires `rp.name` and `user.displayName` in makeCredential requests;
/// Firefox omits them when the RP didn't provide them, and iOS then aborts
/// the hybrid session. Inject the missing fields (`user.displayName` falls
/// back to `user.name`, `rp.name` to ""). These are display-only fields not
/// covered by clientDataHash or attestation, so injecting them does not
/// affect cryptographic integrity. Returns a borrow of the input when no
/// patching is needed or the payload doesn't parse.
pub fn patch_makecredential(command: &[u8]) -> Cow<'_, [u8]> {
    let Some((&CMD_MAKE_CREDENTIAL, params)) = command.split_first() else {
        return Cow::Borrowed(command);
    };

    let result = (|| -> Option<Vec<u8>> {
        let mut c = cbor::Decoder::new(params);
        let pairs = c.map_header()?;

        let mut out = vec![CMD_MAKE_CREDENTIAL];
        let mut entries: Vec<(u64, std::ops::Range<usize>)> = Vec::new();
        for _ in 0..pairs {
            let key = c.uint()?;
            let start = c.pos();
            c.skip_value()?;
            entries.push((key, start..c.pos()));
        }

        let mut changed = false;
        cbor::map(&mut out, pairs);
        for (key, span) in entries {
            let value = &params[span.clone()];
            let patched = match key {
                MC_KEY_RP => {
                    // rp entity: add "name" if missing
                    patch_text_map(value, "name", "").map(|(v, _)| v)
                }
                MC_KEY_USER => {
                    // user entity: add "displayName", falling back to "name"
                    let display = {
                        let mut inner = cbor::Decoder::new(value);
                        let mut found = None;
                        if let Some(p) = inner.map_header() {
                            for _ in 0..p {
                                let Some(k) = inner.text_str() else { break };
                                if k == "name" {
                                    found = inner.text();
                                } else {
                                    if inner.skip_value().is_none() {
                                        break;
                                    }
                                }
                            }
                        }
                        found.unwrap_or_default()
                    };
                    patch_text_map(value, "displayName", &display).map(|(v, _)| v)
                }
                _ => None,
            };
            cbor::uint(&mut out, key);
            match patched {
                Some(v) => {
                    changed = true;
                    out.extend_from_slice(&v);
                }
                None => out.extend_from_slice(value),
            }
        }
        if changed { Some(out) } else { None }
    })();

    result.map_or(Cow::Borrowed(command), Cow::Owned)
}

/// OpenSSH hardcodes `rp.id = "ssh:"` and the user entity `openssh`/`openssh`
/// for every sk key. Synced passkey stores (e.g. iCloud Keychain) keep one
/// passkey per (rpId, userHandle), so a second `ssh-keygen` through the same
/// phone silently *replaces* the first passkey, orphaning the existing key
/// handle files. For this fixed RP only, rewrite the user entity with a fresh
/// random handle and a distinguishable label so each registration lands as a
/// new passkey. OpenSSH never reads the user handle back, and the user entity
/// is covered by neither clientDataHash nor attestation, so the rewrite is
/// transparent. Never touch real WebAuthn RPs: there the user handle is the
/// account binding. Returns a borrow of the input for other RPs, non-parseable
/// payloads, or a user entity without an "id".
pub fn dissociate_ssh_user(command: &[u8]) -> Cow<'_, [u8]> {
    let Some((&CMD_MAKE_CREDENTIAL, params)) = command.split_first() else {
        return Cow::Borrowed(command);
    };

    let result = (|| -> Option<Vec<u8>> {
        let mut c = cbor::Decoder::new(params);
        let pairs = c.map_header()?;

        let mut entries: Vec<(u64, std::ops::Range<usize>)> = Vec::new();
        let mut rp_is_ssh = false;
        for _ in 0..pairs {
            let key = c.uint()?;
            let start = c.pos();
            if key == MC_KEY_RP {
                let inner_pairs = c.map_header()?;
                for _ in 0..inner_pairs {
                    let k = c.text_str()?;
                    if k == "id" {
                        rp_is_ssh = c.text_str()? == "ssh:";
                    } else {
                        c.skip_value()?;
                    }
                }
            } else {
                c.skip_value()?;
            }
            entries.push((key, start..c.pos()));
        }
        if !rp_is_ssh {
            return None;
        }

        let mut handle = [0u8; 32];
        OsRng.fill_bytes(&mut handle);
        let label = format!("ssh:{}", hex::encode(&handle[..4]));

        let mut out = vec![CMD_MAKE_CREDENTIAL];
        cbor::map(&mut out, pairs);
        let mut changed = false;
        for (key, span) in entries {
            cbor::uint(&mut out, key);
            let value = &params[span.clone()];
            if key == MC_KEY_USER {
                let rewritten = rewrite_user_entity(value, &handle, &label);
                changed |= rewritten.is_some();
                out.extend_from_slice(rewritten.as_deref().unwrap_or(value));
            } else {
                out.extend_from_slice(value);
            }
        }
        // Without a user.id the registration would still replace the stored
        // passkey; fail safe and leave the request untouched.
        changed.then_some(out)
    })();

    result.map_or(Cow::Borrowed(command), Cow::Owned)
}

/// Rebuild a user entity map with "id" replaced by `handle` and "name" /
/// "displayName" replaced by `label`, preserving key order and every other
/// field byte-for-byte. Returns None when the map has no "id".
fn rewrite_user_entity(data: &[u8], handle: &[u8; 32], label: &str) -> Option<Vec<u8>> {
    let mut c = cbor::Decoder::new(data);
    let pairs = c.map_header()?;

    let mut entries: Vec<(&str, std::ops::Range<usize>)> = Vec::new();
    let mut has_id = false;
    for _ in 0..pairs {
        let k = c.text_str()?;
        has_id |= k == "id";
        let start = c.pos();
        c.skip_value()?;
        entries.push((k, start..c.pos()));
    }
    if !has_id {
        return None;
    }

    let mut out = Vec::new();
    cbor::map(&mut out, entries.len() as u64);
    for (k, span) in entries {
        cbor::text(&mut out, k);
        match k {
            "id" => cbor::bytes(&mut out, handle),
            "name" | "displayName" => cbor::text(&mut out, label),
            _ => out.extend_from_slice(&data[span]),
        }
    }
    Some(out)
}

/// Remove the advisory `transports` hint from every credential descriptor in a
/// getAssertion `allowList` (key 3) or makeCredential `excludeList` (key 5).
///
/// Firefox tags credentials it learned over USB-HID with
/// `transports: ["usb"]`. Forwarded untouched over caBLE, some phone
/// authenticators reject the credential as incompatible with the hybrid
/// transport ("no passkeys found"). The hint is advisory and covered by no
/// signature, so dropping it is safe. Descriptor order and every other field
/// are preserved byte-for-byte. Returns a borrow of the input if nothing
/// needed stripping or the payload doesn't parse.
pub fn strip_transport_hints(command: &[u8]) -> Cow<'_, [u8]> {
    let Some((&cmd, params)) = command.split_first() else {
        return Cow::Borrowed(command);
    };
    // CTAP2 parameter numbering: getAssertion.allowList = 3,
    // makeCredential.excludeList = 5 (4 is pubKeyCredParams).
    let list_key = match cmd {
        CMD_MAKE_CREDENTIAL => MC_KEY_EXCLUDE_LIST,
        CMD_GET_ASSERTION => GA_KEY_ALLOW_LIST,
        _ => return Cow::Borrowed(command),
    };

    let result = (|| -> Option<Vec<u8>> {
        let mut c = cbor::Decoder::new(params);
        let pairs = c.map_header()?;

        let mut out = vec![cmd];
        let mut entries: Vec<(u64, std::ops::Range<usize>)> = Vec::new();
        for _ in 0..pairs {
            let key = c.uint()?;
            let start = c.pos();
            c.skip_value()?;
            entries.push((key, start..c.pos()));
        }

        let mut changed = false;
        cbor::map(&mut out, pairs);
        for (key, span) in entries {
            cbor::uint(&mut out, key);
            let value = &params[span.clone()];
            if key == list_key
                && let Some((stripped, true)) = strip_transports_from_array(value)
            {
                changed = true;
                out.extend_from_slice(&stripped);
                continue;
            }
            out.extend_from_slice(value);
        }
        changed.then_some(out)
    })();

    match result {
        Some(out) => {
            tracing::info!("request carries transport hints, stripped them");
            Cow::Owned(out)
        }
        None => Cow::Borrowed(command),
    }
}

/// Drop a descriptor's `transports` entry while keeping the remaining pairs in
/// order. Returns `(rebuilt, removed)`; `None` when `data` is not a text-keyed
/// map or lacks an `id`, so callers can fail safe and keep the original.
fn strip_transports_from_descriptor(data: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut c = cbor::Decoder::new(data);
    let pairs = c.map_header()?;

    let mut kept: Vec<(std::ops::Range<usize>, std::ops::Range<usize>)> = Vec::new();
    let mut removed = false;
    let mut has_id = false;
    for _ in 0..pairs {
        let key_start = c.pos();
        let key = c.text_str()?;
        let key_end = c.pos();
        let val_start = c.pos();
        c.skip_value()?;
        let val_end = c.pos();
        if key == "transports" {
            removed = true;
        } else {
            has_id |= key == "id";
            kept.push((key_start..key_end, val_start..val_end));
        }
    }
    if !has_id {
        return None;
    }

    let mut out = Vec::new();
    cbor::map(&mut out, kept.len() as u64);
    for (k, v) in kept {
        out.extend_from_slice(&data[k]);
        out.extend_from_slice(&data[v]);
    }
    Some((out, removed))
}

/// Strip transport hints from every descriptor in an array. Returns
/// `(rebuilt, removed)`; `None` when `data` is not an array.
fn strip_transports_from_array(data: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut c = cbor::Decoder::new(data);
    let b = c.byte()?;
    if b >> 5 != cbor::MAJOR_ARRAY {
        return None;
    }
    let n = c.argument(b & cbor::ARG_MASK)?;

    let mut out = Vec::new();
    cbor::array(&mut out, n);
    let mut removed = false;
    for _ in 0..n {
        let start = c.pos();
        c.skip_value()?;
        let elem = &data[start..c.pos()];
        match strip_transports_from_descriptor(elem) {
            Some((stripped, true)) => {
                removed = true;
                out.extend_from_slice(&stripped);
            }
            _ => out.extend_from_slice(elem),
        }
    }
    Some((out, removed))
}

/// Canonical CBOR order for text map keys: shorter first, then bytewise.
fn canonical_key_order(a: &str, b: &str) -> std::cmp::Ordering {
    (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()))
}

/// Rewrite a getAssertion's `options` map (key 5) the way Chromium sends it:
/// drop `up: true` (the CTAP default) and emit the remaining keys in
/// canonical CBOR order.
///
/// Firefox encodes `{"uv": true, "up": true}`, out of canonical order. iOS
/// accepts that, but Android's hybrid authenticator parses strictly and
/// fails the whole request, showing "Something went wrong" on the phone.
/// `up: false` is kept, and every other parameter is preserved byte-for-byte.
/// Returns a borrow of the input if nothing needed changing or the payload
/// doesn't parse.
pub fn normalize_assertion_options(command: &[u8]) -> Cow<'_, [u8]> {
    let Some((&CMD_GET_ASSERTION, params)) = command.split_first() else {
        return Cow::Borrowed(command);
    };

    let result = (|| -> Option<Vec<u8>> {
        let mut c = cbor::Decoder::new(params);
        let pairs = c.map_header()?;
        let mut entries: Vec<(u64, std::ops::Range<usize>)> = Vec::new();
        for _ in 0..pairs {
            let key = c.uint()?;
            let start = c.pos();
            c.skip_value()?;
            entries.push((key, start..c.pos()));
        }
        if c.pos() != params.len() {
            return None;
        }

        let (_, span) = entries.iter().find(|(k, _)| *k == GA_KEY_OPTIONS)?;
        let opts = &params[span.clone()];
        let mut oc = cbor::Decoder::new(opts);
        let n = oc.map_header()?;
        let mut kept: Vec<(&str, std::ops::Range<usize>)> = Vec::new();
        let mut dropped_up = false;
        for _ in 0..n {
            let k = oc.text_str()?;
            let start = oc.pos();
            oc.skip_value()?;
            if k == "up" && opts[start..oc.pos()] == [cbor::TRUE] {
                dropped_up = true;
                continue;
            }
            kept.push((k, start..oc.pos()));
        }
        let in_order = kept
            .windows(2)
            .all(|w| canonical_key_order(w[0].0, w[1].0).is_lt());
        if !dropped_up && in_order {
            return None;
        }
        kept.sort_by(|a, b| canonical_key_order(a.0, b.0));

        let mut out = vec![CMD_GET_ASSERTION];
        cbor::map(&mut out, if kept.is_empty() { pairs - 1 } else { pairs });
        for (key, span) in &entries {
            if *key != GA_KEY_OPTIONS {
                cbor::uint(&mut out, *key);
                out.extend_from_slice(&params[span.clone()]);
            } else if !kept.is_empty() {
                cbor::uint(&mut out, *key);
                cbor::map(&mut out, kept.len() as u64);
                for (k, v) in &kept {
                    cbor::text(&mut out, k);
                    out.extend_from_slice(&opts[v.clone()]);
                }
            }
        }
        Some(out)
    })();

    match result {
        Some(out) => {
            tracing::info!("normalized getAssertion options for strict phone parsers");
            Cow::Owned(out)
        }
        None => Cow::Borrowed(command),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Firefox 158's interactive getAssertion, as captured from webauthn.io:
    /// {1: "webauthn.io", 2: h'..'x32, 3: [{"id": h'..'x16, "type": "public-key"}],
    ///  5: {"uv": true, "up": true}}
    const FIREFOX_GET_ASSERTION: &str = "02a4016b776562617574686e2e696f025820bebe124d3cfc465e744f4b2e936599c6f2493cb6c69e920b825abb3582d00c2f0381a262696450f7e8ace3d949a33b57e185494310fe7364747970656a7075626c69632d6b657905a2627576f5627570f5";

    #[test]
    fn normalize_assertion_options_firefox_request() {
        let cmd = hex::decode(FIREFOX_GET_ASSERTION).unwrap();
        let out = normalize_assertion_options(&cmd);
        // Same request, options reduced to {"uv": true} like Chromium sends.
        let mut want = cmd[..cmd.len() - "05a2627576f5627570f5".len() / 2].to_vec();
        want.extend_from_slice(&hex::decode("05a1627576f5").unwrap());
        assert_eq!(hex::encode(&out), hex::encode(&want));
        // idempotent
        assert!(matches!(normalize_assertion_options(&out), Cow::Borrowed(_)));
    }

    #[test]
    fn normalize_assertion_options_drops_lone_up_true() {
        // {1: "a", 2: h'00', 5: {"up": true}} -> {1: "a", 2: h'00'}
        let cmd = hex::decode("02a301616102410005a1627570f5").unwrap();
        let out = normalize_assertion_options(&cmd);
        assert_eq!(hex::encode(&out), "02a2016161024100");
    }

    #[test]
    fn normalize_assertion_options_keeps_up_false_and_sorts() {
        // {5: {"uv": true, "up": false}} -> {5: {"up": false, "uv": true}}
        let cmd = hex::decode("02a105a2627576f5627570f4").unwrap();
        let out = normalize_assertion_options(&cmd);
        assert_eq!(hex::encode(&out), "02a105a2627570f4627576f5");
    }

    #[test]
    fn normalize_assertion_options_noop() {
        // Already canonical, no up: true.
        let cmd = hex::decode("02a105a1627576f5").unwrap();
        assert!(matches!(normalize_assertion_options(&cmd), Cow::Borrowed(_)));
        // No options at all.
        let cmd = hex::decode("02a2016161024100").unwrap();
        assert!(matches!(normalize_assertion_options(&cmd), Cow::Borrowed(_)));
        // makeCredential is left alone.
        let cmd = hex::decode("01a105a2627576f5627570f5").unwrap();
        assert!(matches!(normalize_assertion_options(&cmd), Cow::Borrowed(_)));
    }

    #[test]
    fn getinfo_shape() {
        let r = getinfo_response(&[0u8; 16]);
        assert_eq!(r[0], 0x00);
        // contains "FIDO_2_0" and "hybrid"
        let s = String::from_utf8_lossy(&r);
        assert!(s.contains("FIDO_2_0"));
        assert!(s.contains("hybrid"));
        // credProtect is required for OpenSSH resident / verify-required keys.
        assert!(s.contains("credProtect"));
        // maxMsgSize must use the minimal two-byte encoding (canonical CBOR),
        // otherwise strict parsers (Chromium) reject the whole response.
        assert!(r.windows(3).any(|w| w == [0x19, 0x1d, 0xb9]));
        assert!(!r.windows(5).any(|w| w == [0x1a, 0x00, 0x00, 0x1d, 0xb9]));
        // Advertise the list limits so the browser does not preflight the
        // allowList one credential at a time (key 7 -> 64, key 8 -> 1024).
        assert!(r.windows(3).any(|w| w == [0x07, 0x18, 0x40]));
        assert!(r.windows(4).any(|w| w == [0x08, 0x19, 0x04, 0x00]));
    }

    #[test]
    fn extract_rp_id_getassertion() {
        // {1: "example.com", 2: h'aa..'}
        let mut cmd = vec![0x02, 0xa2, 0x01, 0x6b];
        cmd.extend_from_slice(b"example.com");
        cmd.extend_from_slice(&[0x02, 0x58, 0x20]);
        cmd.extend_from_slice(&[0xaa; 32]);
        assert_eq!(extract_rp_id(&cmd).as_deref(), Some("example.com"));
    }

    #[test]
    fn extract_rp_id_makecredential() {
        // {1: h'..32..', 2: {"id": "webauthn.io"}, 3: {...user...}}
        let mut cmd = vec![0x01, 0xa3, 0x01, 0x58, 0x20];
        cmd.extend_from_slice(&[0xbb; 32]); // clientDataHash
        // key 2: rp map {"id": "webauthn.io"}
        cmd.extend_from_slice(&[0x02, 0xa1, 0x62]);
        cmd.extend_from_slice(b"id");
        cmd.push(0x6b);
        cmd.extend_from_slice(b"webauthn.io");
        // key 3: user map {id: h'01', name: "u", displayName: "u"}
        cmd.extend_from_slice(&[0x03, 0xa3, 0x62]);
        cmd.extend_from_slice(b"id");
        cmd.extend_from_slice(&[0x41, 0x01]);
        cmd.push(0x64);
        cmd.extend_from_slice(b"name");
        cmd.push(0x61);
        cmd.extend_from_slice(b"u");
        cmd.push(0x6b);
        cmd.extend_from_slice(b"displayName");
        cmd.push(0x61);
        cmd.extend_from_slice(b"u");
        assert_eq!(extract_rp_id(&cmd).as_deref(), Some("webauthn.io"));
    }

    #[test]
    fn u2f_appid_detection() {
        assert!(is_u2f_appid(
            "https://api.x.com/1.1/onboarding/x_u2f_trusted_facets.json"
        ));
        assert!(is_u2f_appid("http://localhost/appid"));
        assert!(!is_u2f_appid("x.com"));
        assert!(!is_u2f_appid("ssh:"));
    }

    #[test]
    fn patch_real_firefox_payload() {
        let cmd = hex::decode("01a6015820cc1f4afda7a13ed02de520a7b2c8d5cce2b1e6d8dbe392f022a0cf88ee456fcb02a16269646b776562617574686e2e696f03a26269644d776562617574686e696f2d7172646e616d656271720483a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b657906a16b686d61632d736563726574f407a262726bf5627576f5").unwrap();
        let patched = patch_makecredential(&cmd);
        assert_ne!(patched, cmd);
        // rpId extraction still works on the patched request
        assert_eq!(extract_rp_id(&patched).as_deref(), Some("webauthn.io"));
        // injected fields are present
        let text = String::from_utf8_lossy(&patched);
        assert!(text.contains("displayName"));
        assert!(text.contains("name"));
        // user.displayName falls back to user.name ("qr")
        let key_pos = patched
            .windows(11)
            .position(|w| w == b"displayName")
            .unwrap();
        assert_eq!(patched[key_pos + 11], 0x62); // text(2)
        assert_eq!(&patched[key_pos + 12..key_pos + 14], b"qr");
    }

    #[test]
    fn patch_is_idempotent_and_untouched_when_complete() {
        let cmd = hex::decode("01a5015820cc1f4afda7a13ed02de520a7b2c8d5cce2b1e6d8dbe392f022a0cf88ee456fcb02a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f03a36269644d776562617574686e696f2d7172646e616d656271726b646973706c61794e616d656271720483a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b657907a162726bf5").unwrap();
        let patched = patch_makecredential(&cmd);
        // A complete request must be returned by borrow, not copied.
        assert!(matches!(&patched, Cow::Borrowed(_)));
        assert_eq!(patched, cmd);
    }

    /// `{"id": h'0102', "type": "public-key", "transports": ["usb"]}`
    const DESC_WITH_TRANSPORTS: &str =
        "a362696442010264747970656a7075626c69632d6b65796a7472616e73706f7274738163757362";

    /// The same descriptor without the transports hint.
    const DESC_NO_TRANSPORTS: &str = "a262696442010264747970656a7075626c69632d6b6579";

    fn get_assertion_with(descriptor_hex: &str) -> Vec<u8> {
        let mut cmd = hex::decode("02a2016b6578616d706c652e636f6d0381").unwrap();
        cmd.extend_from_slice(&hex::decode(descriptor_hex).unwrap());
        cmd
    }

    fn get_assertion_with_transport_hint() -> Vec<u8> {
        get_assertion_with(DESC_WITH_TRANSPORTS)
    }

    #[test]
    fn strip_transport_hints_get_assertion() {
        let cmd = get_assertion_with_transport_hint();
        let out = strip_transport_hints(&cmd);

        assert_ne!(out, cmd);
        assert!(!String::from_utf8_lossy(&out).contains("transports"));
        // the credential id (bstr 42 01 02) survives
        assert!(hex::encode(&out).contains("420102"));
        // the rest of the request is untouched
        assert_eq!(extract_rp_id(&out).as_deref(), Some("example.com"));
        // idempotent
        assert_eq!(strip_transport_hints(&out), out);
    }

    #[test]
    fn strip_transport_hints_make_credential_exclude_list() {
        // {1: h'aa'x32, 2: {"id": "example.com"}, 5: [descriptor-with-transports]}
        let mut cmd = hex::decode("01a3015820").unwrap();
        cmd.extend_from_slice(&[0xaa; 32]);
        cmd.extend_from_slice(&hex::decode("02a16269646b6578616d706c652e636f6d0581").unwrap());
        cmd.extend_from_slice(&hex::decode(DESC_WITH_TRANSPORTS).unwrap());

        let out = strip_transport_hints(&cmd);
        assert_ne!(out, cmd);
        assert!(!String::from_utf8_lossy(&out).contains("transports"));
        assert!(hex::encode(&out).contains("420102"));
        assert_eq!(strip_transport_hints(&out), out);
    }

    #[test]
    fn strip_transport_hints_noop_without_hint() {
        // Interactive getAssertion with an allowList but no transports.
        let cmd = get_assertion_with(DESC_NO_TRANSPORTS);
        let out = strip_transport_hints(&cmd);
        // Nothing to strip: the request must be returned by borrow, not copied.
        assert!(matches!(&out, Cow::Borrowed(_)));
        assert_eq!(out, cmd);
        // Unrelated command byte is left alone.
        let out = strip_transport_hints(&[0x06, 0x00]);
        assert!(matches!(&out, Cow::Borrowed(_)));
        assert_eq!(out, vec![0x06, 0x00]);
    }

    /// Parse the user entity (key 3) of a makeCredential command into
    /// (id, name, displayName) for assertions on the rewritten requests.
    fn parse_user_entity(cmd: &[u8]) -> (Vec<u8>, String, String) {
        let mut c = cbor::Decoder::new(&cmd[1..]);
        let pairs = c.map_header().unwrap();
        for _ in 0..pairs {
            let key = c.uint().unwrap();
            if key != MC_KEY_USER {
                c.skip_value().unwrap();
                continue;
            }
            let inner = c.map_header().unwrap();
            let (mut id, mut name, mut display) = (Vec::new(), String::new(), String::new());
            for _ in 0..inner {
                match c.text().unwrap().as_str() {
                    "id" => id = c.bytes().unwrap().to_vec(),
                    "name" => name = c.text().unwrap(),
                    "displayName" => display = c.text().unwrap(),
                    _ => c.skip_value().unwrap(),
                }
            }
            return (id, name, display);
        }
        panic!("no user entity");
    }

    /// An OpenSSH-style makeCredential: rp {"id": "ssh:"}, user
    /// {id, name, displayName} all "openssh".
    fn openssh_make_credential() -> Vec<u8> {
        let mut cmd = vec![CMD_MAKE_CREDENTIAL];
        cbor::map(&mut cmd, 3);
        cbor::uint(&mut cmd, 1);
        cbor::bytes(&mut cmd, &[0xcc; 32]);
        cbor::uint(&mut cmd, MC_KEY_RP);
        cbor::map(&mut cmd, 1);
        cbor::text(&mut cmd, "id");
        cbor::text(&mut cmd, "ssh:");
        cbor::uint(&mut cmd, MC_KEY_USER);
        cbor::map(&mut cmd, 3);
        cbor::text(&mut cmd, "id");
        cbor::bytes(&mut cmd, b"openssh");
        cbor::text(&mut cmd, "name");
        cbor::text(&mut cmd, "openssh");
        cbor::text(&mut cmd, "displayName");
        cbor::text(&mut cmd, "openssh");
        cmd
    }

    #[test]
    fn dissociate_ssh_user_rewrites_handle_and_label() {
        let cmd = openssh_make_credential();
        let out = dissociate_ssh_user(&cmd);
        assert_ne!(out, cmd);
        assert_eq!(extract_rp_id(&out).as_deref(), Some("ssh:"));
        let (id, name, display) = parse_user_entity(&out);
        assert_eq!(id.len(), 32);
        let label = format!("ssh:{}", hex::encode(&id[..4]));
        assert_eq!(name, label);
        assert_eq!(display, label);
        // A second registration gets an independent handle.
        let out2 = dissociate_ssh_user(&cmd);
        assert_ne!(parse_user_entity(&out2).0, id);
    }

    #[test]
    fn dissociate_ssh_user_leaves_other_rps_alone() {
        // Real WebAuthn RPs: the user handle is the account binding.
        let mut cmd = vec![CMD_MAKE_CREDENTIAL];
        cbor::map(&mut cmd, 3);
        cbor::uint(&mut cmd, 1);
        cbor::bytes(&mut cmd, &[0xcc; 32]);
        cbor::uint(&mut cmd, MC_KEY_RP);
        cbor::map(&mut cmd, 1);
        cbor::text(&mut cmd, "id");
        cbor::text(&mut cmd, "example.com");
        cbor::uint(&mut cmd, MC_KEY_USER);
        cbor::map(&mut cmd, 3);
        cbor::text(&mut cmd, "id");
        cbor::bytes(&mut cmd, b"user-42");
        cbor::text(&mut cmd, "name");
        cbor::text(&mut cmd, "user@example.com");
        cbor::text(&mut cmd, "displayName");
        cbor::text(&mut cmd, "User 42");
        let out = dissociate_ssh_user(&cmd);
        // Other RPs are returned by borrow, not copied.
        assert!(matches!(&out, Cow::Borrowed(_)));
        assert_eq!(out, cmd);
        // getAssertion is never touched
        let ga = hex::decode("02a201647373683a025820").unwrap();
        let mut ga_full = ga.clone();
        ga_full.extend_from_slice(&[0xaa; 32]);
        let out = dissociate_ssh_user(&ga_full);
        assert!(matches!(&out, Cow::Borrowed(_)));
        assert_eq!(out, ga_full);
    }

    #[test]
    fn dissociate_ssh_user_requires_user_id() {
        let mut cmd = vec![CMD_MAKE_CREDENTIAL];
        cbor::map(&mut cmd, 3);
        cbor::uint(&mut cmd, 1);
        cbor::bytes(&mut cmd, &[0xcc; 32]);
        cbor::uint(&mut cmd, MC_KEY_RP);
        cbor::map(&mut cmd, 1);
        cbor::text(&mut cmd, "id");
        cbor::text(&mut cmd, "ssh:");
        cbor::uint(&mut cmd, MC_KEY_USER);
        cbor::map(&mut cmd, 1);
        cbor::text(&mut cmd, "name");
        cbor::text(&mut cmd, "openssh");
        let out = dissociate_ssh_user(&cmd);
        // No user id: fail safe by returning the request untouched, by borrow.
        assert!(matches!(&out, Cow::Borrowed(_)));
        assert_eq!(out, cmd);
    }

    #[test]
    fn blink_probe_detection() {
        // Captured from Firefox's dummy_make_credentials_cmd.
        let probe = hex::decode("01a6015820d0cee6fc7dbf599a919db8fb951311269f0eb781f7841c6cc0544ad9da34154b02a26269646d6d616b652e6d652e626c696e6b646e616d656003a36269644100646e616d656d6d616b652e6d652e626c696e6b6b646973706c61794e616d656d6d616b652e6d652e626c696e6b0481a263616c672664747970656a7075626c69632d6b657908400901").unwrap();
        assert!(is_blink_probe(&probe));
        assert!(!is_blink_probe(&[0x02, 0xa1, 0x01, 0x61, 0x61]));
    }

    #[test]
    fn silent_probe_detection() {
        // Real probe captured from Firefox: options {up: false}
        let probe = hex::decode("02a4016b776562617574686e2e696f025820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550381a26269645456ebb4bab2368cd5c71e173c5213c85203e2511964747970656a7075626c69632d6b657905a1627570f4").unwrap();
        assert!(answer_silent_probe(&probe).is_some());
        // Real interactive request: options {uv: true, up: true}
        let interactive = hex::decode("02a4016b776562617574686e2e696f025820341a4e06e8dfd6cd4244803bd2079eb48ec2f1b41f832f2e18de51bd91248e8e0381a26269645456ebb4bab2368cd5c71e173c5213c85203e2511964747970656a7075626c69632d6b657905a2627576f5627570f5").unwrap();
        assert!(answer_silent_probe(&interactive).is_none());
        // No options at all
        let plain = hex::decode("02a2016b6578616d706c652e636f6d025820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(answer_silent_probe(&plain).is_none());
        // Captured from `ssh-keygen -t ecdsa-sk -O resident`: a discoverable
        // getAssertion for rpId "ssh:" with options {up:false, uv:true} and
        // no allowList. It must be relayed, not answered locally.
        let ssh_resident = hex::decode(
            "02a301647373683a02582066687aadf862bd776c8fc18b8e9f8e20\
             089714856ee233b3902a591d0d5f292505a2627570f4627576f5",
        )
        .unwrap();
        assert!(answer_silent_probe(&ssh_resident).is_none());
    }

    #[test]
    fn silent_probe_answer_echoes_credential() {
        let probe = hex::decode("02a4016b776562617574686e2e696f025820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550381a26269645456ebb4bab2368cd5c71e173c5213c85203e2511964747970656a7075626c69632d6b657905a1627570f4").unwrap();
        let (rp, resp, rest) = answer_silent_probe(&probe).unwrap();
        assert_eq!(rp, "webauthn.io");
        assert!(rest.is_empty());
        assert_eq!(resp[0], 0x00);
        // echoes the credential id 56ebb4bab2368cd5c71e173c5213c85203e25119
        let cred = hex::decode("56ebb4bab2368cd5c71e173c5213c85203e25119").unwrap();
        assert!(resp.windows(cred.len()).any(|w| w == cred.as_slice()));
        assert!(resp.windows(10).any(|w| w == b"public-key"));
        // single credential: no numberOfCredentials field
        assert!(!resp.ends_with(&[0x05, 0x01]));
        // getAssertion without allowList cannot be faked
        let plain = hex::decode("02a2016b6578616d706c652e636f6d025820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(answer_silent_probe(&plain).is_none());
    }

    #[test]
    fn silent_probe_answer_reports_all_credentials() {
        // {1: "example.com", 2: h'aa'x32, 3: [{"id": h'0102'}, {"id": h'0304'}]}
        let mut two = hex::decode("02a4016b6578616d706c652e636f6d025820").unwrap();
        two.extend_from_slice(&[0xaa; 32]);
        two.extend_from_slice(&hex::decode("0382").unwrap());
        two.extend_from_slice(
            &hex::decode("a262696442010264747970656a7075626c69632d6b6579").unwrap(),
        );
        two.extend_from_slice(
            &hex::decode("a262696442030464747970656a7075626c69632d6b6579").unwrap(),
        );
        two.extend_from_slice(&hex::decode("05a1627570f4").unwrap()); // options {up: false}

        let (rp, resp, rest) = answer_silent_probe(&two).unwrap();
        assert_eq!(rp, "example.com");
        assert_eq!(resp[0], 0x00);
        // numberOfCredentials = 2 (key 5) so the client asks for the rest
        assert_eq!(&resp[resp.len() - 2..], &[0x05, 0x02]);
        assert_eq!(rest, vec![vec![0x03, 0x04]]);

        // the follow-up echoes the second credential without a count field
        let next = fake_next_assertion("example.com", &[0x03, 0x04]);
        assert_eq!(next[0], 0x00);
        assert!(next.windows(2).any(|w| w == [0x03, 0x04]));
        assert!(!next.windows(2).any(|w| w == [0x05, 0x01]));
    }
}

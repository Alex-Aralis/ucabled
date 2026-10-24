// SPDX-License-Identifier: GPL-3.0-or-later

//! Linked phones: caBLE "state-assisted" transactions (PXP §5.3.2, see
//! `docs/linking.md`).
//!
//! When the QR code offers linking, the phone may send *linking information*
//! during or right after a QR transaction. It holds a contact ID, which the
//! tunnel server uses to wake the phone (an FCM token on Android), a link ID
//! and secret for later handshakes, and the phone's long-term public key. With
//! it, later transactions reach the phone without a QR code: the phone gets a
//! notification, and its BLE advert still proves that it is nearby.
//!
//! The linking information arrives through the tunnel server, which is not
//! trusted, so it carries a signature: HMAC-SHA256 over the QR handshake's
//! hash, keyed with ECDH(our identity key, the phone's public key). Only the
//! phone that completed the handshake can produce it.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::cbor;

/// File in the daemon's state directory that holds the linked phones.
pub const LINKS_FILE_NAME: &str = "links.cbor";

/// Linking map keys (Chromium `Pairing::Parse`).
const LINK_KEY_CONTACT_ID: u64 = 1;
const LINK_KEY_ID: u64 = 2;
const LINK_KEY_SECRET: u64 = 3;
const LINK_KEY_PUBLIC_KEY: u64 = 4;
const LINK_KEY_NAME: u64 = 5;
const LINK_KEY_SIGNATURE: u64 = 6;

/// Post-handshake message key carrying the linking map; update messages
/// carry it under key 1.
pub const POST_HANDSHAKE_KEY_LINKING: u64 = 2;
pub const UPDATE_KEY_LINKING: u64 = 1;

/// Storage-only keys for the extra fields we keep per link.
const STORE_KEY_DOMAIN: u64 = 7;
const STORE_KEY_CREATED: u64 = 8;

const P256_X962_LENGTH: usize = 65;
const SIGNATURE_LENGTH: usize = 32;
/// Bounds for the opaque fields. An FCM token is a few hundred bytes; the link
/// ID is 8 bytes and the secret 32 bytes on Android. The phone is not trusted
/// to make us store arbitrarily large blobs.
const MAX_CONTACT_ID_LENGTH: usize = 2048;
const MAX_LINK_ID_LENGTH: usize = 64;
const MIN_SECRET_LENGTH: usize = 16;
const MAX_SECRET_LENGTH: usize = 64;
/// Phone names are shown in the UI and logs; keep them short and printable.
const MAX_NAME_CHARS: usize = 64;
/// How many phones to remember. The oldest link is dropped beyond this.
const MAX_LINKS: usize = 8;

/// Serialises every read-modify-write of the links file within the daemon:
/// linking updates arrive on background tasks.
static STORE_LOCK: Mutex<()> = Mutex::new(());

/// One linked phone.
#[derive(Clone, PartialEq, Eq)]
pub struct Link {
    /// Opaque handle the tunnel server uses to contact the phone.
    pub contact_id: Vec<u8>,
    /// Identifies this computer to the phone in later contacts.
    pub link_id: Vec<u8>,
    /// Root secret for later EID keys and handshake PSKs.
    pub secret: Vec<u8>,
    /// The phone's long-term P-256 public key (X9.62 uncompressed).
    pub peer_public_key: [u8; P256_X962_LENGTH],
    /// Name the phone gave itself, e.g. "Pixel 9".
    pub name: String,
    /// Tunnel server domain ID of the transaction that created the link.
    pub tunnel_domain: u16,
    /// Unix time the link was stored.
    pub created: u64,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret or the contact ID.
        f.debug_struct("Link")
            .field("name", &self.name)
            .field("tunnel_domain", &self.tunnel_domain)
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

/// Parse and verify linking information sent by a phone.
///
/// `data` must start at the linking map. `domain` is the tunnel server domain
/// of the QR transaction, `identity` our identity key (its public key was in
/// the QR code), and `handshake_hash` that transaction's Noise handshake hash.
pub fn parse_linking(
    data: &[u8],
    domain: u16,
    identity: &SecretKey,
    handshake_hash: &[u8; 32],
) -> Result<Link> {
    let mut c = cbor::Decoder::new(data);
    let pairs = c
        .map_header()
        .ok_or_else(|| anyhow!("linking info is not a map"))?;

    let mut contact_id = None;
    let mut link_id = None;
    let mut secret = None;
    let mut public_key = None;
    let mut name = None;
    let mut signature = None;
    for _ in 0..pairs {
        let key = c.uint().ok_or_else(|| anyhow!("bad linking map key"))?;
        match key {
            LINK_KEY_CONTACT_ID => contact_id = c.bytes().map(<[u8]>::to_vec),
            LINK_KEY_ID => link_id = c.bytes().map(<[u8]>::to_vec),
            LINK_KEY_SECRET => secret = c.bytes().map(<[u8]>::to_vec),
            LINK_KEY_PUBLIC_KEY => public_key = c.bytes().map(<[u8]>::to_vec),
            LINK_KEY_NAME => name = c.text(),
            LINK_KEY_SIGNATURE => signature = c.bytes().map(<[u8]>::to_vec),
            _ => c
                .skip_value()
                .ok_or_else(|| anyhow!("bad linking map value"))?,
        }
    }

    let contact_id = contact_id.ok_or_else(|| anyhow!("linking info lacks a contact ID"))?;
    let link_id = link_id.ok_or_else(|| anyhow!("linking info lacks a link ID"))?;
    let mut secret = secret.ok_or_else(|| anyhow!("linking info lacks a secret"))?;
    let public_key = public_key.ok_or_else(|| anyhow!("linking info lacks a public key"))?;
    let name = name.ok_or_else(|| anyhow!("linking info lacks a name"))?;
    let signature = signature.ok_or_else(|| anyhow!("linking info lacks a signature"))?;

    let checked = (|| {
        if contact_id.is_empty() || contact_id.len() > MAX_CONTACT_ID_LENGTH {
            bail!("contact ID has a bad length ({})", contact_id.len());
        }
        if link_id.is_empty() || link_id.len() > MAX_LINK_ID_LENGTH {
            bail!("link ID has a bad length ({})", link_id.len());
        }
        if !(MIN_SECRET_LENGTH..=MAX_SECRET_LENGTH).contains(&secret.len()) {
            bail!("link secret has a bad length ({})", secret.len());
        }
        let peer_public_key: [u8; P256_X962_LENGTH] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("phone public key has a bad length ({})", public_key.len()))?;
        PublicKey::from_sec1_bytes(&peer_public_key)
            .map_err(|_| anyhow!("phone public key is not a P-256 point"))?;
        if signature.len() != SIGNATURE_LENGTH {
            bail!("linking signature has a bad length ({})", signature.len());
        }
        verify_signature(identity, &peer_public_key, handshake_hash, &signature)?;
        Ok(peer_public_key)
    })();
    let peer_public_key = match checked {
        Ok(key) => key,
        Err(e) => {
            secret.zeroize();
            return Err(e);
        }
    };

    Ok(Link {
        contact_id,
        link_id,
        secret,
        peer_public_key,
        name: sanitize_name(&name),
        tunnel_domain: domain,
        created: now(),
    })
}

/// The pairing signature: HMAC-SHA256(ECDH x-coordinate, handshake hash),
/// compared in constant time (Chromium `VerifyPairingSignature`).
fn verify_signature(
    identity: &SecretKey,
    peer_public_key: &[u8; P256_X962_LENGTH],
    handshake_hash: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let mut shared = crate::handshake::ecdh(identity, peer_public_key)
        .ok_or_else(|| anyhow!("ECDH with the phone public key failed"))?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&shared).expect("HMAC takes any key");
    shared.zeroize();
    mac.update(handshake_hash);
    mac.verify_slice(signature)
        .map_err(|_| anyhow!("linking signature does not verify"))
}

/// Keep phone names printable and short: they come from the phone and end up
/// in the UI and the journal.
fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "phone".to_string()
    } else {
        trimmed.to_string()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Find the linking map in a decrypted post-handshake message (key 2) or
/// update message (key 1) and return its bytes. `None` when the message has
/// no linking information or does not parse as a map.
pub fn find_linking_map(message: &[u8], key: u64) -> Option<&[u8]> {
    let mut c = cbor::Decoder::new(message);
    let pairs = c.map_header()?;
    for _ in 0..pairs {
        let k = c.uint()?;
        let start = c.pos();
        c.skip_value()?;
        if k == key {
            return Some(&message[start..c.pos()]);
        }
    }
    None
}

/// Load the linked phones from `dir`. A missing file means no links; entries
/// that fail to parse are skipped with a warning.
pub fn load(dir: &Path) -> Vec<Link> {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    load_unlocked(dir)
}

fn load_unlocked(dir: &Path) -> Vec<Link> {
    let path = dir.join(LINKS_FILE_NAME);
    let mut bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!("cannot read {}: {e}", path.display());
            return Vec::new();
        }
    };
    let links = decode_links(&bytes).unwrap_or_else(|| {
        tracing::warn!("{} is corrupt; ignoring it", path.display());
        Vec::new()
    });
    bytes.zeroize();
    links
}

/// Store `link`, replacing any earlier link to the same phone (same public
/// key) and dropping the oldest links beyond [`MAX_LINKS`].
pub fn add(dir: &Path, link: Link) -> Result<()> {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut links = load_unlocked(dir);
    links.retain(|l| l.peer_public_key != link.peer_public_key);
    links.push(link);
    links.sort_by_key(|l| l.created);
    if links.len() > MAX_LINKS {
        let excess = links.len() - MAX_LINKS;
        links.drain(..excess);
    }
    save_unlocked(dir, &links)
}

/// Forget the phone with `peer_public_key`, e.g. after the tunnel server
/// reported its contact ID as gone (HTTP 410).
pub fn remove(dir: &Path, peer_public_key: &[u8; P256_X962_LENGTH]) -> Result<()> {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut links = load_unlocked(dir);
    let before = links.len();
    links.retain(|l| &l.peer_public_key != peer_public_key);
    if links.len() == before {
        return Ok(());
    }
    save_unlocked(dir, &links)
}

fn save_unlocked(dir: &Path, links: &[Link]) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(LINKS_FILE_NAME);
    let mut bytes = encode_links(links);
    let written = crate::identity::write_private(&path, &bytes)
        .with_context(|| format!("writing {}", path.display()));
    bytes.zeroize();
    written
}

/// Storage format: a CBOR array of maps with the linking keys plus the domain
/// and creation time.
fn encode_links(links: &[Link]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::array(&mut out, links.len() as u64);
    for l in links {
        cbor::map(&mut out, 7);
        cbor::uint(&mut out, LINK_KEY_CONTACT_ID);
        cbor::bytes(&mut out, &l.contact_id);
        cbor::uint(&mut out, LINK_KEY_ID);
        cbor::bytes(&mut out, &l.link_id);
        cbor::uint(&mut out, LINK_KEY_SECRET);
        cbor::bytes(&mut out, &l.secret);
        cbor::uint(&mut out, LINK_KEY_PUBLIC_KEY);
        cbor::bytes(&mut out, &l.peer_public_key);
        cbor::uint(&mut out, LINK_KEY_NAME);
        cbor::text(&mut out, &l.name);
        cbor::uint(&mut out, STORE_KEY_DOMAIN);
        cbor::uint(&mut out, l.tunnel_domain as u64);
        cbor::uint(&mut out, STORE_KEY_CREATED);
        cbor::uint(&mut out, l.created);
    }
    out
}

fn decode_links(data: &[u8]) -> Option<Vec<Link>> {
    let mut c = cbor::Decoder::new(data);
    let b = c.byte()?;
    if b >> 5 != cbor::MAJOR_ARRAY {
        return None;
    }
    let n = c.argument(b & cbor::ARG_MASK)?;
    let mut links = Vec::new();
    for _ in 0..n {
        let start = c.pos();
        c.skip_value()?;
        match decode_link(&data[start..c.pos()]) {
            Some(link) => links.push(link),
            None => tracing::warn!("skipping a malformed stored link"),
        }
    }
    Some(links)
}

fn decode_link(data: &[u8]) -> Option<Link> {
    let mut c = cbor::Decoder::new(data);
    let pairs = c.map_header()?;
    let mut contact_id = None;
    let mut link_id = None;
    let mut secret = None;
    let mut public_key = None;
    let mut name = None;
    let mut domain = None;
    let mut created = None;
    for _ in 0..pairs {
        match c.uint()? {
            LINK_KEY_CONTACT_ID => contact_id = Some(c.bytes()?.to_vec()),
            LINK_KEY_ID => link_id = Some(c.bytes()?.to_vec()),
            LINK_KEY_SECRET => secret = Some(c.bytes()?.to_vec()),
            LINK_KEY_PUBLIC_KEY => public_key = Some(c.bytes()?.to_vec()),
            LINK_KEY_NAME => name = Some(c.text()?),
            STORE_KEY_DOMAIN => domain = Some(u16::try_from(c.uint()?).ok()?),
            STORE_KEY_CREATED => created = Some(c.uint()?),
            _ => c.skip_value()?,
        }
    }
    Some(Link {
        contact_id: contact_id?,
        link_id: link_id?,
        secret: secret?,
        peer_public_key: public_key?.as_slice().try_into().ok()?,
        name: name?,
        tunnel_domain: domain?,
        created: created?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    /// Build the linking map a phone would send, signed for `identity` and
    /// `handshake_hash`.
    pub(crate) fn phone_linking_map(
        phone: &SecretKey,
        identity: &SecretKey,
        handshake_hash: &[u8; 32],
        name: &str,
    ) -> Vec<u8> {
        let phone_public = phone.public_key().to_encoded_point(false);
        let identity_public = identity.public_key().to_encoded_point(false);
        let shared = crate::handshake::ecdh(phone, identity_public.as_bytes()).unwrap();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&shared).unwrap();
        mac.update(handshake_hash);
        let signature = mac.finalize().into_bytes();

        let mut out = Vec::new();
        cbor::map(&mut out, 7);
        cbor::uint(&mut out, LINK_KEY_CONTACT_ID);
        cbor::bytes(&mut out, b"fcm-token-for-tests");
        cbor::uint(&mut out, LINK_KEY_ID);
        cbor::bytes(&mut out, &[7u8; 8]);
        cbor::uint(&mut out, LINK_KEY_SECRET);
        cbor::bytes(&mut out, &[9u8; 32]);
        cbor::uint(&mut out, LINK_KEY_PUBLIC_KEY);
        cbor::bytes(&mut out, phone_public.as_bytes());
        cbor::uint(&mut out, LINK_KEY_NAME);
        cbor::text(&mut out, name);
        cbor::uint(&mut out, LINK_KEY_SIGNATURE);
        cbor::bytes(&mut out, &signature);
        // Play Services' tag (key 999) must be tolerated.
        cbor::uint(&mut out, 999);
        out.push(cbor::TRUE);
        out
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ucabled-links-{tag}-{}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn accepts_correctly_signed_linking_info() {
        let identity = SecretKey::random(&mut OsRng);
        let phone = SecretKey::random(&mut OsRng);
        let hash = [5u8; 32];
        let map = phone_linking_map(&phone, &identity, &hash, "Pixel\u{7} 9");
        let link = parse_linking(&map, 0, &identity, &hash).unwrap();
        assert_eq!(link.contact_id, b"fcm-token-for-tests");
        assert_eq!(link.link_id, [7u8; 8]);
        assert_eq!(link.secret, [9u8; 32]);
        assert_eq!(
            &link.peer_public_key[..],
            phone.public_key().to_encoded_point(false).as_bytes()
        );
        // Control characters are stripped from the name.
        assert_eq!(link.name, "Pixel 9");
        assert_eq!(link.tunnel_domain, 0);
    }

    #[test]
    fn rejects_a_signature_for_another_handshake_or_identity() {
        let identity = SecretKey::random(&mut OsRng);
        let phone = SecretKey::random(&mut OsRng);
        let map = phone_linking_map(&phone, &identity, &[5u8; 32], "Pixel");
        // A different handshake (e.g. replayed linking info).
        assert!(parse_linking(&map, 0, &identity, &[6u8; 32]).is_err());
        // Signed for a different computer.
        let other = SecretKey::random(&mut OsRng);
        assert!(parse_linking(&map, 0, &other, &[5u8; 32]).is_err());
    }

    #[test]
    fn rejects_incomplete_linking_info() {
        let identity = SecretKey::random(&mut OsRng);
        let mut map = Vec::new();
        cbor::map(&mut map, 1);
        cbor::uint(&mut map, LINK_KEY_CONTACT_ID);
        cbor::bytes(&mut map, b"x");
        assert!(parse_linking(&map, 0, &identity, &[0u8; 32]).is_err());
        assert!(parse_linking(&[0x80], 0, &identity, &[0u8; 32]).is_err());
    }

    #[test]
    fn finds_the_linking_map_in_a_message() {
        let identity = SecretKey::random(&mut OsRng);
        let phone = SecretKey::random(&mut OsRng);
        let hash = [1u8; 32];
        let linking = phone_linking_map(&phone, &identity, &hash, "Pixel");
        // Post-handshake message: {1: getInfo bytes, 2: linking, 3: features}
        let mut msg = Vec::new();
        cbor::map(&mut msg, 3);
        cbor::uint(&mut msg, 1);
        cbor::bytes(&mut msg, &[0xa0]);
        cbor::uint(&mut msg, 2);
        msg.extend_from_slice(&linking);
        cbor::uint(&mut msg, 3);
        cbor::array(&mut msg, 1);
        cbor::text(&mut msg, "ctap");
        let found = find_linking_map(&msg, POST_HANDSHAKE_KEY_LINKING).unwrap();
        assert_eq!(found, &linking[..]);
        assert!(find_linking_map(&msg, 9).is_none());
        assert!(find_linking_map(&[0xff], 2).is_none());
    }

    #[test]
    fn store_round_trip_replaces_the_same_phone() {
        let dir = temp_dir("store");
        let identity = SecretKey::random(&mut OsRng);
        let phone = SecretKey::random(&mut OsRng);
        let hash = [3u8; 32];
        assert!(load(&dir).is_empty());

        let first = parse_linking(
            &phone_linking_map(&phone, &identity, &hash, "Old name"),
            0,
            &identity,
            &hash,
        )
        .unwrap();
        add(&dir, first).unwrap();
        let second = parse_linking(
            &phone_linking_map(&phone, &identity, &hash, "New name"),
            0,
            &identity,
            &hash,
        )
        .unwrap();
        add(&dir, second.clone()).unwrap();

        let links = load(&dir);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0], second);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(LINKS_FILE_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        remove(&dir, &second.peer_public_key).unwrap();
        assert!(load(&dir).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keeps_at_most_max_links() {
        let dir = temp_dir("cap");
        let identity = SecretKey::random(&mut OsRng);
        let hash = [4u8; 32];
        for i in 0..MAX_LINKS + 2 {
            let phone = SecretKey::random(&mut OsRng);
            let mut link = parse_linking(
                &phone_linking_map(&phone, &identity, &hash, &format!("phone {i}")),
                0,
                &identity,
                &hash,
            )
            .unwrap();
            link.created = i as u64;
            add(&dir, link).unwrap();
        }
        let links = load(&dir);
        assert_eq!(links.len(), MAX_LINKS);
        assert_eq!(links[0].name, "phone 2");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_corrupt_file_reads_as_no_links() {
        let dir = temp_dir("corrupt");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(LINKS_FILE_NAME), b"\xff\xff").unwrap();
        assert!(load(&dir).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}

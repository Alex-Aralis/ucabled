// SPDX-License-Identifier: GPL-3.0-or-later

//! Persistent desktop identity key for caBLE transactions.
//!
//! Chromium keeps a long-term identity key per device; ucabled originally
//! generated a fresh random key for every QR transaction. Using a persistent
//! identity aligns with Chromium and is a prerequisite for caBLE linking
//! (see `docs/linking.md`): the phone's linking signature is verified with
//! `ECDH(identity, phone public key)`, and a linked phone may later recognise
//! the desktop by this key.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use p256::SecretKey;
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub const IDENTITY_FILE_NAME: &str = "identity.key";

/// Fallback state directory when systemd's `$STATE_DIRECTORY` is unset
/// (dist installs, manual runs).
pub const DEFAULT_STATE_DIR: &str = "/var/lib/ucabled";

/// Directory holding the identity key: `$STATE_DIRECTORY` when the daemon
/// runs under systemd with `StateDirectory=ucabled`, otherwise the dist
/// default.
pub fn state_dir() -> PathBuf {
    match std::env::var_os("STATE_DIRECTORY") {
        // systemd may pass a colon-separated list; we declare exactly one.
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(DEFAULT_STATE_DIR),
    }
}

/// Load the persistent identity key from `dir`, creating and storing a fresh
/// random one when none exists. A corrupt or unreadable existing file is an
/// error, not a silent regeneration: losing the key is visible, accidentally
/// replacing it must not be.
pub fn load_or_create(dir: &Path) -> Result<SecretKey> {
    let path = dir.join(IDENTITY_FILE_NAME);
    match fs::read(&path) {
        Ok(mut bytes) => {
            warn_if_group_or_world_readable(&path);
            // Do not leave the key in a heap buffer; wipe it once parsed.
            let key = SecretKey::from_slice(&bytes)
                .with_context(|| format!("invalid identity key in {}", path.display()));
            bytes.zeroize();
            key
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = SecretKey::random(&mut OsRng);
            fs::create_dir_all(dir)
                .with_context(|| format!("creating state directory {}", dir.display()))?;
            let mut bytes = key.to_bytes();
            let written = write_private(&path, &bytes)
                .with_context(|| format!("writing identity key to {}", path.display()));
            bytes.zeroize();
            written?;
            tracing::info!(path = %path.display(), "generated a new persistent identity key");
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("reading identity key from {}", path.display())),
    }
}

/// Write the key atomically (rename into place) with owner-only permissions;
/// the daemon's UMask is 0077, but do not rely on it.
///
/// The temporary file gets a random name so a leftover from a crashed write
/// cannot wedge every later start with `AlreadyExists`; `create_new` keeps the
/// `O_EXCL` guarantee against a squatting file or symlink.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut last = None;
    for _ in 0..16 {
        let tmp = path.with_extension(format!("tmp.{:016x}", rand::random::<u64>()));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };
        let write = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        let result = write.and_then(|()| fs::rename(&tmp, path));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        return result;
    }
    Err(last.unwrap_or_else(|| io::Error::other("no temporary name")))
}

/// A pre-existing key file with group/other bits set was not created by us
/// (e.g. restored from a backup) and may be readable by other users. Warn
/// instead of silently rewriting permissions we did not set — the same
/// "warn, don't fix" philosophy as `uhid_perm`.
#[cfg(unix)]
fn warn_if_group_or_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format_args!("{mode:04o}"),
                    "identity key is group/world-readable; run: chmod 600 {}",
                    path.display()
                );
            }
        }
        Err(e) => tracing::warn!("cannot stat {}: {e}", path.display()),
    }
}

#[cfg(not(unix))]
fn warn_if_group_or_world_readable(_path: &Path) {}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_then_reloads_the_same_key() {
        let dir = std::env::temp_dir().join(format!("ucabled-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let first = load_or_create(&dir).unwrap();
        let second = load_or_create(&dir).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(IDENTITY_FILE_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ignores_a_stale_temporary_file_from_a_crashed_write() {
        let dir =
            std::env::temp_dir().join(format!("ucabled-identity-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Both the old fixed temp name and a random-looking leftover must not
        // stop a fresh key from being created.
        fs::write(dir.join("identity.tmp"), b"stale").unwrap();
        fs::write(dir.join("identity.tmp.deadbeef"), b"stale").unwrap();

        let key = load_or_create(&dir).unwrap();
        assert_eq!(load_or_create(&dir).unwrap().to_bytes(), key.to_bytes());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_a_corrupt_key_file() {
        let dir =
            std::env::temp_dir().join(format!("ucabled-identity-corrupt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(IDENTITY_FILE_NAME), b"not a key").unwrap();

        assert!(load_or_create(&dir).is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn loads_a_key_with_loose_permissions_but_warns() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("ucabled-identity-perms-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let key = load_or_create(&dir).unwrap();
        let path = dir.join(IDENTITY_FILE_NAME);
        // Simulate a key restored from a backup with loose permissions.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        // Warn, don't fix: the key still loads and the mode is untouched.
        let reloaded = load_or_create(&dir).unwrap();
        assert_eq!(reloaded.to_bytes(), key.to_bytes());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        fs::remove_dir_all(&dir).unwrap();
    }
}

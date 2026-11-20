//! Private runtime and per-sandbox filesystem state.

use std::{
    fs::{self, DirBuilder, File, OpenOptions, TryLockError},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use tracing::warn;

use crate::{Error, Result};

const BOOTSTRAP: &str = include_str!("bootstrap.sh");

const NSSWITCH: &str = "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\nprotocols: files\nservices: files\nethers: files\nrpc: files\n";

pub struct Root {
    path: PathBuf,
}

fn key(id: &str) -> String {
    // Use 128 bits to leave room for the Unix socket path.
    let mut key = format!("{:x}", Sha256::digest(id.as_bytes()));
    key.truncate(32);
    key
}

#[derive(Debug)]
// We use FD instead of process as the proof of owner for a particular state, since FD is inherited
// after fork and can also be cloned, we therefore explicitly unlock the file when dropping the
// lock, hence this wrapper
pub struct Lock(File);

impl Drop for Lock {
    fn drop(&mut self) {
        // Closing the descriptor is insufficient: a concurrently forked child may
        // hold an inherited duplicate until exec closes it. Explicit unlock makes
        // the kernel lock lifetime match this guard's logical ownership lifetime.
        if let Err(error) = self.0.unlock() {
            warn!(%error, "failed to unlock sandbox state");
        }
    }
}

impl Root {
    pub fn open(path: PathBuf) -> Result<Self> {
        // Get the metadata of the path without following symlink (if the path is one).
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(Error::Config(format!(
                        "Guardian state root is not a directory: {}",
                        path.display()
                    )));
                }
                // Mode includes higher bits which are irrelevant to permission (e.g. 0o41777
                // instead of 777), hence truncation to lower bits.
                let mode = metadata.permissions().mode() & 0o777;
                if mode != 0o700 {
                    return Err(Error::Config(format!(
                        "Guardian state root must have mode 0700, found {mode:04o}: {}",
                        path.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .recursive(true)
                    // ensures the permission on creation is never broader than 700
                    // this is preferable to `create_dir_all` which assumes umask which might be
                    // too broad.
                    .mode(0o700)
                    .create(&path)?;
                // then makes sure it's exactly 700
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            }
            Err(error) => return Err(error.into()),
        }

        Ok(Self { path })
    }

    pub fn path(&self, id: &str) -> PathBuf {
        self.path.join(key(id))
    }

    pub fn create(&self, id: &str) -> Result<State> {
        fn write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                // again to ensure permission is never broader than the `mode` supplied.
                .mode(mode)
                .open(path)?;
            file.write_all(contents)?;
            file.sync_all()?;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            Ok(())
        }

        let state = State {
            path: self.path(id),
            _lock: self.acquire(id)?,
        };

        state.remove()?;
        fs::create_dir(&state.path)?;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o711))?;

        write(
            &state.path.join("resolv.conf"),
            b"nameserver 127.0.0.1\noptions use-vc\n",
            0o444,
        )?;
        write(
            &state.path.join("hosts"),
            b"127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n",
            0o444,
        )?;
        write(
            &state.path.join("nsswitch.conf"),
            NSSWITCH.as_bytes(),
            0o444,
        )?;
        write(
            &state.path.join("bootstrap.sh"),
            BOOTSTRAP.as_bytes(),
            0o555,
        )?;

        Ok(state)
    }

    pub fn acquire(&self, id: &str) -> Result<Lock> {
        let path = self.path.join(format!(".{}.lock", key(id)));
        let lock = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        lock.set_permissions(fs::Permissions::from_mode(0o600))?;

        match lock.try_lock() {
            Ok(()) => Ok(Lock(lock)),
            Err(TryLockError::WouldBlock) => Err(Error::Busy(format!(
                "another Guardian process owns sandbox state {id}"
            ))),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }

    pub fn is_acquired(&self, id: &str) -> Result<bool> {
        match self.acquire(id) {
            Ok(lock) => {
                drop(lock);
                Ok(false)
            }
            Err(Error::Busy(_)) => Ok(true),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug)]
pub struct State {
    path: PathBuf,
    _lock: Lock,
}

impl State {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn proxy_socket(&self) -> PathBuf {
        self.path.join("proxy.sock")
    }

    pub fn resolv_conf(&self) -> PathBuf {
        self.path.join("resolv.conf")
    }

    pub fn nsswitch_conf(&self) -> PathBuf {
        self.path.join("nsswitch.conf")
    }

    pub fn hosts(&self) -> PathBuf {
        self.path.join("hosts")
    }

    fn remove(&self) -> Result<()> {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

impl Drop for State {
    fn drop(&mut self) {
        // Rust drops fields after this method returns, so `_lock` remains held
        // while the state directory is removed and unlocks immediately afterward.
        if let Err(error) = self.remove() {
            warn!(path = %self.path.display(), %error, "failed to remove sandbox state");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_sandbox_state_has_right_content_and_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("guardian");
        let root = Root::open(root_path.clone()).unwrap();
        let id = "sandbox";
        let state = root.create(id).unwrap();

        assert_eq!(
            fs::read_to_string(state.resolv_conf()).unwrap(),
            "nameserver 127.0.0.1\noptions use-vc\n"
        );
        assert!(
            fs::read_to_string(state.path.join("bootstrap.sh"))
                .unwrap()
                .contains("SOCKS5-CONNECT")
        );
        assert!(BOOTSTRAP.contains("while :; do"));
        assert!(BOOTSTRAP.contains("trap 'exit 0' INT TERM"));
        assert!(
            std::process::Command::new("sh")
                .args(["-n", state.path.join("bootstrap.sh").to_str().unwrap()])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            fs::metadata(state.path()).unwrap().permissions().mode() & 0o777,
            0o711
        );
        assert_eq!(
            fs::metadata(state.resolv_conf())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        assert_eq!(
            fs::metadata(state.path.join("bootstrap.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );

        let path = state.path().to_owned();
        drop(state);
        assert!(!path.exists());
        let lock = root_path.join(format!(".{}.lock", key(id)));
        assert_eq!(
            fs::metadata(lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn multiple_root_instances_allowed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let _first = Root::open(path.clone()).unwrap();
        Root::open(path).unwrap();
    }

    #[test]
    fn sandbox_state_is_exclusive() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let first = Root::open(path.clone()).unwrap();
        let second = Root::open(path).unwrap();
        let id = "sandbox";
        let state = first.create(id).unwrap();

        assert!(matches!(second.create(id), Err(Error::Busy(_))));
        assert!(second.is_acquired(id).unwrap());
        assert!(state.resolv_conf().exists());
        drop(state);
        assert!(!second.is_acquired(id).unwrap());
    }

    #[test]
    fn explicit_unlock_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let root = Root::open(temp.path().join("guardian")).unwrap();
        let id = "sandbox";
        let state = root.create(id).unwrap();
        let inherited = state._lock.0.try_clone().unwrap();

        drop(state);

        assert!(!root.is_acquired(id).unwrap());
        drop(inherited);
    }

    #[test]
    fn distinct_sandbox_states_can_coexist() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let first = Root::open(path.clone()).unwrap();
        let second = Root::open(path).unwrap();
        let first_state = first.create("first").unwrap();
        let second_state = second.create("second").unwrap();

        assert_ne!(first_state.path(), second_state.path());
        assert!(first_state.resolv_conf().exists());
        assert!(second_state.resolv_conf().exists());

        drop(first_state);
        assert!(second_state.path().exists());
    }

    #[test]
    fn rebuilds_existing_state_on_creation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let root = Root::open(path.clone()).unwrap();
        let id = "sandbox";
        let state_path = root.path(id);
        fs::create_dir(&state_path).unwrap();

        let state = root.create(id).unwrap();
        assert!(state.resolv_conf().exists());
        assert!(state.hosts().exists());
        assert!(state.nsswitch_conf().exists());
        assert!(state.path.join("bootstrap.sh").exists());
    }

    #[test]
    fn leaves_unrelated_folder_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let root = Root::open(path.clone()).unwrap();
        let stale = root.path("stale");
        let unrelated = path.join("not-a-sandbox");
        fs::create_dir(&stale).unwrap();
        fs::create_dir(&unrelated).unwrap();

        let _state = root.create("sandbox").unwrap();

        assert!(stale.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn refuses_to_change_permissions_on_an_existing_directory() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Root::open(temp.path().to_owned()).is_err());
        assert_eq!(
            fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

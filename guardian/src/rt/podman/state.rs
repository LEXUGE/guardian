//! Private runtime and per-sandbox filesystem state.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use tracing::warn;
use uuid::Uuid;

use crate::{Error, Result};

const BOOTSTRAP: &str = include_str!("bootstrap.sh");

const NSSWITCH: &str = "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\nprotocols: files\nservices: files\nethers: files\nrpc: files\n";

pub struct Root {
    path: PathBuf,
}

impl Root {
    pub fn open(path: PathBuf) -> Result<Self> {
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(Error::Config(format!(
                        "Guardian state root is not a directory: {}",
                        path.display()
                    )));
                }
                let mode = metadata.permissions().mode() & 0o777;
                if mode != 0o700 {
                    return Err(Error::Config(format!(
                        "Guardian state root must have mode 0700, found {mode:04o}: {}",
                        path.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            }
            Err(error) => return Err(error.into()),
        }

        Ok(Self { path })
    }

    pub fn create(&self, id: Option<Uuid>) -> Result<State> {
        fn write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(path)?;
            file.write_all(contents)?;
            file.sync_all()?;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            Ok(())
        }

        let id = id.unwrap_or_else(Uuid::new_v4);
        let state = State {
            id,
            path: self.path.join(id.simple().to_string()),
            _lock: self.try_acquire(id)?,
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

    fn try_acquire(&self, id: Uuid) -> Result<File> {
        let path = self.path.join(format!(".{}.lock", id.simple()));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        lock.set_permissions(fs::Permissions::from_mode(0o600))?;

        match lock.try_lock() {
            Ok(()) => Ok(lock),
            Err(TryLockError::WouldBlock) => Err(Error::Busy(format!(
                "another Guardian process owns sandbox state {id}"
            ))),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

#[derive(Debug)]
pub struct State {
    id: Uuid,
    path: PathBuf,
    _lock: File,
}

impl State {
    pub fn id(&self) -> Uuid {
        self.id
    }

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
        if let Err(error) = self.remove() {
            warn!(path = %self.path.display(), %error, "failed to remove sandbox state");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_controlled_sandbox_files() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("guardian");
        let root = Root::open(root_path.clone()).unwrap();
        let state = root.create(None).unwrap();

        assert_eq!(
            fs::read_to_string(state.resolv_conf()).unwrap(),
            "nameserver 127.0.0.1\noptions use-vc\n"
        );
        assert!(
            fs::read_to_string(state.path.join("bootstrap.sh"))
                .unwrap()
                .contains("SOCKS5-CONNECT")
        );
        assert!(BOOTSTRAP.contains("exec \"$@\""));
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

        let id = state.id();
        let path = state.path().to_owned();
        drop(state);
        assert!(!path.exists());
        let lock = root_path.join(format!(".{}.lock", id.simple()));
        assert_eq!(
            fs::metadata(lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn runtime_root_can_be_shared() {
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
        let id = Uuid::new_v4();
        let state = first.create(Some(id)).unwrap();

        assert!(matches!(second.create(Some(id)), Err(Error::Busy(_))));
        assert!(state.resolv_conf().exists());
    }

    #[test]
    fn distinct_sandbox_states_are_independent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let first = Root::open(path.clone()).unwrap();
        let second = Root::open(path).unwrap();
        let first_state = first.create(Some(Uuid::new_v4())).unwrap();
        let second_state = second.create(Some(Uuid::new_v4())).unwrap();

        assert_ne!(first_state.path(), second_state.path());
        assert!(first_state.resolv_conf().exists());
        assert!(second_state.resolv_conf().exists());

        drop(first_state);
        assert!(second_state.path().exists());
    }

    #[test]
    fn rebuilds_existing_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let root = Root::open(path.clone()).unwrap();
        let id = Uuid::new_v4();
        let state_path = path.join(id.simple().to_string());
        fs::create_dir(&state_path).unwrap();

        let state = root.create(Some(id)).unwrap();
        assert!(state.resolv_conf().exists());
        assert!(state.hosts().exists());
        assert!(state.nsswitch_conf().exists());
        assert!(state.path.join("bootstrap.sh").exists());
    }

    #[test]
    fn leaves_unrelated_state_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let root = Root::open(path.clone()).unwrap();
        let stale = path.join(Uuid::new_v4().simple().to_string());
        let unrelated = path.join("not-a-sandbox");
        fs::create_dir(&stale).unwrap();
        fs::create_dir(&unrelated).unwrap();

        let _state = root.create(None).unwrap();

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

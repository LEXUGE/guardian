//! Private runtime and per-sandbox filesystem state.

use std::{
    fs::{self, File, OpenOptions},
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
    _lock: File,
}

impl Root {
    pub fn acquire(path: PathBuf) -> Result<Self> {
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

        let lock_path = path.join("guardian.lock");
        // The open file owns the advisory lock and must survive existing state.
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(lock_path)?;
        lock.try_lock().map_err(|err| {
            Error::Config(format!(
                "another Guardian process owns {}: {err}",
                path.display()
            ))
        })?;

        Ok(Self { path, _lock: lock })
    }

    pub fn clear(&self) -> Result<()> {
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            }
        }
        Ok(())
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
        let path = self.path.join(id.simple().to_string());
        let state = State { id, path };

        match fs::create_dir(&state.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(state),
            Err(error) => return Err(error.into()),
        }
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
}

#[derive(Debug)]
pub struct State {
    id: Uuid,
    path: PathBuf,
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
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
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
        let root = Root::acquire(temp.path().join("guardian")).unwrap();
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

        let path = state.path().to_owned();
        drop(state);
        assert!(!path.exists());
    }

    #[test]
    fn runtime_root_is_exclusive() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("guardian");
        let _first = Root::acquire(path.clone()).unwrap();
        assert!(Root::acquire(path).is_err());
    }

    #[test]
    fn refuses_to_change_permissions_on_an_existing_directory() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Root::acquire(temp.path().to_owned()).is_err());
        assert_eq!(
            fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

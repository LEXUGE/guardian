use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use tempfile::TempDir;

pub struct MockPodman {
    temp: TempDir,
    binary: PathBuf,
    commands: PathBuf,
    containers: PathBuf,
}

impl MockPodman {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("podman");
        // records all the commands used on the mock podman
        let commands = temp.path().join("commands");
        // list all the containers
        let containers = temp.path().join("containers.json");
        let status = temp.path().join("status");

        fs::write(&containers, "[]\n").unwrap();
        fs::write(&status, "stopped\n").unwrap();
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    create) echo test-container; exit 0 ;;\n    '--format=json') cat '{}'; exit 0 ;;\n    '--format={{{{.State}}}}') cat '{}'; exit 0 ;;\n    start|stop|kill|rm) exit 0 ;;\n  esac\ndone\nexit 1\n",
                commands.display(),
                containers.display(),
                status.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            temp,
            binary,
            commands,
            containers,
        }
    }

    pub fn binary(&self) -> PathBuf {
        self.binary.clone()
    }

    pub fn socket(&self) -> PathBuf {
        self.temp.path().join("podman.sock")
    }

    pub fn state_root(&self) -> PathBuf {
        self.temp.path().join("state")
    }

    pub fn set_containers(&self, json: &str) {
        fs::write(&self.containers, json).unwrap();
    }

    pub fn commands(&self) -> String {
        fs::read_to_string(&self.commands).unwrap()
    }
}

use std::{
    ffi::OsString,
    path::PathBuf,
    process::{Output, Stdio},
    time::Duration,
};

use serde::Deserialize;
use tokio::process::{Child, Command};
use uuid::Uuid;

use super::{HostUds, Status};
use crate::{Error, Result};

const MANAGED_LABEL: &str = "io.guardian.managed=true";
const SANDBOX_ID_LABEL: &str = "io.guardian.sandbox.id";
const HOST_UDS_LABEL: &str = "io.guardian.sandbox.host-uds";

#[derive(Debug, Clone)]
pub(super) struct Cli {
    binary: PathBuf,
    runtime: PathBuf,
}

impl Cli {
    pub fn new(binary: PathBuf, runtime: PathBuf) -> Self {
        Self { binary, runtime }
    }

    pub async fn create(&self, spec: &Create<'_>) -> Result<String> {
        fn create_args(spec: &Create<'_>) -> Vec<OsString> {
            let mut args = vec![
                OsString::from("create"),
                OsString::from(format!("--name={}", spec.name)),
                OsString::from(format!("--label={MANAGED_LABEL}")),
                OsString::from(format!("--label={SANDBOX_ID_LABEL}={}", spec.sandbox_id)),
                OsString::from(format!("--label={HOST_UDS_LABEL}={}", spec.host_uds)),
                OsString::from("--network=none"),
                OsString::from("--init"),
                OsString::from("--http-proxy=false"),
                OsString::from("--cap-add=NET_BIND_SERVICE"),
                OsString::from("--interactive"),
            ];
            args.extend(
                spec.mounts
                    .iter()
                    .map(|mount| OsString::from(format!("--mount={mount}"))),
            );
            for mount in spec.user_mounts {
                args.push(OsString::from("--mount"));
                args.push(mount.clone());
            }
            args.extend(
                spec.env
                    .iter()
                    .map(|variable| OsString::from(format!("--env={variable}"))),
            );
            if spec.tty {
                args.push(OsString::from("--tty"));
            }
            args.push(OsString::from(spec.image));
            args.extend(spec.command.iter().cloned());
            args
        }

        let output = self
            .podman()
            .args(self.rt_args(spec.host_uds))
            .args(create_args(spec))
            .output()
            .await?;
        output.check()?;

        let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if id.is_empty() {
            return Err(Error::Podman(
                "podman create returned an empty container ID".into(),
            ));
        }
        Ok(id)
    }

    pub async fn get(&self, id: Uuid) -> Result<Container> {
        let label = format!("label={SANDBOX_ID_LABEL}={id}");
        let output = self
            .podman()
            .args([
                "ps",
                "--all",
                "--no-trunc",
                "--filter=label=io.guardian.managed=true",
                &format!("--filter={label}"),
                "--format=json",
            ])
            .output()
            .await?;
        output.check()?;
        let mut containers: Vec<Container> = serde_json::from_slice(&output.stdout)
            .map_err(|error| Error::Podman(format!("invalid container list: {error}")))?;
        let container = containers
            .pop()
            .ok_or_else(|| Error::Podman(format!("sandbox {id} does not exist")))?;
        if !containers.is_empty() {
            return Err(Error::Podman(format!(
                "multiple containers use sandbox ID {id}"
            )));
        }
        Ok(container)
    }

    pub async fn status(&self, id: &str) -> Result<Status> {
        let output = self
            .podman()
            .args([
                "ps",
                "--all",
                &format!("--filter=id={id}"),
                "--format={{.State}}",
            ])
            .output()
            .await?;
        output.check()?;

        match String::from_utf8_lossy(&output.stdout).trim() {
            "configured" | "created" | "initialized" => Ok(Status::Created),
            "running" => Ok(Status::Running),
            "exited" | "stopped" => Ok(Status::Stopped),
            "" => Err(Error::Podman(format!("container {id} does not exist"))),
            state => Err(Error::Podman(format!(
                "container {id} has unsupported state {state}"
            ))),
        }
    }

    pub fn start(&self, id: &str, inherit: bool, host_uds: HostUds) -> Result<Child> {
        let mut command = self.podman();
        command.args(self.rt_args(host_uds)).args([
            "start",
            "--attach",
            "--interactive",
            "--sig-proxy=false",
            id,
        ]);

        #[rustfmt::skip]
        command
            .stdin(if inherit { Stdio::inherit() } else { Stdio::piped() })
            .stdout(if inherit { Stdio::inherit() } else { Stdio::piped() })
            .stderr(if inherit { Stdio::inherit() } else { Stdio::piped() });
        Ok(command.spawn()?)
    }

    pub async fn signal(&self, id: &str, signal: i32) -> Result<()> {
        self.podman()
            .args(["kill", &format!("--signal={signal}"), id])
            .output()
            .await?
            .check()
    }

    pub async fn stop(&self, id: &str, grace: Duration) -> Result<()> {
        let seconds = grace.as_secs().to_string();
        self.podman()
            .args(["stop", "--ignore", &format!("--time={seconds}"), id])
            .output()
            .await?
            .check()
    }

    pub async fn kill(&self, id: &str) -> Result<()> {
        self.podman()
            .args(["kill", "--signal=KILL", id])
            .output()
            .await?
            .check()
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        self.podman()
            .args(["rm", "--force", "--ignore", "--volumes", id])
            .output()
            .await?
            .check()
    }

    fn rt_args(&self, host_uds: HostUds) -> Vec<OsString> {
        vec![
            OsString::from("--runtime"),
            self.runtime.as_os_str().to_owned(),
            OsString::from("--runtime-flag=network=none"),
            OsString::from(format!("--runtime-flag=host-uds={host_uds}")),
            OsString::from("--runtime-flag=ignore-cgroups"),
        ]
    }

    fn podman(&self) -> Command {
        Command::new(&self.binary)
    }
}

pub(super) struct Create<'a> {
    pub name: &'a str,
    pub sandbox_id: Uuid,
    pub mounts: &'a [String],
    pub user_mounts: &'a [OsString],
    pub env: &'a [String],
    pub image: &'a str,
    pub command: &'a [OsString],
    pub tty: bool,
    pub host_uds: HostUds,
}

#[derive(Deserialize)]
pub(super) struct Container {
    #[serde(rename = "Id")]
    pub container_id: String,
    #[serde(rename = "Labels")]
    pub labels: Labels,
}

#[derive(Deserialize)]
pub(super) struct Labels {
    #[serde(rename = "io.guardian.sandbox.id")]
    pub id: Uuid,
    #[serde(rename = "io.guardian.sandbox.host-uds", default)]
    pub host_uds: HostUds,
}

trait OutputExt {
    fn check(&self) -> Result<()>;
}

impl OutputExt for Output {
    fn check(&self) -> Result<()> {
        if self.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&self.stderr).trim().to_owned();
        Err(Error::Podman(format!(
            "command failed (status {}): {stderr}",
            self.status
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    #[tokio::test]
    async fn get_deserializes_sandbox_labels() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("podman");
        fs::write(
            &binary,
            "#!/bin/sh\necho '[{\"Id\":\"container-id\",\"Labels\":{\"io.guardian.sandbox.id\":\"00000000-0000-0000-0000-000000000001\",\"io.guardian.sandbox.host-uds\":\"none\",\"other.label\":\"ignored\"}}]'\n",
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();

        let container = Cli::new(binary, "runsc".into())
            .get(Uuid::new_v4())
            .await
            .unwrap();

        assert_eq!(container.container_id, "container-id");
        assert_eq!(
            container.labels.id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert_eq!(container.labels.host_uds, HostUds::None);
    }
}

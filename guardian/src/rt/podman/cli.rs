use std::{ffi::OsString, path::PathBuf, process::Output, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use uuid::Uuid;

use super::{GVisorPlatform, HostUds, Status};
use crate::{Error, Result};

const MANAGED_LABEL: &str = "io.guardian.managed=true";
const SANDBOX_ID_LABEL: &str = "io.guardian.sandbox.id";
const HOST_UDS_LABEL: &str = "io.guardian.sandbox.gvisor.host-uds";
const OVERLAY2_LABEL: &str = "io.guardian.sandbox.gvisor.overlay2";
const PLATFORM_LABEL: &str = "io.guardian.sandbox.gvisor.platform";

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
                OsString::from(format!("--label={OVERLAY2_LABEL}={}", spec.overlay2)),
                OsString::from(format!("--label={PLATFORM_LABEL}={}", spec.platform)),
                OsString::from("--network=none"),
                OsString::from("--init"),
                OsString::from("--http-proxy=false"),
                OsString::from("--cap-add=NET_BIND_SERVICE"),
                // sets the `stop_timeout` which is used by the exec session force remove
                // redundant for container removal as it sets time independently
                OsString::from(format!("--stop-timeout={}", spec.stop_timeout.as_secs())),
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
            for volume in spec.user_volumes {
                args.push(OsString::from("--volume"));
                args.push(volume.clone());
            }
            args.extend(
                spec.env
                    .iter()
                    .map(|variable| OsString::from(format!("--env={variable}"))),
            );
            args.push(OsString::from(spec.image));
            args.extend(spec.command.iter().cloned());
            args
        }

        let output = self
            .podman()
            .args(self.rt_args(spec.host_uds, spec.overlay2, spec.platform))
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

    pub async fn list(&self) -> Result<Vec<Container>> {
        self.list_filtered(None).await
    }

    async fn list_filtered(&self, sandbox_id: Option<&str>) -> Result<Vec<Container>> {
        let mut command = self.podman();
        command.args([
            "ps",
            "--all",
            "--no-trunc",
            "--filter=label=io.guardian.managed=true",
        ]);
        if let Some(sandbox_id) = sandbox_id {
            command.arg(format!("--filter=label={SANDBOX_ID_LABEL}={sandbox_id}"));
        }
        let output = command.arg("--format=json").output().await?;
        output.check()?;
        serde_json::from_slice(&output.stdout)
            .map_err(|error| Error::Podman(format!("invalid container list: {error}")))
    }

    pub async fn get(&self, id: Uuid) -> Result<Container> {
        let mut containers = self.list_filtered(Some(&id.to_string())).await?;
        let container = containers
            .pop()
            .ok_or_else(|| Error::Podman(format!("sandbox {id} does not exist")))?;
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

    pub async fn start(
        &self,
        id: &str,
        host_uds: HostUds,
        overlay2: &str,
        platform: GVisorPlatform,
    ) -> Result<()> {
        self.podman()
            .args(self.rt_args(host_uds, overlay2, platform))
            .args(["start", id])
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

    fn rt_args(
        &self,
        host_uds: HostUds,
        overlay2: &str,
        platform: GVisorPlatform,
    ) -> Vec<OsString> {
        vec![
            OsString::from("--runtime"),
            self.runtime.as_os_str().to_owned(),
            OsString::from("--runtime-flag=network=none"),
            OsString::from(format!("--runtime-flag=host-uds={host_uds}")),
            OsString::from(format!("--runtime-flag=overlay2={overlay2}")),
            OsString::from(format!("--runtime-flag=platform={platform}")),
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
    pub user_volumes: &'a [OsString],
    pub env: &'a [String],
    pub image: &'a str,
    pub command: &'a [OsString],
    pub stop_timeout: Duration,
    pub host_uds: HostUds,
    pub overlay2: &'a str,
    pub platform: GVisorPlatform,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Container {
    #[serde(rename = "Names")]
    pub names: Vec<String>,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "Id")]
    pub container_id: String,
    #[serde(rename = "Labels")]
    pub labels: Labels,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Labels {
    #[serde(rename = "io.guardian.sandbox.id")]
    pub id: Uuid,
    #[serde(rename = "io.guardian.sandbox.gvisor.host-uds", default)]
    pub host_uds: HostUds,
    #[serde(
        rename = "io.guardian.sandbox.gvisor.overlay2",
        default = "default_overlay2"
    )]
    pub overlay2: String,
    #[serde(
        rename = "io.guardian.sandbox.gvisor.platform",
        default = "default_platform"
    )]
    pub platform: GVisorPlatform,
}

fn default_overlay2() -> String {
    "root:self".into()
}

fn default_platform() -> GVisorPlatform {
    // Containers created before platform selection was persisted used systrap.
    GVisorPlatform::Systrap
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
    use super::{super::mock::MockPodman, *};

    #[tokio::test]
    async fn get_deserializes_sandbox_labels() {
        let mock = MockPodman::new();
        mock.set_containers(
            r#"[{"Names":["container-name","alias"],"Image":"example:latest","Id":"container-id","Labels":{"io.guardian.sandbox.id":"00000000-0000-0000-0000-000000000001","io.guardian.sandbox.gvisor.host-uds":"none","io.guardian.sandbox.gvisor.overlay2":"root:dir=/run/guardian","other.label":"ignored"}}]"#,
        );

        let container = Cli::new(mock.binary(), "runsc".into())
            .get(Uuid::new_v4())
            .await
            .unwrap();

        assert_eq!(container.names, ["container-name", "alias"]);
        assert_eq!(container.image, "example:latest");
        assert_eq!(container.container_id, "container-id");
        assert_eq!(
            container.labels.id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert_eq!(container.labels.host_uds, HostUds::None);
        assert_eq!(container.labels.overlay2, "root:dir=/run/guardian");
    }
}

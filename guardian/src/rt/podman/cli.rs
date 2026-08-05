use std::{
    ffi::OsString,
    path::PathBuf,
    process::{Output, Stdio},
    time::Duration,
};

use tokio::process::{Child, Command};
use uuid::Uuid;

use super::Status;
use crate::{Error, Result};

const MANAGED_LABEL: &str = "io.guardian.managed=true";
const SANDBOX_LABEL: &str = "io.guardian.sandbox";

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
                OsString::from(format!("--label={SANDBOX_LABEL}={}", spec.sandbox_id)),
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
            .args(self.rt_args())
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

    pub async fn get(&self, id: Uuid) -> Result<String> {
        let label = format!("label={SANDBOX_LABEL}={id}");
        let output = self
            .podman()
            .args([
                "ps",
                "--all",
                "--no-trunc",
                "--filter=label=io.guardian.managed=true",
                &format!("--filter={label}"),
                "--format={{.ID}}",
            ])
            .output()
            .await?;
        output.check()?;

        let output = String::from_utf8_lossy(&output.stdout);
        let mut containers = output.lines().filter(|line| !line.trim().is_empty());
        let container = containers
            .next()
            .ok_or_else(|| Error::Podman(format!("sandbox {id} does not exist")))?;
        if containers.next().is_some() {
            return Err(Error::Podman(format!(
                "multiple containers use sandbox ID {id}"
            )));
        }
        Ok(container.trim().to_owned())
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

    pub fn start(&self, id: &str, inherit: bool) -> Result<Child> {
        let mut command = self.podman();
        command.args(self.rt_args()).args([
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

    fn rt_args(&self) -> Vec<OsString> {
        vec![
            OsString::from("--runtime"),
            self.runtime.as_os_str().to_owned(),
            OsString::from("--runtime-flag=network=none"),
            OsString::from("--runtime-flag=host-uds=open"),
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

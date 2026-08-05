use std::{ffi::OsString, net::Ipv4Addr, path::PathBuf, time::Duration};

use clap::{Parser, Subcommand};
use guardian::{Error, Result, rt::podman};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Secure, auditable computing environment for AI agent"
)]
pub struct Cli {
    /// Append structured logs to this file.
    #[arg(long, global = true, default_value = "guardian.jsonl")]
    pub log_file: PathBuf,

    #[command(flatten)]
    pub runtime: RuntimeArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, clap::Args)]
pub struct RuntimeArgs {
    /// Podman executable.
    #[arg(long, global = true, default_value = "podman")]
    podman: PathBuf,

    /// gVisor OCI runtime executable or configured runtime name.
    #[arg(long, global = true, default_value = "runsc")]
    runtime: PathBuf,

    /// Private Guardian runtime directory (must have mode 0700).
    #[arg(long, global = true)]
    state_root: Option<PathBuf>,

    /// Outbound TCP connection timeout.
    #[arg(
        long,
        global = true,
        value_parser = humantime::parse_duration,
        default_value = "10s"
    )]
    connect_timeout: Duration,

    /// Grace period before a stopped container is killed.
    #[arg(
        long,
        global = true,
        value_parser = humantime::parse_duration,
        default_value = "5s"
    )]
    stop_timeout: Duration,
}

impl RuntimeArgs {
    pub fn into_config(self) -> Result<podman::Config> {
        let root = match self.state_root {
            Some(path) if path.is_absolute() => path,
            Some(path) => std::env::current_dir()?.join(path),
            None => {
                let runtime = std::env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
                    Error::Config("XDG_RUNTIME_DIR is unset; pass --state-root explicitly".into())
                })?;
                let runtime = PathBuf::from(runtime);
                if !runtime.is_absolute() || !runtime.is_dir() {
                    return Err(Error::Config(format!(
                        "XDG_RUNTIME_DIR does not name an existing absolute directory: {}",
                        runtime.display()
                    )));
                }
                runtime.join("guardian")
            }
        };

        Ok(podman::Config {
            podman: self.podman,
            runtime: self.runtime,
            root,
            connect_timeout: self.connect_timeout,
            stop_timeout: self.stop_timeout,
        })
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a persistent sandbox.
    Create(CreateArgs),

    /// Create, start, and attach to a sandbox.
    Run {
        #[command(flatten)]
        create: CreateArgs,

        /// Remove the sandbox after it exits.
        #[arg(long, default_value_t = true)]
        ephemeral: bool,
    },

    /// Start and attach to a sandbox.
    Start { id: Uuid },

    /// Print sandbox status.
    Status { id: Uuid },

    /// Force-stop a sandbox.
    Kill { id: Uuid },

    /// Delete a sandbox.
    Remove { id: Uuid },
}

#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    /// Podman container name. Defaults to guardian-UUID.
    #[arg(long)]
    pub name: Option<String>,

    /// Podman mount specification. May be repeated.
    #[arg(long = "mount", value_name = "TYPE-SPECIFIC-OPTIONS")]
    pub mounts: Vec<OsString>,

    /// Podman volume specification. May be repeated.
    #[arg(long = "volume", value_name = "VOLUME-SPEC")]
    pub volumes: Vec<OsString>,

    /// OCI image name or ID.
    pub image: String,

    /// Allocate a terminal instead of separate stdout and stderr streams.
    #[arg(long)]
    pub tty: bool,

    /// Upstream recursive resolver used by the DNS-over-TCP relay.
    #[arg(long, default_value = "1.1.1.1")]
    pub upstream_dns: Ipv4Addr,

    /// Guest networking through Guardian.
    #[arg(long, default_value_t = podman::HostUds::Open)]
    pub network: podman::HostUds,

    /// Command and arguments. Defaults to /bin/sh.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        default_value = "/bin/sh"
    )]
    pub command: Vec<OsString>,
}

impl CreateArgs {
    pub fn into_spec(self) -> podman::Spec {
        podman::Spec {
            name: self.name,
            mounts: self.mounts,
            volumes: self.volumes,
            image: self.image,
            command: self.command,
            tty: self.tty,
            upstream_dns: self.upstream_dns,
            host_uds: self.network,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_command_replaces_default() {
        let cli = Cli::try_parse_from(["guardian", "run", "image", "echo", "hello"]).unwrap();
        let Command::Run { create, .. } = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(
            create.command,
            [OsString::from("echo"), OsString::from("hello")]
        );
    }

    #[test]
    fn mounts_are_repeatable() {
        let cli = Cli::try_parse_from([
            "guardian",
            "run",
            "--mount",
            "type=bind,source=./workspace,destination=/workspace",
            "--mount",
            "type=volume,destination=/cache,ro",
            "image",
        ])
        .unwrap();
        let Command::Run { create, .. } = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(
            create.mounts,
            [
                OsString::from("type=bind,source=./workspace,destination=/workspace"),
                OsString::from("type=volume,destination=/cache,ro")
            ]
        );
    }

    #[test]
    fn volumes_are_repeatable() {
        let cli = Cli::try_parse_from([
            "guardian",
            "run",
            "--volume",
            "cache:/cache:ro",
            "--volume",
            "./workspace:/workspace",
            "image",
        ])
        .unwrap();
        let Command::Run { create, .. } = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(
            create.volumes,
            [
                OsString::from("cache:/cache:ro"),
                OsString::from("./workspace:/workspace")
            ]
        );
    }

    #[test]
    fn network_accepts_none_and_defaults_to_open() {
        let default = Cli::try_parse_from(["guardian", "create", "image"]).unwrap();
        let Command::Create(default) = default.command else {
            panic!("expected create command");
        };
        assert_eq!(default.network, podman::HostUds::Open);

        let none = Cli::try_parse_from(["guardian", "create", "--network=none", "image"]).unwrap();
        let Command::Create(none) = none.command else {
            panic!("expected create command");
        };
        assert_eq!(none.network, podman::HostUds::None);
    }
}

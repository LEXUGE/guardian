use std::{
    ffi::OsString,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Parser, Subcommand};
use guardian::{Error, Result, net::policy::Policy, rt::podman};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Secure, auditable computing environment for AI agent"
)]
pub struct Cli {
    /// Append structured logs to this file. Defaults to STATE_ROOT/log.jsonl.
    #[arg(long, global = true)]
    pub log_file: Option<PathBuf>,

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

    /// Podman API Unix socket. Defaults below XDG_RUNTIME_DIR.
    #[arg(long, global = true)]
    podman_socket: Option<PathBuf>,

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
        let runtime_dir = || {
            let path = std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .ok_or_else(|| Error::Config("XDG_RUNTIME_DIR is unset".into()))?;
            if !path.is_absolute() || !path.is_dir() {
                return Err(Error::Config(format!(
                    "XDG_RUNTIME_DIR does not name an existing absolute directory: {}",
                    path.display()
                )));
            }
            Ok(path)
        };
        let absolute = |path: PathBuf| -> Result<PathBuf> {
            if path.is_absolute() {
                Ok(path)
            } else {
                Ok(std::env::current_dir()?.join(path))
            }
        };

        let root = match self.state_root {
            Some(path) => absolute(path)?,
            None => runtime_dir()?.join("guardian"),
        };
        let socket = match self.podman_socket {
            Some(path) if path.is_absolute() => path,
            Some(path) => {
                return Err(Error::Config(format!(
                    "Podman socket path is not absolute: {}",
                    path.display()
                )));
            }
            None => runtime_dir()?.join("podman/podman.sock"),
        };

        Ok(podman::Config {
            podman: self.podman,
            runtime: self.runtime,
            socket,
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

    /// Create a sandbox, run one command, then stop the sandbox.
    Run {
        #[command(flatten)]
        create: CreateArgs,

        #[command(flatten)]
        exec: ExecArgs,

        #[command(flatten)]
        egress: EgressArgs,

        /// Remove the sandbox after the command exits.
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true",
            require_equals = true
        )]
        ephemeral: bool,
    },

    /// Start a sandbox and own it until interrupted.
    Start {
        id: String,

        #[command(flatten)]
        egress: EgressArgs,
    },

    /// Execute one command in a running sandbox.
    Exec {
        id: String,

        #[command(flatten)]
        exec: ExecArgs,
    },

    /// Print sandbox status.
    Status { id: String },

    /// Force-stop a sandbox.
    Kill { id: String },

    /// Delete a sandbox.
    Remove { id: String },

    /// List Guardian-managed containers as JSON.
    List,
}

#[derive(Debug, clap::Args)]
pub struct EgressArgs {
    /// TOML network policy for this sandbox run.
    #[arg(long, value_name = "PATH")]
    pub net_policy: Vec<PathBuf>,
}

impl EgressArgs {
    pub fn into_policy(self) -> Result<Policy> {
        if self.net_policy.is_empty() {
            return Ok(Policy::default());
        }

        let mut errors = Vec::new();
        let policy = self.net_policy.into_iter().find_map(|path| {
            if path == Path::new("default") {
                return Some(Policy::default());
            }
            let source = match fs::read_to_string(&path) {
                Ok(source) => source,
                Err(error) => {
                    errors.push(format!(
                        "cannot read network policy {}: {error}",
                        path.display()
                    ));
                    return None;
                }
            };
            match toml::from_str(&source) {
                Ok(policy) => Some(policy),
                Err(error) => {
                    errors.push(format!(
                        "invalid network policy {}: {error}",
                        path.display()
                    ));
                    None
                }
            }
        });

        policy.ok_or_else(|| Error::Config(errors.join("; ")))
    }
}

#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    /// Sandbox ID and Podman container name. Generated when omitted.
    #[arg(long)]
    pub id: Option<String>,

    /// Podman mount specification. May be repeated.
    #[arg(long = "mount", value_name = "TYPE-SPECIFIC-OPTIONS")]
    pub mounts: Vec<OsString>,

    /// Podman volume specification. May be repeated.
    #[arg(long = "volume", value_name = "VOLUME-SPEC")]
    pub volumes: Vec<OsString>,

    /// OCI image name or ID.
    pub image: String,

    /// Upstream recursive resolver used by the DNS-over-TCP relay.
    #[arg(long, default_value = "1.1.1.1")]
    pub upstream_dns: Ipv4Addr,

    /// Guest networking through Guardian.
    #[arg(long, default_value_t = podman::HostUds::Open)]
    pub network: podman::HostUds,

    /// gVisor filesystem overlay configuration.
    #[arg(long, default_value = "root:self")]
    pub gvisor_overlay2: String,

    /// gVisor execution platform.
    #[arg(long = "gvisor-platform", default_value_t = podman::GVisorPlatform::Kvm)]
    pub gvisor_platform: podman::GVisorPlatform,
}

#[derive(Debug, clap::Args)]
pub struct ExecArgs {
    /// Allocate a guest terminal and use the inherited host terminal in raw mode.
    #[arg(short = 't', long)]
    pub tty: bool,

    /// Environment variable override for this command. May be repeated.
    #[arg(short = 'e', long, value_name = "KEY=VALUE", value_parser = parse_env)]
    pub env: Vec<String>,

    /// Absolute guest working directory for this command.
    #[arg(short = 'w', long = "workdir", value_name = "PATH", value_parser = parse_workdir)]
    pub working_dir: Option<String>,

    /// Command and arguments. Defaults to /bin/sh.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        default_value = "/bin/sh"
    )]
    pub command: Vec<String>,
}

impl ExecArgs {
    pub fn into_spec(self) -> podman::ExecSpec {
        podman::ExecSpec {
            command: self.command,
            env: self.env,
            tty: self.tty,
            working_dir: self.working_dir,
            ..Default::default()
        }
    }
}

fn parse_env(value: &str) -> std::result::Result<String, String> {
    match value.split_once('=') {
        Some((key, _)) if !key.is_empty() => Ok(value.to_owned()),
        _ => Err("expected KEY=VALUE with a nonempty key".into()),
    }
}

fn parse_workdir(value: &str) -> std::result::Result<String, String> {
    if Path::new(value).is_absolute() {
        Ok(value.to_owned())
    } else {
        Err("working directory must be an absolute guest path".into())
    }
}

impl CreateArgs {
    pub fn into_spec(self) -> podman::Spec {
        podman::Spec {
            id: self.id,
            mounts: self.mounts,
            volumes: self.volumes,
            image: self.image,
            upstream_dns: self.upstream_dns,
            host_uds: self.network,
            overlay2: self.gvisor_overlay2,
            platform: self.gvisor_platform,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn explicit_command_replaces_default() {
        let cli = Cli::try_parse_from([
            "guardian",
            "run",
            "--id",
            "agent",
            "--ephemeral=false",
            "image",
            "echo",
            "hello",
        ])
        .unwrap();
        let Command::Run {
            create,
            exec,
            ephemeral,
            ..
        } = cli.command
        else {
            panic!("expected run command");
        };
        assert_eq!(create.into_spec().id.as_deref(), Some("agent"));
        assert!(!ephemeral);
        assert_eq!(exec.command, ["echo", "hello"]);
    }

    #[test]
    fn tty_is_an_exec_option() {
        let cli = Cli::try_parse_from(["guardian", "exec", "agent", "-t", "bash"]).unwrap();
        let Command::Exec { exec, .. } = cli.command else {
            panic!("expected exec command");
        };
        assert!(exec.tty);
        assert_eq!(exec.command, ["bash"]);
    }

    #[test]
    fn exec_environment_and_workdir_are_forwarded() {
        let cli = Cli::try_parse_from([
            "guardian",
            "exec",
            "agent",
            "--env",
            "HOME=/home/agent",
            "--env",
            "EMPTY=",
            "--env",
            "TOKEN=a=b",
            "--workdir",
            "/workspace",
        ])
        .unwrap();
        let Command::Exec { exec, .. } = cli.command else {
            panic!("expected exec command");
        };
        let spec = exec.into_spec();
        assert_eq!(spec.env, ["HOME=/home/agent", "EMPTY=", "TOKEN=a=b"]);
        assert_eq!(spec.working_dir.as_deref(), Some("/workspace"));
    }

    #[test]
    fn exec_rejects_invalid_overrides() {
        for (option, value) in [
            ("--env", "HOME"),
            ("--env", "=value"),
            ("--workdir", "workspace"),
            ("--workdir", ""),
        ] {
            let error =
                Cli::try_parse_from(["guardian", "exec", "agent", option, value]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        }
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
        let default =
            Cli::try_parse_from(["guardian", "create", "--id", "agent", "image"]).unwrap();
        let Command::Create(create) = default.command else {
            panic!("expected create command");
        };
        let spec = create.into_spec();
        assert_eq!(spec.id.as_deref(), Some("agent"));
        assert_eq!(spec.host_uds, podman::HostUds::Open);

        let none = Cli::try_parse_from(["guardian", "create", "--network=none", "image"]).unwrap();
        let Command::Create(create) = none.command else {
            panic!("expected create command");
        };
        assert_eq!(create.network, podman::HostUds::None);
    }

    #[test]
    fn podman_socket_must_be_absolute() {
        let cli = Cli::try_parse_from([
            "guardian",
            "--state-root=/tmp/guardian-test",
            "--podman-socket=podman.sock",
            "list",
        ])
        .unwrap();
        let error = cli.runtime.into_config().unwrap_err();
        assert!(error.to_string().contains("socket path is not absolute"));
    }

    fn into_policy(paths: impl IntoIterator<Item = PathBuf>) -> Result<Policy> {
        EgressArgs {
            net_policy: paths.into_iter().collect(),
        }
        .into_policy()
    }

    #[test]
    fn selects_first_successful_policy() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("file1");
        let file2 = dir.path().join("file2");
        let file3 = dir.path().join("file3");
        // file1 exists but contains malformed TOML.
        fs::write(&file1, "[").unwrap();
        // file2 is a directory, so it cannot be read as a policy file.
        fs::create_dir(&file2).unwrap();
        let source = "[domains]\nallow = [\"example.com\"]";
        fs::write(&file3, source).unwrap();

        let policy = into_policy([file1, file2, file3, PathBuf::from("default")]).unwrap();
        let expected: Policy = toml::from_str(source).unwrap();
        assert_eq!(format!("{policy:?}"), format!("{expected:?}"));
    }

    #[test]
    fn selects_default_after_unsuccessful_policies() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("file1");
        let file2 = dir.path().join("file2");
        // file1 exists but contains malformed TOML.
        fs::write(&file1, "[").unwrap();
        // file2 is a directory, so it cannot be read as a policy file.
        fs::create_dir(&file2).unwrap();

        let policy = into_policy([file1, file2, PathBuf::from("default")]).unwrap();
        assert_eq!(format!("{policy:?}"), format!("{:?}", Policy::default()));
    }

    #[test]
    fn returns_error_when_no_policy_succeeds() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("file1");
        let file2 = dir.path().join("file2");
        // file1 exists but contains malformed TOML.
        fs::write(&file1, "[").unwrap();
        // file2 is a directory, so it cannot be read as a policy file.
        fs::create_dir(&file2).unwrap();

        assert!(into_policy([file1, file2]).is_err());
    }

    #[test]
    fn selects_default_without_policy_arguments() {
        let policy = into_policy([]).unwrap();
        assert_eq!(format!("{policy:?}"), format!("{:?}", Policy::default()));
    }
}

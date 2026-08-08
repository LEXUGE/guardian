use std::{
    ffi::OsString,
    fmt,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{ExitCode, ExitStatus},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{self, AsyncWriteExt},
    process::Child,
    signal::unix::{self, SignalKind},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    Error, Result,
    net::uds,
    rt::{self, Process as _, Stdio},
};

mod cli;
mod state;

use cli::{Cli, Create};
use state::{Root, State};

pub use cli::{Container, Labels};

const BOOTSTRAP: &str = "/run/guardian/bootstrap.sh";

#[derive(Debug, Clone)]
pub struct Config {
    pub podman: PathBuf,
    pub runtime: PathBuf,
    pub root: PathBuf,
    pub connect_timeout: Duration,
    pub stop_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct Spec {
    pub name: Option<String>,
    pub mounts: Vec<OsString>,
    pub volumes: Vec<OsString>,
    pub image: String,
    pub command: Vec<OsString>,
    pub tty: bool,
    pub upstream_dns: Ipv4Addr,
    pub host_uds: HostUds,
    pub overlay2: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HostUds {
    #[default]
    None,
    Open,
}

impl fmt::Display for HostUds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "none",
            Self::Open => "open",
        })
    }
}

impl FromStr for HostUds {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "none" => Ok(Self::None),
            "open" => Ok(Self::Open),
            _ => Err(format!("unsupported host UDS mode {value:?}")),
        }
    }
}

struct Context {
    cli: Cli,
    root: Root,
    proxy: uds::Config,
    stop_timeout: Duration,
}

pub struct Podman {
    context: Arc<Context>,
}

impl Podman {
    /// Lists every container created by Guardian.
    pub async fn list(&self) -> Result<Vec<Container>> {
        self.context.cli.list().await
    }
}

impl rt::Backend for Podman {
    type Config = Config;
    type Spec = Spec;
    type Id = Uuid;
    type Sandbox = Sandbox;

    async fn init(config: Self::Config) -> Result<Self> {
        let root = Root::acquire(config.root)?;
        root.clear()?;
        Ok(Self {
            context: Arc::new(Context {
                cli: Cli::new(config.podman, config.runtime),
                root,
                proxy: uds::Config {
                    connect_timeout: config.connect_timeout,
                },
                stop_timeout: config.stop_timeout,
            }),
        })
    }

    async fn create(&mut self, mut spec: Self::Spec) -> Result<Self::Sandbox> {
        let state = self.context.root.create(None)?;
        let id = state.id();
        let mounts = [
            (state.path().to_owned(), "/run/guardian"),
            (state.resolv_conf(), "/etc/resolv.conf"),
            (state.nsswitch_conf(), "/etc/nsswitch.conf"),
            (state.hosts(), "/etc/hosts"),
        ]
        .map(|(source, destination)| {
            format!(
                "type=bind,source={},destination={destination},ro",
                source.display()
            )
        });
        let env = [format!("GUARDIAN_UPSTREAM_DNS={}", spec.upstream_dns)];

        spec.command.insert(0, OsString::from(BOOTSTRAP));
        let name = spec
            .name
            .take()
            .unwrap_or_else(|| format!("guardian-{}", id.simple()));
        let container_id = self
            .context
            .cli
            .create(&Create {
                name: &name,
                sandbox_id: id,
                mounts: &mounts,
                user_mounts: &spec.mounts,
                user_volumes: &spec.volumes,
                env: &env,
                image: &spec.image,
                command: &spec.command,
                tty: spec.tty,
                host_uds: spec.host_uds,
                overlay2: &spec.overlay2,
            })
            .await?;

        info!(sandbox_id = %id, %container_id, image = spec.image, "sandbox created");
        Ok(Sandbox {
            context: Arc::clone(&self.context),
            id,
            container_id,
            host_uds: spec.host_uds,
            overlay2: spec.overlay2,
        })
    }

    async fn get(&self, id: Uuid) -> Result<Self::Sandbox> {
        let container = self.context.cli.get(id).await?;
        Ok(Sandbox {
            context: Arc::clone(&self.context),
            id: container.labels.id,
            container_id: container.container_id,
            host_uds: container.labels.host_uds,
            overlay2: container.labels.overlay2,
        })
    }
}

pub struct Sandbox {
    context: Arc<Context>,
    id: Uuid,
    container_id: String,
    host_uds: HostUds,
    overlay2: String,
}

impl rt::Sandbox for Sandbox {
    type Id = Uuid;
    type Process = Process;
    type Status = Status;

    fn id(&self) -> Uuid {
        self.id
    }

    async fn status(&self) -> Result<Self::Status> {
        self.context.cli.status(&self.container_id).await
    }

    async fn start(&self, stdio: Stdio) -> Result<Self::Process> {
        match self.status().await? {
            Status::Created | Status::Stopped => {}
            Status::Running => {
                return Err(Error::Podman(format!(
                    "sandbox {} is already running",
                    self.id
                )));
            }
        }

        let state = self.context.root.create(Some(self.id))?;
        let proxy = ProxyTask::spawn(
            self.host_uds,
            &state.proxy_socket(),
            self.context.proxy.clone(),
        )?;
        let inherit = matches!(&stdio, Stdio::Inherit);
        let mut child =
            self.context
                .cli
                .start(&self.container_id, inherit, self.host_uds, &self.overlay2)?;
        let stdio = StdioTask::spawn(stdio, &mut child);
        let container =
            ContainerTask::spawn(Arc::clone(&self.context), self.container_id.clone(), child);

        info!(sandbox_id = %self.id, container_id = %self.container_id, "sandbox started");
        Ok(Process {
            context: Arc::clone(&self.context),
            container_id: self.container_id.clone(),
            container,
            stdio,
            proxy,
            state,
        })
    }

    async fn kill(&self) -> Result<()> {
        self.context.cli.kill(&self.container_id).await
    }

    async fn remove(self) -> Result<()> {
        self.context.cli.remove(&self.container_id).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Created,
    Running,
    Stopped,
}

impl fmt::Display for Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        })
    }
}

pub struct Process {
    context: Arc<Context>,
    container_id: String,
    container: ContainerTask,
    stdio: StdioTask,
    proxy: ProxyTask,
    state: State,
}

impl Process {
    async fn wait(&mut self) -> Result<ExitCode> {
        enum Event {
            Exited(Result<ExitCode>),
            Signal(SignalKind),
        }

        let mut interrupt = unix::signal(SignalKind::interrupt())?;
        let mut terminate = unix::signal(SignalKind::terminate())?;
        let event = tokio::select! {
            result = &mut self.container.task => Event::Exited(result?),
            _ = interrupt.recv() => Event::Signal(SignalKind::interrupt()),
            _ = terminate.recv() => Event::Signal(SignalKind::terminate()),
        };

        match event {
            Event::Exited(result) => result,
            Event::Signal(signal) => {
                info!(
                    signal = signal.as_raw_value(),
                    "forwarding signal to sandbox"
                );
                if let Err(error) = self.signal(signal).await {
                    // The container may exit after select chooses the signal branch
                    // but before Podman handles it. Prefer its result when the
                    // supervisor has already observed the exit; other signal errors
                    // remain failures.
                    if self.container.task.is_finished() {
                        return (&mut self.container.task).await?;
                    }
                    return Err(error);
                }
                match timeout(self.context.stop_timeout, &mut self.container.task).await {
                    Ok(result) => result?,
                    Err(_) => {
                        self.container.stop();
                        (&mut self.container.task).await?
                    }
                }
            }
        }
    }

    async fn finish(self, code: ExitCode) -> Result<ExitCode> {
        self.stdio.finish().await;
        self.proxy.finish().await?;
        drop(self.state);

        info!(container_id = %self.container_id, ?code, "sandbox exited");
        Ok(code)
    }
}

impl rt::Process for Process {
    async fn signal(&mut self, signal: SignalKind) -> Result<()> {
        self.context
            .cli
            .signal(&self.container_id, signal.as_raw_value())
            .await
    }

    async fn stop(mut self) -> Result<ExitCode> {
        self.container.stop();
        // Do not use the `join` or `wait` here because we don't want to handle signals.
        let code = (&mut self.container.task).await??;
        self.finish(code).await
    }

    async fn join(mut self) -> Result<ExitCode> {
        let code = self.wait().await?;
        self.finish(code).await
    }
}

struct ContainerTask {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<ExitCode>>,
}

impl ContainerTask {
    fn spawn(context: Arc<Context>, container_id: String, mut child: Child) -> Self {
        let (shutdown, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let status = tokio::select! {
                biased;
                status = child.wait() => status?,
                _ = receiver.changed() => {
                    context
                        .cli
                        .stop(&container_id, context.stop_timeout)
                        .await?;
                    child.wait().await?
                }
            };
            Self::exit_code(status)
        });
        Self { shutdown, task }
    }

    fn exit_code(status: ExitStatus) -> Result<ExitCode> {
        let code = status.code().ok_or_else(|| {
            Error::Podman(format!(
                "podman attach process exited without a code: {status}"
            ))
        })?;
        let code = u8::try_from(code)
            .map_err(|_| Error::Podman(format!("invalid podman exit code: {code}")))?;
        Ok(ExitCode::from(code))
    }

    fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}

enum StdioTask {
    Inherit,
    Redirect {
        shutdown: watch::Sender<bool>,
        task: JoinHandle<()>,
    },
}

impl StdioTask {
    fn spawn(stdio: Stdio, child: &mut Child) -> Self {
        let Stdio::Redirect {
            mut stdin,
            mut stdout,
            mut stderr,
        } = stdio
        else {
            return Self::Inherit;
        };

        let mut child_stdin = child.stdin.take().expect("child stdin is piped");
        let mut child_stdout = child.stdout.take().expect("child stdout is piped");
        let mut child_stderr = child.stderr.take().expect("child stderr is piped");
        let (shutdown, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let input = async move {
                if let Err(error) = async {
                    io::copy(&mut stdin, &mut child_stdin).await?;
                    child_stdin.shutdown().await
                }
                .await
                {
                    warn!(%error, "stdin copy failed");
                }
            };
            let output = async move {
                let stdout = async {
                    if let Err(error) = async {
                        io::copy(&mut child_stdout, &mut stdout).await?;
                        stdout.flush().await
                    }
                    .await
                    {
                        warn!(%error, "stdout copy failed");
                    }
                };
                let stderr = async {
                    if let Err(error) = async {
                        io::copy(&mut child_stderr, &mut stderr).await?;
                        stderr.flush().await
                    }
                    .await
                    {
                        warn!(%error, "stderr copy failed");
                    }
                };
                tokio::join!(stdout, stderr);
            };

            tokio::pin!(input);
            tokio::pin!(output);
            tokio::select! {
                _ = input.as_mut() => output.await,
                _ = output.as_mut() => {},
                _ = receiver.changed() => output.await,
            }
        });
        Self::Redirect { shutdown, task }
    }

    async fn finish(self) {
        if let Self::Redirect { shutdown, task } = self {
            drop(shutdown);
            let _ = task.await;
        }
    }
}

enum ProxyTask {
    Disabled,
    Running {
        shutdown: watch::Sender<bool>,
        task: JoinHandle<Result<()>>,
    },
}

impl ProxyTask {
    fn spawn(host_uds: HostUds, path: &Path, config: uds::Config) -> Result<Self> {
        match host_uds {
            HostUds::None => Ok(Self::Disabled),
            HostUds::Open => {
                let proxy = uds::Proxy::bind(path, config)?;
                let (shutdown, receiver) = watch::channel(false);
                let task = tokio::spawn(proxy.run(receiver));
                Ok(Self::Running { shutdown, task })
            }
        }
    }

    async fn finish(self) -> Result<()> {
        match self {
            Self::Disabled => Ok(()),
            Self::Running { shutdown, task } => {
                drop(shutdown);
                task.await?
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::rt::{Backend as _, Sandbox as _};

    #[tokio::test]
    async fn sandbox_can_be_started_more_than_once() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("podman");
        let log = temp.path().join("commands");
        // This shell script stands in for Podman. It logs the complete argv
        // for assertions, returns a stable container ID for `create`, reports
        // `stopped` for status checks, copies attached stdin to stdout with
        // `cat` during `start`, and makes cleanup commands succeed.
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    create) echo test-container; exit 0 ;;\n    ps) echo stopped; exit 0 ;;\n    start) cat; exit $? ;;\n    stop|kill|rm) exit 0 ;;\n  esac\ndone\nexit 1\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();

        let mut backend = Podman::init(Config {
            podman: binary,
            runtime: "runsc".into(),
            root: temp.path().join("state"),
            connect_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();
        let sandbox = backend
            .create(Spec {
                name: None,
                mounts: vec![OsString::from("type=volume,destination=/workspace,ro")],
                volumes: vec![OsString::from("cache:/cache:ro")],
                image: "example/image".into(),
                command: vec![OsString::from("command")],
                tty: false,
                upstream_dns: Ipv4Addr::new(1, 1, 1, 1),
                host_uds: HostUds::Open,
                overlay2: "root:self".into(),
            })
            .await
            .unwrap();
        let state = temp
            .path()
            .join("state")
            .join(sandbox.id().simple().to_string());
        assert!(!state.exists());

        let (mut input, input_reader) = io::duplex(64);
        let (output_writer, mut output) = io::duplex(64);
        let (error_writer, _errors) = io::duplex(64);
        input.write_all(b"through process").await.unwrap();
        input.shutdown().await.unwrap();
        let process = sandbox
            .start(Stdio::new(input_reader, output_writer, error_writer))
            .await
            .unwrap();
        assert!(state.join("proxy.sock").exists());
        process.join().await.unwrap();
        assert!(!state.exists());

        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"through process");

        let (input, _) = io::duplex(64);
        let (output, _) = io::duplex(64);
        let (errors, _) = io::duplex(64);
        sandbox
            .start(Stdio::new(input, output, errors))
            .await
            .unwrap()
            .stop()
            .await
            .unwrap();
        sandbox.remove().await.unwrap();

        let commands = fs::read_to_string(&log).unwrap();
        assert_eq!(
            commands
                .lines()
                .filter(|line| line.contains(" start "))
                .count(),
            2
        );
        assert!(
            commands
                .lines()
                .any(|command| command.contains("--mount type=volume,destination=/workspace,ro"))
        );
        assert!(
            commands
                .lines()
                .any(|command| command.contains("--volume cache:/cache:ro"))
        );
        assert_eq!(
            commands
                .lines()
                .filter(|line| line.contains(" create "))
                .count(),
            1
        );
        assert!(commands.lines().any(|command| command.contains("stop ")));
        assert!(commands.lines().any(|command| command.contains("rm ")));
    }

    #[tokio::test]
    async fn missing_host_uds_defaults_to_disabled() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("podman");
        let log = temp.path().join("commands");
        // This fake has the same command behavior, but its `--format=json`
        // response contains only the sandbox ID label. Omitting the gVisor
        // labels makes recovery exercise their Serde defaults.
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    create) echo test-container; exit 0 ;;\n    '--format=json') echo '[{{\"Names\":[\"test-container\"],\"Image\":\"example/image\",\"Id\":\"test-container\",\"Labels\":{{\"io.guardian.sandbox.id\":\"00000000-0000-0000-0000-000000000001\"}}}}]'; exit 0 ;;\n    '--format={{{{.State}}}}') echo stopped; exit 0 ;;\n    start) cat; exit $? ;;\n  esac\ndone\nexit 1\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();

        let mut backend = Podman::init(Config {
            podman: binary,
            runtime: "runsc".into(),
            root: temp.path().join("state"),
            connect_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();
        let sandbox = backend
            .create(Spec {
                name: None,
                mounts: Vec::new(),
                volumes: Vec::new(),
                image: "example/image".into(),
                command: vec![OsString::from("command")],
                tty: false,
                upstream_dns: Ipv4Addr::new(1, 1, 1, 1),
                host_uds: HostUds::None,
                overlay2: "root:self".into(),
            })
            .await
            .unwrap();
        let id = sandbox.id();
        drop(sandbox);

        let sandbox = backend.get(id).await.unwrap();
        let state = temp
            .path()
            .join("state")
            .join(sandbox.id().simple().to_string());
        let (mut input, input_reader) = io::duplex(64);
        let (output_writer, mut output) = io::duplex(64);
        let (error_writer, _) = io::duplex(64);
        input.write_all(b"without proxy").await.unwrap();
        input.shutdown().await.unwrap();
        let process = sandbox
            .start(Stdio::new(input_reader, output_writer, error_writer))
            .await
            .unwrap();

        assert!(state.exists());
        assert!(!state.join("proxy.sock").exists());
        process.join().await.unwrap();
        assert!(!state.exists());
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"without proxy");

        let commands = fs::read_to_string(&log).unwrap();
        assert!(commands.lines().any(|command| {
            command.contains("--label=io.guardian.sandbox.gvisor.host-uds=none")
        }));
        // Both create and start passes this flag
        assert_eq!(
            commands
                .lines()
                .filter(|command| command.contains("--runtime-flag=host-uds=none"))
                .count(),
            2
        );
        assert!(commands.lines().any(|command| {
            command.contains("--label=io.guardian.sandbox.gvisor.overlay2=root:self")
        }));
        // Both create and start passes this flag
        assert_eq!(
            commands
                .lines()
                .filter(|command| command.contains("--runtime-flag=overlay2=root:self"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn anonymous_read_only_mount_rejects_writes() {
        let temp = tempfile::tempdir().unwrap();
        let mut backend = Podman::init(Config {
            podman: "podman".into(),
            runtime: "runsc".into(),
            root: temp.path().join("state"),
            connect_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();
        let sandbox = backend
            .create(Spec {
                name: None,
                mounts: vec![OsString::from("type=volume,destination=/readonly,ro")],
                volumes: Vec::new(),
                image: "alpine:3.23.5".into(),
                command: vec![
                    OsString::from("sh"),
                    OsString::from("-c"),
                    OsString::from("! touch /readonly/file"),
                ],
                tty: false,
                upstream_dns: Ipv4Addr::new(1, 1, 1, 1),
                host_uds: HostUds::None,
                overlay2: "root:self".into(),
            })
            .await
            .unwrap();

        let code = sandbox
            .start(Stdio::inherit())
            .await
            .unwrap()
            .join()
            .await
            .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        sandbox.remove().await.unwrap();
    }
}

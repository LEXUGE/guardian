use std::{
    ffi::OsString,
    fmt,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use futures::StreamExt;
use podman_rest_client::{AttachFrame, AttachFrameStream};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    signal::unix::{self, SignalKind},
    sync::{oneshot, watch},
    task::JoinHandle,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    Error, Result,
    net::uds,
    rt::{self, Stdio},
};

pub mod api;
mod cli;
#[cfg(test)]
mod mock;
mod state;

use cli::{Cli, Create};
use state::{Root, State};

pub use cli::{Container, Labels};

const BOOTSTRAP: &str = "/run/guardian/bootstrap.sh";

#[derive(Debug, Clone)]
pub struct Config {
    pub podman: PathBuf,
    pub runtime: PathBuf,
    pub socket: PathBuf,
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
    pub upstream_dns: Ipv4Addr,
    pub host_uds: HostUds,
    pub overlay2: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecSpec {
    pub command: Vec<String>,
    pub env: Vec<String>,
    pub tty: bool,
    pub user: Option<String>,
    pub working_dir: Option<String>,
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
    exec: Arc<api::ExecApi>,
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
        let root = Root::open(config.root)?;
        Ok(Self {
            context: Arc::new(Context {
                cli: Cli::new(config.podman, config.runtime),
                exec: Arc::new(api::ExecApi::new(config.socket)?),
                root,
                proxy: uds::Config {
                    connect_timeout: config.connect_timeout,
                },
                stop_timeout: config.stop_timeout,
            }),
        })
    }

    async fn create(&mut self, spec: Self::Spec) -> Result<Self::Sandbox> {
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
        let mut env = vec![format!("GUARDIAN_UPSTREAM_DNS={}", spec.upstream_dns)];
        if spec.host_uds == HostUds::Open {
            env.extend(
                [
                    "ALL_PROXY=socks5h://127.0.0.1:1080",
                    "all_proxy=socks5h://127.0.0.1:1080",
                    "HTTP_PROXY=socks5h://127.0.0.1:1080",
                    "http_proxy=socks5h://127.0.0.1:1080",
                    "HTTPS_PROXY=socks5h://127.0.0.1:1080",
                    "https_proxy=socks5h://127.0.0.1:1080",
                    "NO_PROXY=127.0.0.1,localhost",
                    "no_proxy=127.0.0.1,localhost",
                ]
                .map(str::to_owned),
            );
        }

        let command = [OsString::from(BOOTSTRAP)];
        let name = spec
            .name
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
                command: &command,
                stop_timeout: self.context.stop_timeout,
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
            active: None,
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
            active: None,
        })
    }
}

pub struct Sandbox {
    context: Arc<Context>,
    id: Uuid,
    container_id: String,
    host_uds: HostUds,
    overlay2: String,
    active: Option<Active>,
}

impl rt::Sandbox for Sandbox {
    type Id = Uuid;
    type Process = Process;
    type ExecSpec = ExecSpec;
    type Status = Status;

    fn id(&self) -> Uuid {
        self.id
    }

    async fn status(&self) -> Result<Self::Status> {
        self.context.cli.status(&self.container_id).await
    }

    async fn start(&mut self) -> Result<()> {
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
        self.context
            .cli
            .start(&self.container_id, self.host_uds, &self.overlay2)
            .await?;

        info!(sandbox_id = %self.id, container_id = %self.container_id, "sandbox started");

        self.active = Some(Active {
            context: Arc::clone(&self.context),
            container_id: self.container_id.clone(),
            proxy,
            state,
        });
        Ok(())
    }

    async fn exec(&self, spec: ExecSpec, stdio: Stdio) -> Result<Self::Process> {
        // we should NOT check if active is Some since it could be managed by another `Sandbox`
        // instance.
        if !self.context.root.is_acquired(self.id)? {
            return Err(Error::Podman(format!(
                "sandbox {} has no running Guardian owner",
                self.id
            )));
        }
        if self.status().await? != Status::Running {
            return Err(Error::Podman(format!(
                "container {} is not running",
                self.container_id
            )));
        }

        let exec = self.context.exec.run(&self.container_id, &spec).await?;
        let (stdio, stdio_done) = StdioTask::spawn(stdio, exec.io, spec.tty);
        let exec = ExecTask::spawn(Arc::clone(&self.context.exec), exec.id, stdio_done);

        Ok(Process { exec, stdio })
    }

    async fn stop(self) -> Result<()> {
        self.active
            .ok_or(Error::Podman(format!(
                "sandbox {} has no required background tasks",
                self.id
            )))?
            .stop()
            .await
    }

    async fn join(self) -> Result<()> {
        self.active
            .ok_or(Error::Podman(format!(
                "sandbox {} has no required background tasks",
                self.id
            )))?
            .join()
            .await
    }

    async fn kill(&self) -> Result<()> {
        self.context.cli.kill(&self.container_id).await
    }

    async fn remove(self) -> Result<()> {
        // makes sure there are no other `Sandbox` instance owning the state
        // and prevents another instance starting the sandbox while we remove it
        let _lock = self.context.root.acquire(self.id)?;
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

#[must_use]
pub struct Active {
    context: Arc<Context>,
    container_id: String,
    proxy: ProxyTask,
    state: State,
}

impl Active {
    async fn finish(self) -> Result<()> {
        self.proxy.finish().await?;
        drop(self.state);
        Ok(())
    }

    async fn stop(self) -> Result<()> {
        let id = self.container_id.clone();
        self.context
            .cli
            .stop(&self.container_id, self.context.stop_timeout)
            .await?;
        self.finish().await?;
        info!(container_id = %id, "sandbox stopped");
        Ok(())
    }

    async fn join(self) -> Result<()> {
        let mut interrupt = unix::signal(SignalKind::interrupt())?;
        let mut terminate = unix::signal(SignalKind::terminate())?;
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        self.stop().await
    }
}

#[must_use]
pub struct Process {
    exec: ExecTask,
    stdio: StdioTask,
}

impl Process {
    async fn wait(&mut self) -> Result<ExitCode> {
        enum Event {
            Complete(Result<Completion>),
            Signal(SignalKind),
        }

        let mut interrupt = unix::signal(SignalKind::interrupt())?;
        let mut terminate = unix::signal(SignalKind::terminate())?;
        let event = tokio::select! {
            result = &mut self.exec.task => Event::Complete(result?),
            _ = interrupt.recv() => Event::Signal(SignalKind::interrupt()),
            _ = terminate.recv() => Event::Signal(SignalKind::terminate()),
        };

        match event {
            Event::Complete(result) => match result? {
                Completion::Exited(code) => Ok(code),
                // this arm is pretty unreacheable
                Completion::Cancelled => Err(Error::Podman(
                    "exec was cancelled (not from `Process`)".into(),
                )),
            },
            Event::Signal(signal) => {
                info!(signal = signal.as_raw_value(), "cancelling foreground exec");
                self.exec.stop();
                match (&mut self.exec.task).await?? {
                    // already exited
                    Completion::Exited(code) => Ok(code),
                    // successfully aborted
                    Completion::Cancelled => Ok(ExitCode::from(
                        // Shells report signal termination as 128 plus the signal number:
                        // SIGINT is 2 and SIGTERM is 15.
                        if signal.as_raw_value() == SignalKind::interrupt().as_raw_value() {
                            130
                        } else {
                            143
                        },
                    )),
                }
            }
        }
    }
}

impl rt::Process for Process {
    async fn stop(mut self) -> Result<()> {
        self.exec.stop();
        match (&mut self.exec.task).await?? {
            Completion::Exited(_) | Completion::Cancelled => {}
        }
        self.stdio.finish().await;
        Ok(())
    }

    async fn join(mut self) -> Result<ExitCode> {
        let code = self.wait().await?;
        self.stdio.finish().await;
        Ok(code)
    }
}

enum Completion {
    Exited(ExitCode),
    Cancelled,
}

struct ExecTask {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<Completion>>,
}

impl ExecTask {
    fn spawn(
        api: Arc<api::ExecApi>,
        exec_id: String,
        mut stdio_done: oneshot::Receiver<Result<()>>,
    ) -> Self {
        let (shutdown, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                result = &mut stdio_done => {
                    match result {
                        // successfully completed
                        Ok(Ok(())) => {}
                        // one copying task finished with failure
                        Ok(Err(error)) => {
                            // ignore cascading removal failure
                            let _ = api.remove(&exec_id).await;
                            return Err(error);
                        }
                        // failed to receive the completion result from
                        Err(_) => {
                            // ignore cascading removal failure
                            let _ = api.remove(&exec_id).await;
                            return Err(Error::Podman(format!(
                                "stdio task ended without reporting exec {exec_id} completion"
                            )));
                        }
                    }

                    let code = match api.exit_code(&exec_id).await? {
                        Some(code) => code,
                        None => {
                            let _ = api.remove(&exec_id).await;
                            return Err(Error::Podman(format!(
                                "exec {exec_id} attachment closed without exit code reported"
                            )));
                        }
                    };
                    api.remove(&exec_id).await?;
                    Ok(Completion::Exited(code))
                }
                _ = receiver.changed() => {
                    api.remove(&exec_id).await?;
                    // opportunistically wait for IO completion
                    let _ = stdio_done.await;
                    Ok(Completion::Cancelled)
                }
            }
        });
        Self { shutdown, task }
    }

    fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}

struct StdioTask {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl StdioTask {
    // spawns a bidirectional copying task and notifies through a oneshot receiver when it's done.
    fn spawn<T>(stdio: Stdio, io: T, tty: bool) -> (Self, oneshot::Receiver<Result<()>>)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Stdio {
            mut stdin,
            mut stdout,
            mut stderr,
        } = stdio;
        let (mut reader, mut writer) = io::split(io);
        let (shutdown, mut receiver) = watch::channel(false);
        let (done, stdio_done) = oneshot::channel();
        let task = tokio::spawn(async move {
            let input = async move {
                if let Err(error) = async {
                    io::copy(&mut stdin, &mut writer).await?;
                    writer.shutdown().await
                }
                .await
                {
                    warn!(%error, "stdin copy failed");
                }
            };
            let output = async move {
                if tty {
                    // if tty then all channels copied to stdout
                    io::copy(&mut reader, &mut stdout).await?;
                    stdout.flush().await
                } else {
                    let mut frames = AttachFrameStream::new(reader);
                    while let Some(frame) = frames.next().await {
                        match frame? {
                            // Podman's own implementation also forwards channel 0 output into stdin
                            AttachFrame::Stdin(bytes) | AttachFrame::Stdout(bytes) => {
                                stdout.write_all(&bytes).await?;
                            }
                            AttachFrame::Stderr(bytes) => stderr.write_all(&bytes).await?,
                        }
                    }
                    stdout.flush().await?;
                    stderr.flush().await
                }
            };

            tokio::pin!(input);
            tokio::pin!(output);
            let result = tokio::select! {
                // when input EOF, wait for the process to finish
                _ = input.as_mut() => output.await,
                // when process finishes, return the result directly
                result = output.as_mut() => result,
                // signal tells us to stop the copying.
                _ = receiver.changed() => output.await,
            };
            // finished copying
            let _ = done.send(result.map_err(Error::from));
        });
        (Self { shutdown, task }, stdio_done)
    }

    async fn finish(self) {
        drop(self.shutdown);
        // wait till shutdown
        let _ = self.task.await;
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::rt::{Backend as _, Process as _, Sandbox as _};

    use super::mock::MockPodman;

    // manually assemble the frame using podman protocol
    fn frame(stream: u8, bytes: &[u8]) -> Vec<u8> {
        let mut frame = vec![stream, 0, 0, 0];
        frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(bytes);
        frame
    }

    fn another_instance(sandbox: &Sandbox) -> Sandbox {
        Sandbox {
            context: Arc::clone(&sandbox.context),
            id: sandbox.id,
            container_id: sandbox.container_id.clone(),
            host_uds: sandbox.host_uds,
            overlay2: sandbox.overlay2.clone(),
            active: None,
        }
    }

    #[tokio::test]
    // single io stream from podman API should demux into stdout and stderr
    async fn stdio_demultiplexes_exec_output() {
        let (io, mut guardian_end) = io::duplex(128);
        let (mut input, input_reader) = io::duplex(16);
        let (stdout_writer, mut stdout) = io::duplex(16);
        let (stderr_writer, mut stderr) = io::duplex(16);
        input.shutdown().await.unwrap();

        let (stdio, done) = StdioTask::spawn(
            Stdio::new(input_reader, stdout_writer, stderr_writer),
            io,
            false,
        );
        guardian_end.write_all(&frame(1, b"out")).await.unwrap();
        guardian_end.write_all(&frame(2, b"err")).await.unwrap();
        guardian_end.shutdown().await.unwrap();

        done.await.unwrap().unwrap();
        stdio.finish().await;
        let mut output = Vec::new();
        let mut errors = Vec::new();
        stdout.read_to_end(&mut output).await.unwrap();
        stderr.read_to_end(&mut errors).await.unwrap();
        assert_eq!(output, b"out");
        assert_eq!(errors, b"err");
    }

    #[tokio::test]
    async fn stdio_copies_tty_output_without_framing() {
        let (io, mut guardian_end) = io::duplex(64);
        let (mut input, input_reader) = io::duplex(16);
        let (stdout_writer, mut stdout) = io::duplex(16);
        let (stderr_writer, _stderr) = io::duplex(16);
        input.write_all(b"input").await.unwrap();
        input.shutdown().await.unwrap();

        let (stdio, done) = StdioTask::spawn(
            Stdio::new(input_reader, stdout_writer, stderr_writer),
            io,
            true,
        );
        let mut received = [0; 5];
        guardian_end.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"input");
        guardian_end.write_all(b"terminal").await.unwrap();
        guardian_end.shutdown().await.unwrap();

        done.await.unwrap().unwrap();
        stdio.finish().await;
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"terminal");
    }

    #[tokio::test]
    async fn sandbox_can_be_started_more_than_once() {
        let mock = MockPodman::new();
        let root = mock.state_root();
        let mut backend = Podman::init(Config {
            podman: mock.binary(),
            runtime: "runsc".into(),
            socket: mock.socket(),
            root: root.clone(),
            connect_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();
        let mut sandbox = backend
            .create(Spec {
                name: None,
                mounts: vec![OsString::from("type=volume,destination=/workspace,ro")],
                volumes: vec![OsString::from("cache:/cache:ro")],
                image: "example/image".into(),
                upstream_dns: Ipv4Addr::new(1, 1, 1, 1),
                host_uds: HostUds::Open,
                overlay2: "root:self".into(),
            })
            .await
            .unwrap();
        let state = root.join(sandbox.id().simple().to_string());
        assert!(!state.exists());

        let mut second = another_instance(&sandbox);
        sandbox.start().await.unwrap();
        assert!(state.join("proxy.sock").exists());
        sandbox.stop().await.unwrap();
        assert!(!state.exists());

        let removal = another_instance(&second);
        second.start().await.unwrap();
        second.stop().await.unwrap();
        removal.remove().await.unwrap();

        let commands = mock.commands();
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
        assert!(commands.contains("--env=HTTPS_PROXY=socks5h://127.0.0.1:1080"));
        assert!(commands.contains("--env=NO_PROXY=127.0.0.1,localhost"));
        assert!(!commands.contains("--interactive"));
        assert!(!commands.contains("--tty"));
        assert!(!commands.contains("--attach"));
    }

    #[tokio::test]
    async fn missing_host_uds_defaults_to_disabled() {
        let mock = MockPodman::new();
        mock.set_containers(
            r#"[{"Names":["test-container"],"Image":"example/image","Id":"test-container","Labels":{"io.guardian.sandbox.id":"00000000-0000-0000-0000-000000000001"}}]"#,
        );
        let root = mock.state_root();
        let mut backend = Podman::init(Config {
            podman: mock.binary(),
            runtime: "runsc".into(),
            socket: mock.socket(),
            root: root.clone(),
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
                upstream_dns: Ipv4Addr::new(1, 1, 1, 1),
                host_uds: HostUds::None,
                overlay2: "root:self".into(),
            })
            .await
            .unwrap();
        let id = sandbox.id();
        drop(sandbox);

        let mut sandbox = backend.get(id).await.unwrap();
        let state = root.join(sandbox.id().simple().to_string());
        sandbox.start().await.unwrap();
        assert!(state.exists());
        assert!(!state.join("proxy.sock").exists());
        sandbox.stop().await.unwrap();
        assert!(!state.exists());

        let commands = mock.commands();
        assert!(!commands.contains("--env=ALL_PROXY="));
        assert!(!commands.contains("--env=HTTPS_PROXY="));
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
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").unwrap();
        let mut backend = Podman::init(Config {
            podman: "podman".into(),
            runtime: "/run/current-system/sw/bin/runsc".into(),
            socket: PathBuf::from(runtime).join("podman/podman.sock"),
            root: temp.path().join("state"),
            connect_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();
        let mut sandbox = backend
            .create(Spec {
                name: None,
                mounts: vec![OsString::from("type=volume,destination=/readonly,ro")],
                volumes: Vec::new(),
                image: "alpine:3.23.5".into(),
                upstream_dns: Ipv4Addr::new(1, 1, 1, 1),
                host_uds: HostUds::None,
                overlay2: "root:self".into(),
            })
            .await
            .unwrap();
        let id = sandbox.id();

        sandbox.start().await.unwrap();
        let code = sandbox
            .exec(
                ExecSpec {
                    command: vec!["sh".into(), "-c".into(), "! touch /readonly/file".into()],
                    ..Default::default()
                },
                Stdio::new(tokio::io::empty(), tokio::io::sink(), tokio::io::sink()),
            )
            .await
            .unwrap()
            .join()
            .await
            .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        sandbox.stop().await.unwrap();
        backend.get(id).await.unwrap().remove().await.unwrap();
    }
}

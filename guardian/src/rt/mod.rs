#![allow(async_fn_in_trait)]

use std::{pin::Pin, process::ExitCode};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::signal::unix::SignalKind;

use crate::Result;

pub mod podman;

pub trait Backend: Sized {
    type Config;
    type Spec;
    type Id;
    type Sandbox: Sandbox<Id = Self::Id>;

    async fn init(config: Self::Config) -> Result<Self>;
    // creates a persistent sandbox
    async fn create(&mut self, spec: Self::Spec) -> Result<Self::Sandbox>;
    // recovers a sandbox by ID
    async fn get(&self, id: Self::Id) -> Result<Self::Sandbox>;
}

pub trait Sandbox {
    type Id;
    type Process: Process;
    type Status;

    fn id(&self) -> Self::Id;
    async fn status(&self) -> Result<Self::Status>;
    // requires a non-running sandbox and returns one attached execution.
    async fn start(&self, stdio: Stdio) -> Result<Self::Process>;
    // force-stops the sandbox via Podman
    async fn kill(&self) -> Result<()>;
    // deletes the sandbox
    async fn remove(self) -> Result<()>;
}

pub trait Process {
    // sends a signal to the process
    async fn signal(&mut self, signal: SignalKind) -> Result<()>;
    // stops the sandbox via podman and waits till the execution finishes without handling signals.
    async fn stop(self) -> Result<ExitCode>;
    // handles the foreground signal and waits till the execution finishes
    async fn join(self) -> Result<ExitCode>;
}

pub enum Stdio {
    Inherit,
    Redirect {
        stdin: Pin<Box<dyn AsyncRead + Send + 'static>>,
        stdout: Pin<Box<dyn AsyncWrite + Send + 'static>>,
        stderr: Pin<Box<dyn AsyncWrite + Send + 'static>>,
    },
}

impl Stdio {
    pub fn new<I, O, E>(stdin: I, stdout: O, stderr: E) -> Self
    where
        I: AsyncRead + Send + 'static,
        O: AsyncWrite + Send + 'static,
        E: AsyncWrite + Send + 'static,
    {
        Self::Redirect {
            stdin: Box::pin(stdin),
            stdout: Box::pin(stdout),
            stderr: Box::pin(stderr),
        }
    }

    pub fn inherit() -> Self {
        Self::Inherit
    }
}

#![allow(async_fn_in_trait)]

use crate::Result;
use std::{pin::Pin, process::ExitCode};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod podman;

pub trait Backend: Sized {
    type Config;
    type Spec;
    type Id;
    type Sandbox: Sandbox<Id = Self::Id>;

    async fn init(config: Self::Config) -> Result<Self>;
    // Creates a persistent sandbox
    async fn create(&mut self, spec: Self::Spec) -> Result<Self::Sandbox>;
    // Recovers a sandbox by ID
    async fn get(&self, id: Self::Id) -> Result<Self::Sandbox>;
}

pub trait Sandbox {
    type Id;
    type Process: Process;
    type ExecSpec;
    type Status;

    fn id(&self) -> Self::Id;
    async fn status(&self) -> Result<Self::Status>;

    // Starts the persistent sandbox and acquires its Guardian resources.
    async fn start(&mut self) -> Result<()>;
    // Stops the sandbox and releases its Guardian resources.
    async fn stop(self) -> Result<()>;
    // Listen for foreground signals and stops the sandbox on signals.
    async fn join(self) -> Result<()>;

    // Starts one command in a running sandbox.
    async fn exec(&self, spec: Self::ExecSpec, stdio: Stdio) -> Result<Self::Process>;

    // Force-stops the sandbox.
    async fn kill(&self) -> Result<()>;
    // Deletes the sandbox.
    async fn remove(self) -> Result<()>;
}

pub trait Process {
    // Cancels this command without handling foreground signals.
    async fn stop(self) -> Result<()>;
    // Handles foreground signals and waits for this command to finish.
    async fn join(self) -> Result<ExitCode>;
}

pub type StdioInput = Pin<Box<dyn AsyncRead + Send + 'static>>;
pub type StdioOutput = Pin<Box<dyn AsyncWrite + Send + 'static>>;

pub struct Stdio {
    pub stdin: StdioInput,
    pub stdout: StdioOutput,
    pub stderr: StdioOutput,
}

impl Stdio {
    pub fn new<I, O, E>(stdin: I, stdout: O, stderr: E) -> Self
    where
        I: AsyncRead + Send + 'static,
        O: AsyncWrite + Send + 'static,
        E: AsyncWrite + Send + 'static,
    {
        Self {
            // FIXME: Why is pin needed?
            stdin: Box::pin(stdin),
            stdout: Box::pin(stdout),
            stderr: Box::pin(stderr),
        }
    }
}

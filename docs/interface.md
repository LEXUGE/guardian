# Runtime interface

See `guardian/src/rt/mod.rs` for the current interface.

```rust
pub trait Backend: Sized {
    type Config;
    type Spec;
    type Sandbox: Sandbox;

    async fn init(config: Self::Config) -> Result<Self>;
    async fn create(&mut self, spec: Self::Spec) -> Result<Self::Sandbox>;
    async fn get(&self, id: Uuid) -> Result<Self::Sandbox>;
}

pub trait Sandbox {
    type Process: Process;
    type Status;

    fn id(&self) -> Uuid;
    async fn status(&self) -> Result<Self::Status>;
    async fn start(&self, stdio: Stdio) -> Result<Self::Process>;
    async fn kill(&self) -> Result<()>;
    async fn remove(self) -> Result<()>;
}

pub trait Process {
    async fn signal(&mut self, signal: SignalKind) -> Result<()>;
    async fn stop(self) -> Result<ExitCode>;
    async fn join(self) -> Result<ExitCode>;
}
```

`create()` creates a persistent sandbox and `get()` recovers it by UUID. `start()` requires a non-running sandbox and returns one attached execution. `kill()` force-stops it; only `remove()` deletes it.

`signal()` sends a signal to the guest. `stop()` stops the sandbox without handling foreground signals. `join()` handles foreground signals and waits for completion. Both consume `Process`; a non-zero exit status is returned as `Ok(ExitCode)`.

## I/O

```rust
pub enum Stdio {
    Inherit,
    Redirect {
        stdin: Pin<Box<dyn AsyncRead + Send + 'static>>,
        stdout: Pin<Box<dyn AsyncWrite + Send + 'static>>,
        stderr: Pin<Box<dyn AsyncWrite + Send + 'static>>,
    },
}
```

`Inherit` passes OS descriptors directly. `Redirect` copies through Tokio I/O; shutdown cancels stdin and drains stdout and stderr on a best-effort basis.

Backends own their network implementation. Execution failure never implicitly removes a persistent sandbox.

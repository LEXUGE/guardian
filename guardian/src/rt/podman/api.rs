//! Small Podman REST client for exec sessions.

use std::{path::Path, process::ExitCode};

use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use podman_rest_client::{
    PodmanRestClient,
    v5::{Client as _, models},
};
use serde::Serialize;

use super::ExecSpec;
use crate::{Error, Result};

// to be compliant with podman_rest_client's API version
const API_VERSION: &str = "v5.1.0";

/// Podman exec ID and its bidirectional io.
pub struct Exec {
    pub id: String,
    pub io: TokioIo<Upgraded>,
}

/// Composite client that manages the exec lifecylce using `podman_rest_client` and a custom force
/// remove endpoint.
pub struct ExecApi {
    rest: PodmanRestClient,
    control: ExecControl,
}

impl ExecApi {
    /// Creates a client for a local Podman Unix socket.
    pub fn new(socket: impl AsRef<Path>) -> Result<Self> {
        let socket = socket.as_ref();
        let socket_string = socket.to_str().ok_or_else(|| {
            Error::Config(format!(
                "Podman socket path is not valid UTF-8: {}",
                socket.display()
            ))
        })?;

        Ok(Self {
            rest: PodmanRestClient::new_unix(socket_string),
            control: ExecControl::new(socket)?,
        })
    }

    async fn create(&self, container_id: &str, spec: &ExecSpec) -> Result<String> {
        let response = self
            .rest
            .exec()
            .container_exec_libpod(
                container_id,
                models::ContainerExecLibpodBody {
                    attach_stdin: Some(true),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(spec.command.clone()),
                    env: (!spec.env.is_empty()).then(|| spec.env.clone()),
                    privileged: Some(false),
                    tty: Some(spec.tty),
                    user: spec.user.clone(),
                    working_dir: spec.working_dir.clone(),
                    ..Default::default()
                },
            )
            .await?;

        Ok(response.id)
    }

    async fn start(&self, id: &str, tty: bool) -> Result<TokioIo<Upgraded>> {
        Ok(self
            .rest
            .exec()
            .exec_start_libpod(
                id,
                models::ExecStartLibpodBody {
                    // attaching IO is required for us
                    detach: Some(false),
                    tty: Some(tty),
                    ..Default::default()
                },
            )
            .await?)
    }

    /// Creates, starts, and attaches to one exec session.
    pub async fn run(&self, container_id: &str, spec: &ExecSpec) -> Result<Exec> {
        let id = self.create(container_id, spec).await?;
        let io = match self.start(&id, spec.tty).await {
            Ok(io) => io,
            Err(error) => {
                // ignore the result of removal cause the session might already be gone.
                let _ = self.remove(&id).await;
                return Err(error);
            }
        };
        Ok(Exec { id, io })
    }

    /// Returns `None` while the exec is running or its exit code is unavailable
    pub async fn exit_code(&self, id: &str) -> Result<Option<ExitCode>> {
        // The generated native endpoint has no response model. The compatible
        // endpoint addresses the same Podman exec ID and has the correct model.
        let status = self.rest.exec_compat().exec_inspect(id).await?;
        Ok(match (status.running, status.exit_code) {
            // report `None` if status aren't available or still running
            (None, _) | (_, None) | (Some(true), _) => None,
            (Some(false), Some(code)) => {
                let code = u8::try_from(code)
                    .map_err(|_| Error::Podman(format!("invalid exec exit code: {code}")))?;
                Some(ExitCode::from(code))
            }
        })
    }

    /// Stops, if necessary, and removes one exec session.
    pub async fn remove(&self, id: &str) -> Result<()> {
        self.control.remove(id).await
    }
}

#[derive(Clone)]
struct ExecControl {
    client: reqwest::Client,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RemoveBody {
    force: bool,
}

impl ExecControl {
    fn new(socket: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .unix_socket(socket.as_ref().to_owned())
                .build()?,
        })
    }

    async fn remove(&self, id: &str) -> Result<()> {
        let response = self
            .client
            .post(format!(
                "http://localhost/{API_VERSION}/libpod/exec/{id}/remove"
            ))
            .json(&RemoveBody { force: true })
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;

        status
            .is_success()
            .then_some(())
            .ok_or(Error::Podman(format!(
                "cannot remove exec {id} ({status}): {body}"
            )))
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    use super::*;

    #[tokio::test]
    async fn remove_sends_the_right_request() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("podman.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
                if request.ends_with(br#"{"Force":true}"#) {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("POST /v5.1.0/libpod/exec/exec-id/remove HTTP/1.1\r\n"));
            assert!(request.contains("content-type: application/json\r\n"));
            assert!(request.contains("content-length: 14\r\n"));
            assert!(request.ends_with(r#"{"Force":true}"#));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        ExecApi::new(&socket)
            .unwrap()
            .remove("exec-id")
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn remove_reports_the_api_error_body() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("podman.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 409 Conflict\r\ncontent-length: 21\r\n\r\nexec is still running",
                )
                .await
                .unwrap();
        });

        let error = ExecApi::new(&socket)
            .unwrap()
            .remove("exec-id")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exec is still running"));
        server.await.unwrap();
    }
}

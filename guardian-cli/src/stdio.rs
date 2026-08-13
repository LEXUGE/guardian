use std::{
    io::{self, IsTerminal as _, Read},
    thread,
};

use bytes::Bytes;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use guardian::{Result, rt::Stdio};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;
use tracing::warn;

const BUFFER_SIZE: usize = 8 * 1024;
const CHANNEL_CAPACITY: usize = 8;

type Stdin = StreamReader<ReceiverStream<io::Result<Bytes>>, Bytes>;

/// Reads inherited stdin on a detached blocking thread.
///
/// Dropping the returned reader closes the channel. A thread already blocked in
/// `read` exits after that read returns; it is not owned by the Tokio runtime.
fn stdin() -> io::Result<Stdin> {
    forward(io::stdin())
}

// forward bytes from a blocking reader via an async stream on another thread so it doesn't block
// the main thread on shutdown.
fn forward<R>(mut reader: R) -> io::Result<Stdin>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
    thread::Builder::new()
        .name("guardian-stdin".into())
        .spawn(move || {
            loop {
                let mut buffer = vec![0; BUFFER_SIZE];
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        buffer.truncate(read);
                        if sender.blocking_send(Ok(Bytes::from(buffer))).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = sender.blocking_send(Err(error));
                        break;
                    }
                }
            }
        })?;

    Ok(StreamReader::new(ReceiverStream::new(receiver)))
}

pub struct TerminalGuard {
    raw: bool,
}

impl TerminalGuard {
    fn enter(tty: bool) -> io::Result<Self> {
        let raw = tty && io::stdin().is_terminal();
        if raw {
            enable_raw_mode()?;
        }
        Ok(Self { raw })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.raw
            && let Err(error) = disable_raw_mode()
        {
            warn!(%error, "failed to restore terminal mode");
        }
    }
}

/// Builds process stdio for one foreground command.
///
/// `tty` puts an inherited terminal into raw mode until the returned guard is
/// dropped. Podman allocates the guest terminal from the corresponding
/// `ExecSpec::tty` value.
pub fn inherit(tty: bool) -> Result<(Stdio, TerminalGuard)> {
    Ok((
        Stdio::new(stdin()?, tokio::io::stdout(), tokio::io::stderr()),
        TerminalGuard::enter(tty)?,
    ))
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt as _;

    use super::*;

    #[tokio::test]
    async fn forwards_bytes_and_eof_from_blocking_reader() {
        let mut input = forward(io::Cursor::new(b"script\n".to_vec())).unwrap();
        let mut output = Vec::new();
        input.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"script\n");
    }
}

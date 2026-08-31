//! SOCKS5 over a per-sandbox Unix domain socket.

use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use fast_socks5::{
    ReplyError, Socks5Command, server::Socks5ServerProtocol, util::target_addr::TargetAddr,
};
use tokio::{
    net::{TcpStream, UnixListener, UnixStream, lookup_host},
    sync::watch,
    task::JoinSet,
    time::timeout,
};
use tracing::{info, warn};

use crate::{Result, net::policy::Policy};

const MAX_CONNECTIONS: usize = 256;

enum ConnectError {
    Denied,
    Io(io::Error),
}

impl From<io::Error> for ConnectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub connect_timeout: Duration,
    pub policy: Policy,
}

pub struct Proxy {
    listener: UnixListener,
    bind_path: PathBuf,
    config: Arc<Config>,
}

impl Proxy {
    pub fn bind(path: &Path, config: Config) -> Result<Self> {
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        Ok(Self {
            listener,
            bind_path: path.to_owned(),
            config: Arc::new(config),
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    if connections.len() >= MAX_CONNECTIONS {
                        drop(stream);
                        continue;
                    }
                    let bind_path = self.bind_path.clone();
                    let config = Arc::clone(&self.config);
                    connections.spawn(async move {
                        if let Err(error) = Self::connection(stream, &config, &bind_path).await {
                            warn!(bind_path = %bind_path.display(), %error, "SOCKS connection failed");
                        }
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        warn!(%error, "SOCKS connection task failed");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }

        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    async fn connection(stream: UnixStream, config: &Config, bind_path: &Path) -> Result<()> {
        let protocol = Socks5ServerProtocol::accept_no_auth(stream).await?;
        let (protocol, command, target) = protocol.read_command().await?;
        if command != Socks5Command::TCPConnect {
            protocol
                .reply_error(&ReplyError::CommandNotSupported)
                .await?;
            return Ok(());
        }

        info!(
            bind_path = %bind_path.display(),
            ?target,
            "SOCKS connection started"
        );

        let (mut outbound, remote) = match timeout(
            config.connect_timeout,
            Self::connect(&target, &config.policy),
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            Ok(Err(ConnectError::Denied)) => {
                info!(bind_path = %bind_path.display(), ?target, "SOCKS connection denied");
                protocol
                    .reply_error(&ReplyError::ConnectionNotAllowed)
                    .await?;
                return Ok(());
            }
            Ok(Err(ConnectError::Io(error))) => {
                protocol.reply_error(&ReplyError::GeneralFailure).await?;
                return Err(error.into());
            }
            Err(_) => {
                protocol.reply_error(&ReplyError::TtlExpired).await?;
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out").into(),
                );
            }
        };

        let mut inbound = protocol.reply_success(outbound.local_addr()?).await?;
        let (guest_to_host, host_to_guest) =
            tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        info!(
            bind_path = %bind_path.display(),
            ?target,
            %remote,
            guest_to_host,
            host_to_guest,
            "SOCKS connection stopped"
        );
        Ok(())
    }

    async fn connect(
        target: &TargetAddr,
        policy: &Policy,
    ) -> std::result::Result<(TcpStream, std::net::SocketAddr), ConnectError> {
        let remote = match target {
            TargetAddr::Ip(address) => policy
                .cidrs
                .allows(address.ip(), address.port())
                .then_some(*address)
                .ok_or(ConnectError::Denied)?,
            TargetAddr::Domain(domain, port) => {
                if !policy.domains.allows(domain, *port) {
                    return Err(ConnectError::Denied);
                }
                lookup_host((domain.as_str(), *port))
                    .await?
                    .find(|address| !policy.cidrs.denies(address.ip(), *port))
                    .ok_or(ConnectError::Denied)?
            }
        };
        Ok((TcpStream::connect(remote).await?, remote))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UnixStream},
    };

    use super::*;

    #[tokio::test]
    async fn end_to_end_connection_test() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("proxy.sock");
        let server = Proxy::bind(
            &socket_path,
            Config {
                connect_timeout: Duration::from_secs(1),
                policy: toml::from_str("[cidrs]\nallow = ['127.0.0.0/8']").unwrap(),
            },
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777,
            0o666
        );
        let (shutdown, receiver) = watch::channel(false);
        let server_task = tokio::spawn(server.run(receiver));

        // An echo server that mocks the remote destination
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buffer = [0u8; 128];
            let read = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..read]).await.unwrap();
        });

        // client authenticate with the SOCKS server over UDS
        let mut client = UnixStream::connect(socket_path).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0]);

        let mut request = vec![5, 1, 0, 1];
        request.extend(Ipv4Addr::LOCALHOST.octets());
        request.extend(echo_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..2], &[5, 0]);

        // sends over the actual bytes
        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        client.shutdown().await.unwrap();

        echo_task.await.unwrap();
        drop(shutdown);
        server_task.await.unwrap().unwrap();
    }
}

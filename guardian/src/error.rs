use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Podman error: {0}")]
    Podman(String),
    #[error("SOCKS error: {0}")]
    Socks(#[from] fast_socks5::SocksError),
    #[error("SOCKS server error: {0}")]
    SocksServer(#[from] fast_socks5::server::SocksServerError),
    #[error("task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

pub type Result<T> = std::result::Result<T, Error>;

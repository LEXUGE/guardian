mod config;
mod stdio;

use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, process::ExitCode, sync::Mutex};

use clap::Parser;
use config::{Cli, Command};
use guardian::{
    Result,
    rt::{Backend as _, Process as _, Sandbox as _, podman::Podman},
};
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    let Cli {
        log_file,
        runtime,
        command,
    } = Cli::parse();
    let config = match runtime.into_config() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("guardian: {error}");
            return ExitCode::from(125);
        }
    };
    let log_file = log_file.unwrap_or_else(|| config.root.join("log.jsonl"));
    let backend = match Podman::init(config).await {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("guardian: {error}");
            return ExitCode::from(125);
        }
    };
    let log = match OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_file)
    {
        Ok(log) => log,
        Err(error) => {
            eprintln!("cannot open {}: {error}", log_file.display());
            return ExitCode::from(125);
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("guardian=info")),
        )
        .json()
        .with_writer(Mutex::new(log))
        .init();

    let result = run(backend, command).await;
    match result {
        Ok(code) => code,
        Err(error) => {
            error!(error = %error, "guardian failed");
            ExitCode::from(125)
        }
    }
}

async fn run(mut backend: Podman, command: Command) -> Result<ExitCode> {
    match command {
        Command::Create(args) => {
            let sandbox = backend.create(args.into_spec()).await?;
            println!("{}", sandbox.id());
            Ok(ExitCode::SUCCESS)
        }
        Command::Run {
            create,
            exec,
            ephemeral,
        } => {
            let exec = exec.into_spec();
            let mut sandbox = backend.create(create.into_spec()).await?;
            let id = sandbox.id();
            eprintln!("guardian: sandbox {id}");
            let result = async {
                sandbox.start().await?;
                let (stdio, terminal) = match stdio::inherit(exec.tty) {
                    Ok(stdio) => stdio,
                    Err(error) => {
                        if let Err(cleanup_error) = sandbox.stop().await {
                            warn!(%cleanup_error, "failed to stop sandbox after stdio setup failed");
                        }
                        return Err(error);
                    }
                };
                let process = match sandbox.exec(exec, stdio).await {
                    Ok(process) => process.join().await,
                    Err(error) => Err(error),
                };
                drop(terminal);
                let cleanup = sandbox.stop().await;
                let code = process?;
                cleanup?;
                Ok(code)
            }
            .await;

            if ephemeral
                && let Err(remove_error) = async { backend.get(id).await?.remove().await }.await
            {
                warn!(%remove_error, "failed to remove ephemeral sandbox");
            }
            result
        }
        Command::Start { id } => {
            let mut sandbox = backend.get(id).await?;
            sandbox.start().await?;
            sandbox.join().await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Exec { id, exec } => {
            let exec = exec.into_spec();
            let (stdio, terminal) = stdio::inherit(exec.tty)?;
            let result = backend.get(id).await?.exec(exec, stdio).await?.join().await;
            drop(terminal);
            result
        }
        Command::Status { id } => {
            println!("{}", backend.get(id).await?.status().await?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Kill { id } => {
            backend.get(id).await?.kill().await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Remove { id } => {
            backend.get(id).await?.remove().await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::List => {
            let containers = backend.list().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&containers).map_err(|error| {
                    guardian::Error::Podman(format!("failed to serialize container list: {error}"))
                })?
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

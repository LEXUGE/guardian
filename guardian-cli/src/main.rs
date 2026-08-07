mod config;

use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, process::ExitCode, sync::Mutex};

use clap::Parser;
use config::{Cli, Command, RuntimeArgs};
use guardian::{
    Result,
    rt::{Backend as _, Process as _, Sandbox as _, Stdio, podman::Podman},
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

    let result = run(runtime, command).await;
    match result {
        Ok(code) => code,
        Err(error) => {
            error!(error = %error, "guardian failed");
            ExitCode::from(125)
        }
    }
}

async fn run(runtime: RuntimeArgs, command: Command) -> Result<ExitCode> {
    let mut backend = Podman::init(runtime.into_config()?).await?;

    match command {
        Command::Create(args) => {
            let sandbox = backend.create(args.into_spec()).await?;
            println!("{}", sandbox.id());
            Ok(ExitCode::SUCCESS)
        }
        Command::Run { create, ephemeral } => {
            let sandbox = backend.create(create.into_spec()).await?;
            eprintln!("guardian: sandbox {}", sandbox.id());
            let result = async { sandbox.start(Stdio::inherit()).await?.join().await }.await;

            if ephemeral && let Err(remove_error) = sandbox.remove().await {
                warn!(%remove_error, "failed to remove ephemeral sandbox");
            }
            result
        }
        Command::Start { id } => {
            backend
                .get(id)
                .await?
                .start(Stdio::inherit())
                .await?
                .join()
                .await
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

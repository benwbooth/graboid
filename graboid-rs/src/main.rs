mod api;
mod archives;
mod claude;
mod config;
mod db;
mod events;
mod models;
mod runner;
mod state;
mod torrent;
mod ui;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;
use crate::db::JobDb;
use crate::events::ServerEvent;
use crate::runner::JobRunner;
use crate::state::{AppState, AuthConfig, GitInfo, RuntimeState};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Arc::new(AppConfig::load());
    let runtime = Arc::new(RuntimeState::new(500, 100));

    let db = Arc::new(JobDb::new(&config.database_path()).await?);
    let requeued = db.requeue_inflight_jobs().await?;
    if requeued > 0 {
        warn!("requeued {requeued} inflight jobs from previous run");
    }

    let (events_tx, _events_rx) = broadcast::channel::<ServerEvent>(4096);
    let runner = JobRunner::new(
        db.clone(),
        events_tx.clone(),
        runtime.clone(),
        config.clone(),
    );

    // Re-enqueue pending jobs from previous sessions.
    for job_id in db.list_pending_job_ids(10_000).await? {
        if let Err(err) = runner.enqueue(job_id.clone()).await {
            warn!("failed to re-enqueue {job_id}: {err:#}");
        }
    }

    let project_root = resolve_project_root();
    let git_info = GitInfo::capture(&project_root);
    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        runner,
        events: events_tx,
        runtime,
        project_root: project_root.clone(),
        git_info,
        auth: AuthConfig {
            username: config.username.clone(),
            password: config.password.clone(),
            session_secret: config.session_secret.clone(),
            session_max_age_seconds: config.session_max_age_seconds,
        },
        config_path: config.config_path.clone(),
        api_key: Arc::new(tokio::sync::RwLock::new(config.api_key.clone())),
    });

    let frontend_dist = project_root.join("frontend/dist");
    let app = if frontend_dist.exists() {
        info!("serving frontend assets from {}", frontend_dist.display());
        api::router(state).nest_service("/assets", ServeDir::new(frontend_dist))
    } else {
        warn!(
            "frontend dist missing at {}; /assets will not be served",
            frontend_dist.display()
        );
        api::router(state)
    };

    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .with_context(|| format!("invalid bind address {}", config.bind_addr))?;

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    info!("graboid-rs listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server failed")?;

    Ok(())
}

fn resolve_project_root() -> std::path::PathBuf {
    let candidates = [
        std::path::PathBuf::from("."),
        std::path::PathBuf::from("graboid-rs"),
        std::path::PathBuf::from("../graboid-rs"),
        std::path::PathBuf::from("../../graboid-rs"),
    ];

    for candidate in candidates {
        if candidate.join("src/ui.rs").exists() {
            return candidate;
        }
    }

    std::path::PathBuf::from(".")
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            let _ = sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    info!("shutdown signal received");
}

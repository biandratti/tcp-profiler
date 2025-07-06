//! # Huginn API
//!
//! Web API server for Huginn network profiler.
//! Provides REST API and WebSocket endpoints for real-time traffic analysis.

pub mod error;
pub mod handlers;
pub mod server;
pub mod state;
pub mod websocket;

// Re-export main types
pub use error::{ApiError, Result};
pub use handlers::*;
pub use server::{ApiServer, ApiServerConfig};
pub use state::AppState;

// Re-export huginn types for convenience
pub use huginn_collector::{CollectorConfig, NetworkCollector};
pub use huginn_core::{TrafficEvent, TrafficProfile};

/// Version of huginn-api
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

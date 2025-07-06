//! # Huginn Collector
//!
//! Network traffic collector for Huginn using huginn-net.
//! Captures network packets and converts them to traffic profiles using huginn-core.

pub mod bridge;
pub mod collector;
pub mod config;
pub mod error;

// Re-export main types
pub use bridge::ChannelBridge;
pub use collector::{CollectorHandle, NetworkCollector, NetworkCollectorBuilder};
pub use config::CollectorConfig;
pub use error::{CollectorError, Result};

// Re-export huginn-core types for convenience
pub use huginn_core::{HuginnAnalyzer, TrafficEvent, TrafficProfile};

/// Version of huginn-collector
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

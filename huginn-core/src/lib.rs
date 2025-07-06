//! # Huginn Core
//!
//! Core library for Huginn network traffic analysis.
//! Provides common data structures, traits, and utilities for network traffic profiling.

pub mod analyzer;
pub mod error;
pub mod events;
pub mod profile;

// Re-export main types
pub use analyzer::{AnalyzerConfig, HuginnAnalyzer};
pub use error::{HuginnError, Result};
pub use events::{EventHandler, LoggingEventHandler, TrafficEvent};
pub use profile::{HttpAnalysis, TcpAnalysis, TlsAnalysis, TrafficProfile};

// Re-export huginn-net types for convenience
pub use huginn_net::fingerprint_result::FingerprintResult;
pub use huginn_net::{HuginnNet, ObservableTcp, ObservableTlsClient};

/// Version of huginn-core
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

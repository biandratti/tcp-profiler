//! # Huginn Core
//! 
//! Core library for Huginn network traffic analysis.
//! Provides common data structures, traits, and utilities for network traffic profiling.

pub mod analyzer;
pub mod profile;
pub mod error;
pub mod events;

// Re-export main types
pub use analyzer::{HuginnAnalyzer, AnalyzerConfig};
pub use profile::{TrafficProfile, TcpAnalysis, HttpAnalysis, TlsAnalysis};
pub use error::{HuginnError, Result};
pub use events::{TrafficEvent, EventHandler, LoggingEventHandler};

// Re-export huginn-net types for convenience
pub use huginn_net::fingerprint_result::FingerprintResult;
pub use huginn_net::{HuginnNet, ObservableTcp, ObservableTlsClient};

/// Version of huginn-core
pub const VERSION: &str = env!("CARGO_PKG_VERSION"); 
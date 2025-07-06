use thiserror::Error;

/// Result type for huginn-core operations
pub type Result<T> = std::result::Result<T, HuginnError>;

/// Errors that can occur in huginn-core
#[derive(Error, Debug)]
pub enum HuginnError {
    #[error("Network analysis error: {0}")]
    NetworkAnalysis(String),

    #[error("Invalid traffic data: {0}")]
    InvalidData(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl HuginnError {
    /// Create a new network analysis error
    pub fn network_analysis<S: Into<String>>(msg: S) -> Self {
        Self::NetworkAnalysis(msg.into())
    }

    /// Create a new invalid data error
    pub fn invalid_data<S: Into<String>>(msg: S) -> Self {
        Self::InvalidData(msg.into())
    }

    /// Create a new configuration error
    pub fn configuration<S: Into<String>>(msg: S) -> Self {
        Self::Configuration(msg.into())
    }
}

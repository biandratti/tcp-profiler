use thiserror::Error;

/// Result type for huginn-collector operations
pub type Result<T> = std::result::Result<T, CollectorError>;

/// Errors that can occur in huginn-collector
#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("Network collection error: {0}")]
    Collection(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Channel error: {0}")]
    Channel(String),

    #[error("Huginn core error: {0}")]
    Core(#[from] huginn_core::HuginnError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl CollectorError {
    /// Create a new collection error
    pub fn collection<S: Into<String>>(msg: S) -> Self {
        Self::Collection(msg.into())
    }

    /// Create a new configuration error
    pub fn configuration<S: Into<String>>(msg: S) -> Self {
        Self::Configuration(msg.into())
    }

    /// Create a new channel error
    pub fn channel<S: Into<String>>(msg: S) -> Self {
        Self::Channel(msg.into())
    }
}

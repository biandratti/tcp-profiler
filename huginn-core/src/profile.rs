use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Complete traffic profile for a network endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficProfile {
    /// Source IP address
    pub ip: IpAddr,
    /// Source port
    pub port: u16,
    /// When this profile was created/updated
    pub timestamp: DateTime<Utc>,
    /// TCP analysis results
    pub tcp: Option<TcpAnalysis>,
    /// HTTP analysis results  
    pub http: Option<HttpAnalysis>,
    /// TLS analysis results
    pub tls: Option<TlsAnalysis>,
    /// Additional metadata
    pub metadata: ProfileMetadata,
}

/// TCP connection analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpAnalysis {
    /// Operating system detection
    pub os: String,
    /// Detection quality/confidence
    pub quality: f64,
    /// Network distance (hops)
    pub distance: u8,
    /// TCP signature string
    pub signature: String,
    /// Detailed TCP characteristics
    pub details: TcpDetails,
}

/// HTTP request/response analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAnalysis {
    /// Browser detection
    pub browser: String,
    /// Detection quality/confidence
    pub quality: f64,
    /// Language detection
    pub language: Option<String>,
    /// Diagnosis information
    pub diagnosis: String,
    /// HTTP signature
    pub signature: String,
    /// Detailed HTTP characteristics
    pub details: HttpDetails,
}

/// TLS connection analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAnalysis {
    /// JA4 fingerprint (full)
    pub ja4: String,
    /// JA4 raw fingerprint
    pub ja4_raw: String,
    /// JA4 original fingerprint
    pub ja4_original: String,
    /// JA4 original raw fingerprint
    pub ja4_original_raw: String,
    /// Detailed TLS characteristics
    pub details: TlsDetails,
}

/// Detailed TCP characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpDetails {
    pub version: String,
    pub initial_ttl: String,
    pub options_length: u8,
    pub mss: Option<u16>,
    pub window_size: String,
    pub window_scale: Option<u8>,
    pub options_layout: String,
    pub quirks: String,
    pub payload_class: String,
}

/// Detailed HTTP characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDetails {
    pub version: String,
    pub header_order: String,
    pub headers_absent: String,
    pub expected_software: String,
}

/// Detailed TLS characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsDetails {
    pub version: String,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
}

/// Additional profile metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    /// First time this IP was seen
    pub first_seen: DateTime<Utc>,
    /// Last time this IP was updated
    pub last_updated: DateTime<Utc>,
    /// Number of packets analyzed
    pub packet_count: u64,
    /// Profile completeness (0.0 - 1.0)
    pub completeness: f64,
}

impl TrafficProfile {
    /// Create a new traffic profile
    pub fn new(ip: IpAddr, port: u16) -> Self {
        let now = Utc::now();
        Self {
            ip,
            port,
            timestamp: now,
            tcp: None,
            http: None,
            tls: None,
            metadata: ProfileMetadata {
                first_seen: now,
                last_updated: now,
                packet_count: 0,
                completeness: 0.0,
            },
        }
    }

    /// Update the profile with new analysis data
    pub fn update_tcp(&mut self, tcp: TcpAnalysis) {
        self.tcp = Some(tcp);
        self.update_metadata();
    }

    /// Update the profile with HTTP analysis
    pub fn update_http(&mut self, http: HttpAnalysis) {
        self.http = Some(http);
        self.update_metadata();
    }

    /// Update the profile with TLS analysis
    pub fn update_tls(&mut self, tls: TlsAnalysis) {
        self.tls = Some(tls);
        self.update_metadata();
    }

    /// Calculate and update profile completeness
    fn update_metadata(&mut self) {
        self.metadata.last_updated = Utc::now();
        self.metadata.packet_count += 1;

        // Calculate completeness based on available data
        let mut score = 0.0;
        if self.tcp.is_some() {
            score += 0.4;
        }
        if self.http.is_some() {
            score += 0.3;
        }
        if self.tls.is_some() {
            score += 0.3;
        }

        self.metadata.completeness = score;
    }

    /// Check if profile has any analysis data
    pub fn is_empty(&self) -> bool {
        self.tcp.is_none() && self.http.is_none() && self.tls.is_none()
    }

    /// Get a summary string of available data
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.tcp.is_some() {
            parts.push("TCP");
        }
        if self.http.is_some() {
            parts.push("HTTP");
        }
        if self.tls.is_some() {
            parts.push("TLS");
        }

        if parts.is_empty() {
            "No data".to_string()
        } else {
            parts.join(" + ")
        }
    }
}

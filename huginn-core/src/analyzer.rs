use crate::profile::{TrafficProfile, TcpAnalysis, HttpAnalysis, TlsAnalysis, TcpDetails, HttpDetails, TlsDetails};
use crate::events::{TrafficEvent, EventDispatcher};
use crate::error::{Result, HuginnError};
use huginn_net::fingerprint_result::*;
use huginn_net::ObservableTcp;
use huginn_net::tcp::{IpVersion, PayloadSize, WindowSize};
use huginn_net::Ttl;
use chrono::Utc;
use std::net::IpAddr;
use std::str::FromStr;

/// Configuration for the Huginn analyzer
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Whether to enable TCP analysis
    pub enable_tcp: bool,
    /// Whether to enable HTTP analysis
    pub enable_http: bool,
    /// Whether to enable TLS analysis
    pub enable_tls: bool,
    /// Minimum quality threshold for results
    pub min_quality: f64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            enable_http: true,
            enable_tls: true,
            min_quality: 0.0,
        }
    }
}

/// Main analyzer that converts huginn-net results to our data structures
pub struct HuginnAnalyzer {
    config: AnalyzerConfig,
    event_dispatcher: EventDispatcher,
}

impl HuginnAnalyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: AnalyzerConfig::default(),
            event_dispatcher: EventDispatcher::new(),
        }
    }

    /// Create a new analyzer with custom configuration
    pub fn with_config(config: AnalyzerConfig) -> Self {
        Self {
            config,
            event_dispatcher: EventDispatcher::new(),
        }
    }

    /// Get a mutable reference to the event dispatcher
    pub fn event_dispatcher_mut(&mut self) -> &mut EventDispatcher {
        &mut self.event_dispatcher
    }

    /// Analyze a fingerprint result and return a traffic profile
    pub fn analyze(&self, result: FingerprintResult) -> Result<Option<TrafficProfile>> {
        // Extract source IP and port from the result
        let (ip, port) = self.extract_ip_port(&result)?;
        
        // Create or update traffic profile
        let mut profile = TrafficProfile::new(ip, port);

        // Analyze TCP if available and enabled
        if self.config.enable_tcp {
            if let Some(syn) = &result.syn {
                if let Some(tcp_analysis) = self.analyze_tcp_syn(syn)? {
                    profile.update_tcp(tcp_analysis);
                    self.emit_tcp_event(&profile, &result.syn.as_ref().unwrap());
                }
            } else if let Some(syn_ack) = &result.syn_ack {
                if let Some(tcp_analysis) = self.analyze_tcp_syn_ack(syn_ack)? {
                    profile.update_tcp(tcp_analysis);
                    self.emit_tcp_event_syn_ack(&profile, &result.syn_ack.as_ref().unwrap());
                }
            }
        }

        // Analyze HTTP if available and enabled
        if self.config.enable_http {
            if let Some(http_req) = &result.http_request {
                if let Some(http_analysis) = self.analyze_http_request(http_req)? {
                    profile.update_http(http_analysis);
                    self.emit_http_event(&profile, &result.http_request.as_ref().unwrap());
                }
            } else if let Some(http_res) = &result.http_response {
                if let Some(http_analysis) = self.analyze_http_response(http_res)? {
                    profile.update_http(http_analysis);
                    self.emit_http_event_response(&profile, &result.http_response.as_ref().unwrap());
                }
            }
        }

        // Analyze TLS if available and enabled
        if self.config.enable_tls {
            if let Some(tls_client) = &result.tls_client {
                if let Some(tls_analysis) = self.analyze_tls_client(tls_client)? {
                    profile.update_tls(tls_analysis);
                    self.emit_tls_event(&profile, &result.tls_client.as_ref().unwrap());
                }
            }
        }

        // Only return profile if it has some data
        if profile.is_empty() {
            Ok(None)
        } else {
            self.event_dispatcher.dispatch(TrafficEvent::ProfileCreated {
                ip: profile.ip,
                port: profile.port,
                timestamp: profile.timestamp,
            });
            Ok(Some(profile))
        }
    }

    /// Extract IP and port from fingerprint result
    fn extract_ip_port(&self, result: &FingerprintResult) -> Result<(IpAddr, u16)> {
        if let Some(syn) = &result.syn {
            let ip = IpAddr::from_str(&syn.source.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {}", e)))?;
            Ok((ip, syn.source.port))
        } else if let Some(syn_ack) = &result.syn_ack {
            let ip = IpAddr::from_str(&syn_ack.destination.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {}", e)))?;
            Ok((ip, syn_ack.destination.port))
        } else if let Some(http_req) = &result.http_request {
            let ip = IpAddr::from_str(&http_req.source.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {}", e)))?;
            Ok((ip, http_req.source.port))
        } else if let Some(http_res) = &result.http_response {
            let ip = IpAddr::from_str(&http_res.destination.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {}", e)))?;
            Ok((ip, http_res.destination.port))
        } else if let Some(tls_client) = &result.tls_client {
            let ip = IpAddr::from_str(&tls_client.source.ip.to_string())
                .map_err(|e| HuginnError::invalid_data(format!("Invalid IP: {}", e)))?;
            Ok((ip, tls_client.source.port))
        } else {
            Err(HuginnError::invalid_data("No valid IP/port found in result"))
        }
    }

    /// Analyze TCP SYN packet
    fn analyze_tcp_syn(&self, syn: &SynTCPOutput) -> Result<Option<TcpAnalysis>> {
        let quality = syn.os_matched.as_ref()
            .map(|m| m.quality as f64)
            .unwrap_or(0.0);

        if quality < self.config.min_quality {
            return Ok(None);
        }

        let os = syn.os_matched.as_ref()
            .map(|m| self.extract_os_string(&m.os))
            .unwrap_or_else(|| "Unknown".to_string());

        let distance = self.extract_distance(&syn.sig.ittl);
        let details = self.convert_tcp_details(&syn.sig);

        Ok(Some(TcpAnalysis {
            os,
            quality,
            distance,
            signature: syn.sig.to_string(),
            details,
        }))
    }

    /// Analyze TCP SYN-ACK packet
    fn analyze_tcp_syn_ack(&self, syn_ack: &SynAckTCPOutput) -> Result<Option<TcpAnalysis>> {
        let quality = syn_ack.os_matched.as_ref()
            .map(|m| m.quality as f64)
            .unwrap_or(0.0);

        if quality < self.config.min_quality {
            return Ok(None);
        }

        let os = syn_ack.os_matched.as_ref()
            .map(|m| self.extract_os_string(&m.os))
            .unwrap_or_else(|| "Unknown".to_string());

        let distance = self.extract_distance(&syn_ack.sig.ittl);
        let details = self.convert_tcp_details(&syn_ack.sig);

        Ok(Some(TcpAnalysis {
            os,
            quality,
            distance,
            signature: syn_ack.sig.to_string(),
            details,
        }))
    }

    /// Analyze HTTP request
    fn analyze_http_request(&self, http_req: &HttpRequestOutput) -> Result<Option<HttpAnalysis>> {
        let quality = http_req.browser_matched.as_ref()
            .map(|m| m.quality as f64)
            .unwrap_or(0.0);

        if quality < self.config.min_quality {
            return Ok(None);
        }

        let browser = http_req.browser_matched.as_ref()
            .map(|m| self.extract_browser_string(&m.browser))
            .unwrap_or_else(|| "Unknown".to_string());

        let details = HttpDetails {
            version: http_req.sig.version.to_string(),
            header_order: http_req.sig.horder.iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            headers_absent: http_req.sig.habsent.iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            expected_software: http_req.sig.expsw.clone(),
        };

        Ok(Some(HttpAnalysis {
            browser,
            quality,
            language: http_req.lang.as_ref().map(|l| l.to_string()),
            diagnosis: http_req.diagnosis.to_string(),
            signature: http_req.sig.to_string(),
            details,
        }))
    }

    /// Analyze HTTP response
    fn analyze_http_response(&self, http_res: &HttpResponseOutput) -> Result<Option<HttpAnalysis>> {
        let quality = http_res.web_server_matched.as_ref()
            .map(|m| m.quality as f64)
            .unwrap_or(0.0);

        if quality < self.config.min_quality {
            return Ok(None);
        }

        let browser = http_res.web_server_matched.as_ref()
            .map(|m| self.extract_web_server_string(&m.web_server))
            .unwrap_or_else(|| "Unknown".to_string());

        let details = HttpDetails {
            version: http_res.sig.version.to_string(),
            header_order: http_res.sig.horder.iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            headers_absent: http_res.sig.habsent.iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            expected_software: http_res.sig.expsw.clone(),
        };

        Ok(Some(HttpAnalysis {
            browser,
            quality,
            language: None, // HTTP responses don't have language info
            diagnosis: http_res.diagnosis.to_string(),
            signature: http_res.sig.to_string(),
            details,
        }))
    }

    /// Analyze TLS client
    fn analyze_tls_client(&self, tls_client: &TlsClientOutput) -> Result<Option<TlsAnalysis>> {
        let details = TlsDetails {
            version: tls_client.sig.version.to_string(),
            sni: tls_client.sig.sni.as_ref().map(|s| s.to_string()),
            alpn: tls_client.sig.alpn.as_ref().map(|s| s.to_string()),
            cipher_suites: tls_client.sig.cipher_suites.clone(),
            extensions: tls_client.sig.extensions.clone(),
            signature_algorithms: tls_client.sig.signature_algorithms.clone(),
            elliptic_curves: tls_client.sig.elliptic_curves.clone(),
        };

        Ok(Some(TlsAnalysis {
            ja4: tls_client.sig.ja4.full.value().to_string(),
            ja4_raw: tls_client.sig.ja4.raw.value().to_string(),
            ja4_original: tls_client.sig.ja4_original.full.value().to_string(),
            ja4_original_raw: tls_client.sig.ja4_original.raw.value().to_string(),
            details,
        }))
    }

    // Helper methods for extracting and converting data
    fn extract_os_string(&self, os: &OperativeSystem) -> String {
        let mut parts = vec![os.name.clone()];
        if let Some(family) = &os.family {
            parts.push(family.clone());
        }
        if let Some(variant) = &os.variant {
            parts.push(variant.clone());
        }
        parts.join(" ")
    }

    fn extract_browser_string(&self, browser: &Browser) -> String {
        let mut parts = vec![browser.name.clone()];
        if let Some(family) = &browser.family {
            parts.push(family.clone());
        }
        if let Some(variant) = &browser.variant {
            parts.push(variant.clone());
        }
        parts.join(" ")
    }

    fn extract_web_server_string(&self, web_server: &WebServer) -> String {
        let mut parts = vec![web_server.name.clone()];
        if let Some(family) = &web_server.family {
            parts.push(family.clone());
        }
        if let Some(variant) = &web_server.variant {
            parts.push(variant.clone());
        }
        parts.join(" ")
    }

    fn extract_distance(&self, ttl: &Ttl) -> u8 {
        match ttl {
            Ttl::Distance(_, hops) => *hops,
            _ => 0,
        }
    }

    fn convert_tcp_details(&self, sig: &ObservableTcp) -> TcpDetails {
        TcpDetails {
            version: match sig.version {
                IpVersion::V4 => "IPv4".to_string(),
                IpVersion::V6 => "IPv6".to_string(),
                IpVersion::Any => "Unknown".to_string(),
            },
            initial_ttl: match sig.ittl {
                Ttl::Distance(_, hops) => format!("Distance*{}", hops),
                Ttl::Value(value) => format!("Value*{}", value),
                Ttl::Bad(value) => format!("Bad*{}", value),
                Ttl::Guess(value) => format!("Guess*{}", value),
            },
            options_length: sig.olen,
            mss: sig.mss,
            window_size: match sig.wsize {
                WindowSize::Mod(val) => format!("MOD*{}", val),
                WindowSize::Mss(val) => format!("MSS*{}", val),
                WindowSize::Mtu(val) => format!("MTU*{}", val),
                WindowSize::Value(val) => format!("Value*{}", val),
                WindowSize::Any => "Any".to_string(),
            },
            window_scale: sig.wscale,
            options_layout: sig.olayout.iter()
                .map(|opt| format!("{:?}", opt))
                .collect::<Vec<_>>()
                .join(","),
            quirks: sig.quirks.iter()
                .map(|quirk| format!("{:?}", quirk))
                .collect::<Vec<_>>()
                .join(","),
            payload_class: match sig.pclass {
                PayloadSize::Zero => "0".to_string(),
                PayloadSize::NonZero => "+".to_string(),
                PayloadSize::Any => "*".to_string(),
            },
        }
    }

    // Event emission methods
    fn emit_tcp_event(&self, profile: &TrafficProfile, _syn: &SynTCPOutput) {
        if let Some(tcp) = &profile.tcp {
            self.event_dispatcher.dispatch(TrafficEvent::TcpAnalyzed {
                ip: profile.ip,
                port: profile.port,
                os: tcp.os.clone(),
                quality: tcp.quality,
                timestamp: Utc::now(),
            });
        }
    }

    fn emit_tcp_event_syn_ack(&self, profile: &TrafficProfile, _syn_ack: &SynAckTCPOutput) {
        if let Some(tcp) = &profile.tcp {
            self.event_dispatcher.dispatch(TrafficEvent::TcpAnalyzed {
                ip: profile.ip,
                port: profile.port,
                os: tcp.os.clone(),
                quality: tcp.quality,
                timestamp: Utc::now(),
            });
        }
    }

    fn emit_http_event(&self, profile: &TrafficProfile, _http_req: &HttpRequestOutput) {
        if let Some(http) = &profile.http {
            self.event_dispatcher.dispatch(TrafficEvent::HttpAnalyzed {
                ip: profile.ip,
                port: profile.port,
                browser: http.browser.clone(),
                quality: http.quality,
                timestamp: Utc::now(),
            });
        }
    }

    fn emit_http_event_response(&self, profile: &TrafficProfile, _http_res: &HttpResponseOutput) {
        if let Some(http) = &profile.http {
            self.event_dispatcher.dispatch(TrafficEvent::HttpAnalyzed {
                ip: profile.ip,
                port: profile.port,
                browser: http.browser.clone(),
                quality: http.quality,
                timestamp: Utc::now(),
            });
        }
    }

    fn emit_tls_event(&self, profile: &TrafficProfile, _tls_client: &TlsClientOutput) {
        if let Some(tls) = &profile.tls {
            self.event_dispatcher.dispatch(TrafficEvent::TlsAnalyzed {
                ip: profile.ip,
                port: profile.port,
                ja4: tls.ja4.clone(),
                timestamp: Utc::now(),
            });
        }
    }
}

impl Default for HuginnAnalyzer {
    fn default() -> Self {
        Self::new()
    }
} 
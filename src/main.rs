use axum::http::HeaderMap;
use axum::{extract::ConnectInfo, response::Json, routing::get, Router};
use clap::Parser;
use passivetcp_rs::p0f_output::{
    Browser, HttpRequestOutput, HttpResponseOutput, MTUOutput, OperativeSystem, SynAckTCPOutput,
    SynTCPOutput, UptimeOutput, WebServer,
};
use passivetcp_rs::{
    db::Database,
    tcp::{IpVersion, PayloadSize, WindowSize},
    ObservableTcp, P0f, Ttl,
};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tower_http::services::fs::ServeDir;
use tracing::{debug, error, info};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'i', long)]
    interface: String,
}

#[derive(Serialize, Clone)]
struct TcpInfo {
    syn: Option<SynAckTCP>,
    syn_ack: Option<SynAckTCP>,
    mtu: Option<Mtu>,
    uptime: Option<Uptime>,
    http_request: Option<HttpRequest>,
    http_response: Option<HttpResponse>,
    source_ip: Option<String>,
}

#[derive(Serialize, Clone)]
struct Uptime {
    time: String,
    freq: String,
}

impl From<&UptimeOutput> for Uptime {
    fn from(output: &UptimeOutput) -> Self {
        Uptime {
            time: format!(
                "{} days, {} hrs, {} min (modulo {} days)",
                output.days, output.hours, output.min, output.up_mod_days
            ),
            freq: format!("{:.2} Hz", output.freq),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct HttpSignature {
    pub version: String,
    pub horder: String,
    pub habsent: String,
    pub expsw: String,
}

#[derive(Serialize, Clone)]
struct HttpRequest {
    lang: Option<String>,
    diagnosis: String,
    browser: String,
    quality: String,
    signature: String,
    detail: HttpSignature,
}

fn extract_browser(browser: Option<&Browser>) -> String {
    if let Some(b) = browser {
        let mut parts = vec![b.name.clone()];
        if let Some(family) = &b.family {
            parts.push(family.clone());
        }
        if let Some(variant) = &b.variant {
            parts.push(variant.clone());
        }
        parts.join(" ")
    } else {
        String::new()
    }
}

impl From<&HttpRequestOutput> for HttpRequest {
    fn from(output: &HttpRequestOutput) -> Self {
        let horder_str = output
            .sig
            .horder
            .iter()
            .map(|h| h.to_string())
            .collect::<Vec<String>>()
            .join(", ");

        let habsent_str = output
            .sig
            .habsent
            .iter()
            .map(|h| h.to_string())
            .collect::<Vec<String>>()
            .join(", ");

        let expsw_str = output.sig.expsw.clone();

        let http_signature_detail = HttpSignature {
            version: output.sig.version.to_string(),
            horder: horder_str,
            habsent: habsent_str,
            expsw: expsw_str,
        };

        HttpRequest {
            lang: output.lang.as_ref().map(|l| l.to_string()),
            diagnosis: output.diagnosis.to_string(),
            browser: extract_browser(output.browser_matched.as_ref().map(|l| &l.browser)),
            quality: output
                .browser_matched
                .as_ref()
                .map(|l| l.quality.to_string())
                .unwrap_or_else(|| "0.00".to_string()),
            signature: output.sig.to_string(),
            detail: http_signature_detail,
        }
    }
}

#[derive(Serialize, Clone)]
struct HttpResponse {
    diagnosis: String,
    web_server: String,
    quality: String,
    sig: String,
}

fn extract_web_server(web_server: Option<&WebServer>) -> String {
    if let Some(ws) = web_server {
        let mut parts = vec![ws.name.clone()];
        if let Some(family) = &ws.family {
            parts.push(family.clone());
        }
        if let Some(variant) = &ws.variant {
            parts.push(variant.clone());
        }
        parts.join(" ")
    } else {
        String::new()
    }
}

impl From<&HttpResponseOutput> for HttpResponse {
    fn from(output: &HttpResponseOutput) -> Self {
        HttpResponse {
            diagnosis: output.diagnosis.to_string(),
            web_server: extract_web_server(
                output.web_server_matched.as_ref().map(|l| &l.web_server),
            ),
            quality: output
                .web_server_matched
                .as_ref()
                .map(|l| l.quality.to_string())
                .unwrap_or_else(|| "0.00".to_string()),
            sig: output.sig.to_string(),
        }
    }
}

#[derive(Serialize, Clone)]
struct Mtu {
    link: String,
    mtu: u16,
}

impl From<&MTUOutput> for Mtu {
    fn from(output: &MTUOutput) -> Self {
        Mtu {
            link: output.link.clone(),
            mtu: output.mtu,
        }
    }
}

#[derive(Serialize, Clone)]
pub struct TcpSignature {
    pub version: String,
    pub ittl: String,
    pub olen: u8,
    pub mss: Option<u16>,
    pub wsize: String,
    pub wscale: Option<u8>,
    pub olayout: String,
    pub quirks: String,
    pub pclass: String,
}

impl From<&ObservableTcp> for TcpSignature {
    fn from(sig: &ObservableTcp) -> Self {
        TcpSignature {
            version: match sig.version {
                IpVersion::V4 => "IPv4".to_string(),
                IpVersion::V6 => "IPv6".to_string(),
                IpVersion::Any => "Unknown IP Version".to_string(),
            },
            ittl: match sig.ittl {
                Ttl::Distance(_, hops) => format!("Distance*{}", hops),
                Ttl::Value(value) => format!("Value*{}", value),
                Ttl::Bad(value) => format!("Bad*{}", value),
                Ttl::Guess(value) => format!("Guess*{}", value),
            },
            olen: sig.olen,
            mss: sig.mss,
            wsize: match sig.wsize {
                WindowSize::Mod(val) => format!("MOD*{}", val),
                WindowSize::Mss(val) => format!("MSS*{}", val),
                WindowSize::Mtu(val) => format!("MTU*{}", val),
                WindowSize::Value(val) => format!("Value*{}", val),
                WindowSize::Any => "Any".to_string(),
            },
            wscale: sig.wscale,
            olayout: sig
                .olayout
                .iter()
                .map(|opt| format!("{:?}", opt))
                .collect::<Vec<String>>()
                .join(","),
            quirks: sig
                .quirks
                .iter()
                .map(|quirk| format!("{:?}", quirk))
                .collect::<Vec<String>>()
                .join(","),
            pclass: match sig.pclass {
                PayloadSize::Zero => "0".to_string(),
                PayloadSize::NonZero => "+".to_string(),
                PayloadSize::Any => "*".to_string(),
            },
        }
    }
}

#[derive(Serialize, Clone)]
struct SynAckTCP {
    os: String,
    quality: String,
    dist: String,
    signature: String,
    detail: TcpSignature,
}

fn extract_os(operative_system: Option<&OperativeSystem>) -> String {
    if let Some(os) = operative_system {
        let mut parts = vec![os.name.clone()];
        if let Some(family) = &os.family {
            parts.push(family.clone());
        }
        if let Some(variant) = &os.variant {
            parts.push(variant.clone());
        }
        parts.join(" ")
    } else {
        String::new()
    }
}

fn extract_dist_string(ttl: &Ttl) -> String {
    match ttl {
        Ttl::Distance(_, hops) => hops.to_string(),
        _ => "0".to_string(),
    }
}

impl From<&SynTCPOutput> for SynAckTCP {
    fn from(output: &SynTCPOutput) -> Self {
        SynAckTCP {
            os: extract_os(output.os_matched.as_ref().map(|l| &l.os)),
            dist: extract_dist_string(&output.sig.ittl),
            quality: output
                .os_matched
                .as_ref()
                .map(|l| l.quality.to_string())
                .unwrap_or_else(|| "0.00".to_string()),
            signature: output.sig.to_string(),
            detail: TcpSignature::from(&output.sig),
        }
    }
}

impl From<&SynAckTCPOutput> for SynAckTCP {
    fn from(output: &SynAckTCPOutput) -> Self {
        SynAckTCP {
            os: extract_os(output.os_matched.as_ref().map(|l| &l.os)),
            quality: output
                .os_matched
                .as_ref()
                .map(|l| l.quality.to_string())
                .unwrap_or_else(|| "0.00".to_string()),
            dist: extract_dist_string(&output.sig.ittl),
            signature: output.sig.to_string(),
            detail: TcpSignature::from(&output.sig),
        }
    }
}

type Cache = Arc<RwLock<HashMap<String, TcpInfo>>>;

struct AppState {
    _sender: mpsc::Sender<passivetcp_rs::p0f_output::P0fOutput>,
    cache: Cache,
}

async fn get_tcp_info(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    state: Arc<AppState>,
) -> Json<impl Serialize> {
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
        })
        .map(String::from)
        .unwrap_or_else(|| addr.ip().to_string());

    let client_port = headers
        .get("x-remote-port")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_else(|| addr.port());

    info!(
        "HTTP Request from IP: {} and port: {} looking up TCP info",
        client_ip, client_port
    );

    let cache = state.cache.read().await;
    let tcp_info = cache.get(&client_ip).cloned();

    Json(tcp_info)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let db = Box::leak(Box::new(Database::default()));
    let (async_sender, mut async_receiver) =
        mpsc::channel::<passivetcp_rs::p0f_output::P0fOutput>(100);
    let (std_sender, std_receiver) = std_mpsc::channel();

    let cache: Cache = Arc::new(RwLock::new(HashMap::new()));

    // Start the P0f analyzer in a separate thread
    let interface = args.interface.clone();
    let db_clone = db;
    info!("Starting P0f analyzer on interface: {}", interface);
    std::thread::spawn(move || {
        debug!("P0f analyzer thread started");
        P0f::new(db_clone, 100).analyze_network(&interface, std_sender);
    });

    // Bridge between std channel and async channel
    let async_sender_clone = async_sender.clone();
    std::thread::spawn(move || {
        debug!("Bridge thread started");
        while let Ok(output) = std_receiver.recv() {
            if async_sender_clone.blocking_send(output).is_err() {
                error!("Failed to send data through async channel");
                break;
            }
        }
    });

    // Process the async messages
    let cache_clone = Arc::clone(&cache);
    tokio::spawn(async move {
        while let Some(output) = async_receiver.recv().await {
            let (source_ip, source_port): (String, u16) = if let Some(syn) = &output.syn {
                (syn.source.ip.to_string(), syn.source.port)
            } else if let Some(syn_ack) = &output.syn_ack {
                (syn_ack.destination.ip.to_string(), syn_ack.destination.port)
            } else if let Some(mtu) = &output.mtu {
                (mtu.source.ip.to_string(), mtu.source.port)
            } else if let Some(uptime) = &output.uptime {
                (uptime.source.ip.to_string(), uptime.source.port)
            } else if let Some(http_req) = &output.http_request {
                (http_req.source.ip.to_string(), http_req.source.port)
            } else if let Some(http_res) = &output.http_response {
                (
                    http_res.destination.ip.to_string(),
                    http_res.destination.port,
                )
            } else {
                continue;
            };

            info!(
                "P0f detected packet from: {} and port: {}",
                source_ip, source_port
            );

            let mut cache = cache_clone.write().await;

            let tcp_info = cache.entry(source_ip.clone()).or_insert_with(|| TcpInfo {
                syn: None,
                syn_ack: None,
                mtu: None,
                uptime: None,
                http_request: None,
                http_response: None,
                source_ip: None,
            });

            if let Some(syn) = &output.syn {
                tcp_info.syn = Some(SynAckTCP::from(syn));
            }
            if let Some(syn_ack) = &output.syn_ack {
                tcp_info.syn_ack = Some(SynAckTCP::from(syn_ack));
            }
            if let Some(mtu) = &output.mtu {
                tcp_info.mtu = Some(Mtu::from(mtu));
            }
            if let Some(uptime) = &output.uptime {
                tcp_info.uptime = Some(Uptime::from(uptime));
            }
            if let Some(http_req) = &output.http_request {
                tcp_info.http_request = Some(HttpRequest::from(http_req));
            }
            if let Some(http_res) = &output.http_response {
                tcp_info.http_response = Some(HttpResponse::from(http_res));
            }
            tcp_info.source_ip = Some(source_ip);
        }
    });

    let state = Arc::new(AppState {
        _sender: async_sender,
        cache,
    });

    let app = Router::new()
        .route(
            "/tcp-info",
            get({
                let state = Arc::clone(&state);
                move |connect_info, headers| get_tcp_info(connect_info, headers, state)
            }),
        )
        .fallback_service(ServeDir::new("static"));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

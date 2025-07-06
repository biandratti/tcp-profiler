// Legacy main.rs - Now redirects to huginn-api
// This file is kept for backwards compatibility

use clap::Parser;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'i', long)]
    interface: String,

    #[arg(long, help = "Path to TLS certificate file (PEM format)")]
    cert: Option<String>,

    #[arg(long, help = "Path to TLS private key file (PEM format)")]
    key: Option<String>,

    #[arg(long, help = "Enable HTTP to HTTPS upgrade", default_value = "false")]
    upgrade: bool,

    #[arg(long, help = "Port to run the server on", default_value = "3000")]
    port: u16,
}

fn main() {
    println!("🦉 Huginn Network Profiler - Legacy Entry Point");
    println!("Redirecting to the new modular huginn-api...");

    let args = Args::parse();

    // Try to find the huginn-api binary
    let huginn_api_path = std::env::current_exe()
        .ok()
        .and_then(|exe_path| {
            exe_path.parent().map(|dir| dir.join("huginn-api"))
        })
        .unwrap_or_else(|| std::path::PathBuf::from("./target/release/huginn-api"));

    // Build command for huginn-api binary
    let mut cmd = Command::new(&huginn_api_path);

    // Add interface argument
    cmd.args(["--interface", &args.interface]);

    // Add bind address (convert port to bind format)
    let bind_addr = format!("0.0.0.0:{}", args.port);
    cmd.args(["--bind", &bind_addr]);

    // Note: TLS arguments are not supported by huginn-api yet
    if args.cert.is_some() || args.key.is_some() {
        eprintln!("Warning: TLS arguments are not yet supported by huginn-api");
    }

    if args.upgrade {
        eprintln!("Warning: --upgrade flag is not yet supported by huginn-api");
    }

    println!("Executing: {:?}", cmd);

    // Execute the command
    match cmd.status() {
        Ok(status) => {
            if status.success() {
                println!("huginn-api completed successfully");
            } else {
                eprintln!("huginn-api exited with error code: {:?}", status.code());
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to execute huginn-api: {}", e);
            eprintln!("Make sure huginn-api is built with: cargo build --bin huginn-api");
            std::process::exit(1);
        }
    }
}

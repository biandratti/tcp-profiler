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

    // Build command for huginn-api
    let mut cmd = Command::new("cargo");
    cmd.args(&["run", "--bin", "huginn-api", "--"]);

    // Add interface argument
    cmd.args(&["--interface", &args.interface]);

    // Add port argument
    cmd.args(&["--port", &args.port.to_string()]);

    // Add TLS arguments if provided
    if let Some(cert) = &args.cert {
        cmd.args(&["--cert", cert]);
    }

    if let Some(key) = &args.key {
        cmd.args(&["--key", key]);
    }

    // Add upgrade flag if enabled
    if args.upgrade {
        cmd.arg("--upgrade");
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

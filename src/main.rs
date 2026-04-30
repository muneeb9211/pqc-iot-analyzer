use clap::{Parser, Subcommand, ValueEnum};
use pqc_iot_analyzer::protocols::ProtocolType;
use pqc_iot_analyzer::report::ReportFormat;
use pqc_iot_analyzer::{analyzer, protocols, report};
use std::path::PathBuf;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "pqc-iot-analyzer",
    version,
    about = "Post-quantum cryptographic readiness analyzer for IoT protocols",
    long_about = "Analyzes IoT network protocol traffic (CoAP, MQTT, RPL) for post-quantum \
                  cryptographic readiness. Detects RSA, ECDSA, ECDH, and other classical \
                  primitives vulnerable to quantum attacks, and recommends NIST PQC \
                  standard replacements (ML-KEM, ML-DSA)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze a sample/capture file for PQC readiness
    Analyze {
        /// Path to hex-encoded sample data file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Output format
        #[arg(long, short, default_value = "text", value_enum)]
        format: OutputFormat,

        /// Filter by protocol (analyze only matching packets)
        #[arg(long, short, value_enum)]
        protocol: Option<ProtocolFilter>,
    },

    /// Scan a sample file filtered by a specific protocol
    Scan {
        /// Path to hex-encoded sample data file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Protocol to filter for
        #[arg(long, value_enum)]
        protocol: ProtocolFilter,

        /// Output format
        #[arg(long, short, default_value = "text", value_enum)]
        format: OutputFormat,
    },

    /// Generate a report from a sample file
    Report {
        /// Path to hex-encoded sample data file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Report format
        #[arg(long, default_value = "text", value_enum)]
        format: OutputFormat,
    },

    /// Show the PQC migration mapping table
    Mappings,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Text,
}

impl From<OutputFormat> for ReportFormat {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Json => ReportFormat::Json,
            OutputFormat::Text => ReportFormat::Text,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProtocolFilter {
    Coap,
    Mqtt,
    Rpl,
}

impl ProtocolFilter {
    fn matches(&self, pt: &ProtocolType) -> bool {
        matches!(
            (self, pt),
            (ProtocolFilter::Coap, ProtocolType::CoAP)
                | (ProtocolFilter::Mqtt, ProtocolType::MQTT)
                | (ProtocolFilter::Rpl, ProtocolType::RPL)
        )
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            file,
            format,
            protocol,
        } => {
            run_analysis(&file, format.into(), protocol);
        }
        Commands::Scan {
            file,
            protocol,
            format,
        } => {
            run_analysis(&file, format.into(), Some(protocol));
        }
        Commands::Report { file, format } => {
            run_analysis(&file, format.into(), None);
        }
        Commands::Mappings => {
            print_migration_table();
        }
    }
}

fn run_analysis(path: &PathBuf, format: ReportFormat, protocol_filter: Option<ProtocolFilter>) {
    let raw_packets = match pqc_iot_analyzer::load_sample_file(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading file '{}': {}", path.display(), e);
            process::exit(1);
        }
    };

    if raw_packets.is_empty() {
        eprintln!("No packet data found in '{}'", path.display());
        process::exit(1);
    }

    let mut parsed_packets = Vec::new();
    let mut parse_errors = 0;

    for (i, raw) in raw_packets.iter().enumerate() {
        match protocols::auto_parse(raw) {
            Ok(pkt) => {
                if let Some(ref filter) = protocol_filter {
                    if filter.matches(&pkt.protocol) {
                        parsed_packets.push(pkt);
                    }
                } else {
                    parsed_packets.push(pkt);
                }
            }
            Err(e) => {
                eprintln!("Warning: packet {} parse error: {}", i + 1, e);
                parse_errors += 1;
            }
        }
    }

    if parsed_packets.is_empty() {
        if let Some(filter) = protocol_filter {
            eprintln!(
                "No {:?} packets found ({} raw packets loaded, {} parse errors)",
                filter,
                raw_packets.len(),
                parse_errors
            );
        } else {
            eprintln!(
                "No packets could be parsed ({} raw packets loaded, {} parse errors)",
                raw_packets.len(),
                parse_errors
            );
        }
        process::exit(1);
    }

    let result = analyzer::analyze(&parsed_packets);
    let output = report::generate(&result, format);
    println!("{}", output);

    if result.score < 50 {
        process::exit(2);
    }
}

fn print_migration_table() {
    println!();
    println!("  PQC Migration Mapping Table");
    println!("  {}", "=".repeat(68));
    println!();
    println!(
        "  {:<22} {:<24} {:<14} {}",
        "Classical Algorithm", "PQC Replacement", "NIST Standard", "Type"
    );
    println!("  {}", "-".repeat(68));

    let mappings = [
        ("RSA (key transport)", "ML-KEM-768 / ML-KEM-1024", "FIPS 203", "KEM"),
        ("RSA (signatures)", "ML-DSA-65 / ML-DSA-87", "FIPS 204", "Signature"),
        ("ECDSA (P-256)", "ML-DSA-44", "FIPS 204", "Signature"),
        ("ECDSA (P-384)", "ML-DSA-65", "FIPS 204", "Signature"),
        ("Ed25519", "ML-DSA-44", "FIPS 204", "Signature"),
        ("Ed448", "ML-DSA-65", "FIPS 204", "Signature"),
        ("ECDH (P-256)", "ML-KEM-768", "FIPS 203", "KEM"),
        ("ECDH (P-384)", "ML-KEM-1024", "FIPS 203", "KEM"),
        ("X25519", "ML-KEM-768", "FIPS 203", "KEM"),
        ("X448", "ML-KEM-1024", "FIPS 203", "KEM"),
        ("DH (2048-bit)", "ML-KEM-768", "FIPS 203", "KEM"),
        ("DH (3072-bit)", "ML-KEM-1024", "FIPS 203", "KEM"),
        ("AES-128", "AES-256*", "N/A", "Symmetric"),
        ("SHA-256", "SHA-256 / SHA-3-256", "FIPS 202", "Hash"),
        ("HMAC-SHA-256", "HMAC-SHA-256", "N/A", "MAC"),
    ];

    for (classical, pqc, standard, typ) in &mappings {
        println!(
            "  {:<22} {:<24} {:<14} {}",
            classical, pqc, standard, typ
        );
    }
    println!();
    println!("  * AES-128 provides ~64-bit security against Grover's algorithm;");
    println!("    AES-256 retains ~128-bit quantum security.");
    println!();
    println!("  References:");
    println!("    FIPS 203 -- ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)");
    println!("    FIPS 204 -- ML-DSA (Module-Lattice-Based Digital Signature Algorithm)");
    println!("    FIPS 205 -- SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)");
    println!();
}

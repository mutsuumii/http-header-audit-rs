use clap::Parser;
use colored::*;
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "http-header-audit", about = "HTTP security header auditor")]
struct Args {
    /// URL(s) to audit
    urls: Vec<String>,

    /// Request timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,
}

struct HeaderCheck {
    name: &'static str,
    severity: &'static str,
    desc: &'static str,
    recommendation: &'static str,
}

fn get_checks() -> Vec<HeaderCheck> {
    vec![
        HeaderCheck {
            name: "Strict-Transport-Security",
            severity: "HIGH",
            desc: "Enforces HTTPS",
            recommendation: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        HeaderCheck {
            name: "Content-Security-Policy",
            severity: "HIGH",
            desc: "Prevents XSS and injection",
            recommendation: "Content-Security-Policy: default-src 'self'",
        },
        HeaderCheck {
            name: "X-Content-Type-Options",
            severity: "MEDIUM",
            desc: "Prevents MIME sniffing",
            recommendation: "X-Content-Type-Options: nosniff",
        },
        HeaderCheck {
            name: "X-Frame-Options",
            severity: "MEDIUM",
            desc: "Prevents clickjacking",
            recommendation: "X-Frame-Options: DENY",
        },
        HeaderCheck {
            name: "Referrer-Policy",
            severity: "MEDIUM",
            desc: "Controls Referer leakage",
            recommendation: "Referrer-Policy: strict-origin-when-cross-origin",
        },
        HeaderCheck {
            name: "Permissions-Policy",
            severity: "MEDIUM",
            desc: "Controls browser features",
            recommendation: "Permissions-Policy: geolocation=(), camera=(), microphone=()",
        },
        HeaderCheck {
            name: "Cross-Origin-Opener-Policy",
            severity: "LOW",
            desc: "Isolates browsing context",
            recommendation: "Cross-Origin-Opener-Policy: same-origin",
        },
    ]
}

const INFO_LEAK: &[&str] = &["Server", "X-Powered-By", "X-AspNet-Version"];

fn audit_url(url: &str, timeout_secs: u64) {
    let url = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("https://{}", url)
    } else {
        url.to_string()
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(false)
        .build()
        .unwrap();

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {}: {}", "[ERROR]".red(), url, e);
            return;
        }
    };

    let status = resp.status().as_u16();
    let headers: HashMap<String, String> = resp.headers()
        .iter()
        .map(|(k, v)| (k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let checks = get_checks();
    let mut present = 0;
    let total = checks.len();

    println!("\n{}", "=".repeat(60));
    println!("  HTTP Security Headers Report");
    println!("  URL: {}  Status: {}", url, status);
    println!("{}", "=".repeat(60));

    println!("\n  {}", "[PRESENT]".green().bold());
    for check in &checks {
        let key = check.name.to_lowercase();
        if let Some(val) = headers.get(&key) {
            present += 1;
            println!("    {} {}: {}", "+".green(), check.name, &val[..val.len().min(70)]);
        }
    }

    println!("\n  {}", "[MISSING]".red().bold());
    for check in &checks {
        let key = check.name.to_lowercase();
        if !headers.contains_key(&key) {
            let sev = match check.severity {
                "HIGH" => check.severity.red(),
                "MEDIUM" => check.severity.yellow(),
                _ => check.severity.normal(),
            };
            println!("    {} [{}] {}", "-".red(), sev, check.name);
            println!("      Add: {}", check.recommendation.dimmed());
        }
    }

    // Info leak
    let mut leaks = false;
    for hdr in INFO_LEAK {
        let key = hdr.to_lowercase();
        if let Some(val) = headers.get(&key) {
            if !leaks {
                println!("\n  {}", "[INFO LEAKAGE]".yellow().bold());
                leaks = true;
            }
            println!("    {} {}: {}", "!".yellow(), hdr, val);
        }
    }

    let score = (present as f64 / total as f64) * 100.0;
    let score_str = format!("{:.0}%", score);
    let colored_score = if score >= 70.0 { score_str.green() }
        else if score >= 40.0 { score_str.yellow() }
        else { score_str.red() };
    println!("\n  Score: {}", colored_score);
}

fn main() {
    let args = Args::parse();
    if args.urls.is_empty() {
        eprintln!("Provide at least one URL");
        std::process::exit(1);
    }
    for url in &args.urls {
        audit_url(url, args.timeout);
    }
}

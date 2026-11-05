# http-header-audit-rs 🦀

HTTP security header auditor in Rust. Checks for missing security headers, info leakage, and gives recommendations.

## Features
- Checks 7 critical security headers (HSTS, CSP, X-Frame-Options, etc.)
- Detects information leakage (Server, X-Powered-By)
- Color-coded severity output
- Score percentage

## Build & Run
```bash
cargo build --release
./target/release/http-header-audit-rs example.com google.com
```

## License
MIT

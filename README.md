# blackroad-pen-test

Stdlib-only penetration testing toolkit. Zero external dependencies.

## Features

- 🔌 **Port Scanner** – Concurrent TCP port scanning with service identification and banner grabbing
- 🔒 **SSL/TLS Analysis** – Certificate validation, expiry check, weak protocol/cipher detection
- 📋 **Security Headers** – HSTS, CSP, X-Frame-Options, referrer policy checks
- �� **CORS Testing** – Reflected origin, wildcard + credentials misconfiguration
- 🚦 **Rate Limit Probe** – Detect missing rate limiting (brute-force risk)
- 📊 **JSON Reports** – Structured penetration test reports

## Usage

```bash
# Full scan
python src/pen_test.py example.com

# Custom port range
python src/pen_test.py example.com --port-range 1-65535

# HTTP target
python src/pen_test.py example.com --scheme http --port 80

# Save report
python src/pen_test.py example.com --output report.json
```

## Stdlib Only

Uses only: `socket`, `ssl`, `urllib`, `concurrent.futures`, `http.client`

## Tests

```bash
pytest tests/ -v
```

## License

Proprietary – BlackRoad OS, Inc. All rights reserved.
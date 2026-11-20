# VulWall

VulWall is a self-hosted security scanner for small and medium businesses. It
continuously discovers your external attack surface (domains, subdomains, IPs,
open ports), scans it for vulnerabilities, and presents the results with
AI-assisted remediation guidance in a web dashboard.

## Repository layout

| Path       | What it is |
|------------|------------|
| `scanner/` | Go scanning engine: asset discovery, port scanning, vulnerability scanners (nuclei, testssl, JS dependencies, HTTP headers, email security) and the knowledge-base engine. Services talk over Redis streams and persist to MongoDB. |
| `web/`     | ASP.NET Core MVC dashboard: assets, scans, discoveries, recommendations and reports. |

## Install

TBD. Self-hosted installation instructions will be added here.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (C) 2026 Moji Tajik

VulWall is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License version 3 as published by the
Free Software Foundation. See [LICENSE](LICENSE) for the full text.

Source: https://github.com/VulWall/VulWall

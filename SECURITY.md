# Security

This project is pre-release and is intended for controlled development traffic. The proxy binds to IPv4 loopback only after explicit Start. It installs no CA and never changes system proxy settings. CONNECT forwards an opaque TCP stream, typically TLS: certificate validation remains between the client and upstream. CONNECT can carry other TCP protocols too; it does not enforce TLS or classify destinations. Direct HTTP Upgrade remains unsupported. TLS interception is not implemented.

Captures omit bodies, redact complete query strings and retain only allowlisted header values. URL paths remain visible and can contain secrets; do not treat this as complete sensitive-data redaction. Metadata is bounded and memory-only. See [HTTP proxy limits](docs/HTTP_PROXY.md).

Do not include credentials, private keys or unredacted traffic in public issues. Report suspected vulnerabilities through GitHub's private vulnerability reporting when enabled; otherwise contact the maintainer privately before disclosing sensitive details. A dedicated security contact and release support policy will be established before distribution.

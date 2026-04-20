# Security Policy

## Supported Versions

ICSForge is currently in the v0.x series (Beta). Security fixes are applied
to the latest minor release only.

| Version | Supported |
|---------|-----------|
| 0.62.x  | ✅ |
| 0.61.x  | ✅ (security fixes only) |
| < 0.61  | ❌ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use **[GitHub Security Advisories](https://github.com/ICSForge/ICSForge/security/advisories/new)**
to privately report a vulnerability. You will receive an acknowledgement
within 1 week. We aim to publish a coordinated disclosure within 30 days
of confirmation, or sooner for critical issues.

If you cannot use GitHub Security Advisories, email
[icsforge at gmail.com] with the following information:

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (what an attacker could achieve)
- Your suggested fix, if any

## What Counts as a Security Vulnerability

Examples of issues that qualify:

- Authentication bypass on any Web UI endpoint
- Forged receipt acceptance when `callback_token` is configured
- Path traversal in `outdir`, alert-ingest paths, or PCAP upload paths
- CSRF bypass on state-mutating endpoints
- Injection (SQL / command / template) in any input
- XSS in Web UI fields
- Privilege escalation when running unprivileged
- Sending live traffic to a destination IP outside the allow-list
- Secret disclosure (session secret, callback token) through the API
- Denial of service via unbounded resource consumption in request handlers

## What Does *Not* Count

- Traffic generation that matches a real ICS protocol — that is the
  intended behaviour of this tool. ICSForge generates realistic OT traffic
  by design. See the [Safety Model](README.md#security-model) for scope.
- Findings that require root access to the host to begin with.
- Findings that require an attacker to already have valid Web UI credentials
  and are working within their documented privilege level.
- Third-party rule quality — we publish three-tier rules with honest FP
  trade-offs documented per tier. If you find a specific false positive,
  open an Issue (not a Security Advisory).

## Safe Harbour

We commit to not pursuing legal action against researchers who:

- Test only against infrastructure they own or are explicitly authorised
  to test
- Do not publicly disclose findings prior to coordinated release
- Do not degrade or disrupt services for other users

Thank you for keeping the OT security community safer.

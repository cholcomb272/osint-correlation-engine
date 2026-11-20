# Security policy

## Reporting

Please do not disclose an exploitable vulnerability in a public issue. Until a project security contact is configured for the eventual GitHub repository, contact the repository owner privately and include affected version, reproduction, impact, and any suggested mitigation. Do not include live secrets or unrelated personal data.

## Supported release

The latest 2.x release receives security fixes. This repository is not yet published, so no public support SLA is promised.

## Security model

The public API is read-only. Mutations require an administrative bearer secret or server access. The browser never receives that secret. Collector destinations are fixed and HTTPS-allowlisted; user reference URLs are stored but never fetched. PostgreSQL remains internal and runtime processes use a non-owner role.

Operators remain responsible for TLS, identity-aware access to admin routes, host hardening, backups, secret rotation, and monitoring. The platform must not be exposed directly to the internet with the development shared-secret model.

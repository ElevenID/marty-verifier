# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Persist privacy-minimized verification events and flush them on a webview-reported reconnect.
- Deliver REST batches with authenticated `POST` and presigned object-store batches with credential-isolated `PUT`.

### Security

- Delete queued evidence only through an atomic exact-batch acknowledgement, retain failed batches with durable retry/error metadata, sanitize request failures so destination credentials are never persisted, enforce queue bounds, and cap configured retry loops.

## [0.1.0] - 2026-01-07

### Added
- Initial release of marty-reporting
- Event tracking and analytics
- Configurable reporting destinations
- Usage metrics and telemetry
- Privacy-focused reporting options

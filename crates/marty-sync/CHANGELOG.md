# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Reject duplicate-member, oversized, malformed, partially parsed, private-key-bearing, or future-dated USB trust packages before returning any derived records, and bind record freshness to the signed package timestamp.

## [0.1.0] - 2026-01-07

### Added
- Initial release of marty-sync
- Trust anchor synchronization engine
- Multiple sync sources support (ICAO PKD, AAMVA DTS)
- USB device synchronization support
- Background sync with configurable intervals

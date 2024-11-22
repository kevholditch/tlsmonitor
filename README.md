# TLSMonitor

A network monitoring tool that observes TLS handshakes and exports metrics about certificates, including expiration notifications.

## Overview

This project is currently a work in progress. The aim is to build a network monitoring tool that can:

- Passively detect TLS certificates by sniffing network traffic
- Monitor certificate expiration dates across your infrastructure
- Help prevent outages caused by expired certificates
- Provide visibility into your TLS certificate estate without requiring access to individual servers

## Current Status

- ✅ Basic TLS certificate detection
- ✅ Certificate parsing and extraction
- 🚧 Metrics export
- 🚧 Expiration monitoring
- 🚧 Alerting system

## Installation

go install github.com/kevholditch/tlsmonitor@latest

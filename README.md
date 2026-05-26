# spngw

Component of the SPN (Service Provider Network) infrastructure: a secure, virtualized distribution network for enterprise applications. `spngw` acts as the ingress gateway and BFF (Backend for Frontend).

## Overview
`spngw` acts as an SSL termination proxy and application gateway. It bridges external user traffic to the internal SPN services, providing a secure and simplified entry point for web applications.

## Key Roles
- **SSL Termination**: Manages secure HTTPS connections from clients.
- **BFF (Backend for Frontend)**: Aggregates and routes requests to appropriate backend services.
- **Inventory Integration**: Relies on `chip-in inventory` for routing and security rules.

## Configuration (Environment Variables)
- `APIGW_INVENTORY_URL`: URL of the chip-in inventory server (supports `http(s)://` or `file://`).
- `APIGW_TLS_BIND_ADDRESS`: IP and port for HTTPS termination.
- `APIGW_HTTP_BIND_ADDRESS`: IP and port for HTTP (often used for redirection).
- `APIGW_TLS_REDIRECT_PORT`: Port used for automatic HTTPS redirection.
- `RUST_LOG`: Log level (e.g., `info`, `debug`).

## Public Interface
- **HTTPS**: Secure entry point based on `APIGW_TLS_BIND_ADDRESS`.
- **HTTP**: Ingress entry point based on `APIGW_HTTP_BIND_ADDRESS`.

## Deployment
- **Binary**: Static `musl` binaries.
- **Container**: Lightweight `scratch`-based images.

# DBSC Example Implementation

This repository contains a complete implementation of the Device Bound Session Credentials (DBSC) protocol, which is a new web authentication mechanism that enhances security by cryptographically binding session credentials to specific devices.

## Overview

DBSC is a browser feature currently in development by Google Chrome that:

1. Creates cryptographic keys in the device's secure hardware (TPM)
2. Signs authentication challenges from servers using these device-bound keys
3. Automatically refreshes short-lived cookies without user interaction
4. Prevents stolen session cookies from being used on other devices

This technology significantly improves web security by mitigating session hijacking attacks, even if attackers manage to steal session cookies or tokens.

## Features

- Complete server-side implementation in Go
- Client-side simulation of DBSC functionality with JavaScript
- Display of the authentication flow in the main application
- Working login system with username/password authentication
- Session management with automatic refreshing
- Comprehensive documentation of the DBSC protocol

## Getting Started

### Prerequisites

- Go 1.17 or later
- Chrome Canary 136.0.7059.0 or later (for native DBSC support)

### Installation

1. Clone this repository:
   ```
   git clone https://github.com/kokukuma/dbsc-example.git
   cd dbsc-example
   ```

2. Install dependencies:
   ```
   go mod download
   ```

3. Build and run the server:
   ```
   go run cmd/server/server.go
   ```

### Testing with DBSC Support

**IMPORTANT: DBSC requires HTTPS to function properly. For local testing, use an HTTPS tunnel (like ngrok) or set up a local HTTPS certificate.**

For the full DBSC experience in Chrome Canary:

1. Open Chrome Canary 136.0.7059.0 or later
2. Enable the following flags in `chrome://flags`:
   - `#enable-bound-session-credentials-software-keys-for-manual-testing`
   - `#enable-standard-device-bound-session-credentials`
   - `#enable-standard-device-bound-session-persistence`
3. Restart Chrome Canary
4. Visit the application via HTTPS (e.g., using ngrok)

For browsers without native DBSC support, the application includes a JavaScript simulation that demonstrates how DBSC works.

## Setting up HTTPS with ngrok

Since DBSC requires HTTPS, you can use ngrok for local testing:

1. [Install ngrok](https://ngrok.com/download)
2. Start your local server: `go run cmd/server/server.go`
3. In another terminal, create an HTTPS tunnel: `ngrok http 8080`
4. Use the HTTPS URL provided by ngrok to access the application

## Demo

The demo application includes:

1. **Homepage with login**: A standard login form with username/password authentication.
2. **Client-side DBSC library**: A fully-functional JavaScript implementation of DBSC.

For demo purposes, use the following credentials:
- Username: `dbsc-user`
- Password: `password`

## How DBSC Works

See [DBSC.md](DBSC.md) for a complete explanation of the DBSC protocol and its security benefits.

## Project Structure

- `cmd/server/server.go` - Main server application
- `cmd/client/` - Client-side web application
  - `login.html` - Login page
  - `index.html` - Homepage
- `internal/server/` - Core server functionality
- `internal/dbsc/` - DBSC implementation
  - `protocol.go` - DBSC protocol and data structures
  - `auth.go` - Session management and authentication
  - `jwt.go` - JWT token handling
  - `handlers.go` - HTTP handlers for DBSC endpoints
  - `logging.go` - DBSC-specific logging

## Security Considerations

This implementation includes security best practices:

1. DBSC requires HTTPS for all communications
2. Device-bound sessions last 7 days, but auth cookies expire after 10 minutes
3. HTTP-only, Secure cookies with proper SameSite attributes are used
4. Challenges are never reused and expire after 5 minutes
5. All cryptographic operations use secure, standard algorithms

## Resources

- [Google DBSC Explainer](https://github.com/WICG/device-bound-session-credentials/blob/main/explainer.md)
- [WICG Proposal](https://github.com/WICG/device-bound-session-credentials)
- [Chrome Status](https://chromestatus.com/feature/5270503774167040)
- [Fighting cookie theft using device bound sessions](https://blog.chromium.org/2024/04/fighting-cookie-theft-using-device.html)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

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
- Chrome 115 or later (for native DBSC support)

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

4. Access the application at `http://localhost:8080`

### Testing with DBSC Support

For the full DBSC experience in Chrome:

1. Open Chrome 115 or later
2. Go to `chrome://flags/#enable-standard-device-bound-session-credentials` 
3. Set to "Enabled"
4. Restart Chrome
5. Visit the application at `http://localhost:8080`

For browsers without native DBSC support, the application includes a JavaScript simulation that demonstrates how DBSC works.

## Demo

The demo application includes:

1. **Homepage with login**: A standard login form with username/password authentication.
2. **Client-side DBSC library**: A fully-functional JavaScript implementation of DBSC.

For demo purposes, use the following credentials:
- Username: `dbsc-user`
- Password: `password`

## How DBSC Works

See [DBSC.md](DBSC.md) for a complete explanation of the DBSC protocol and its security benefits.

For technical implementation details, see [DBSC-implementation-notes.md](DBSC-implementation-notes.md).

## Project Structure

- `cmd/server/server.go` - Main server application
- `cmd/client/` - Client-side web application
  - `dbsc-client.js` - JavaScript implementation of DBSC
  - `login.html` - Login page
  - `index.html` - Homepage
- `internal/server/server.go` - Server-side DBSC implementation

## Security Considerations

This implementation is for demonstration and educational purposes. For production use:

1. Always use HTTPS for all DBSC communications
2. Implement fallback for non-DBSC browsers
3. Use HTTP-only, Secure cookies with proper SameSite attributes
4. Store keys securely in server-side databases
5. Rotate challenges and never reuse them
6. Implement rate limiting to prevent brute force attacks
7. Set appropriate timeouts for challenges and session registration

## Resources

- [Google DBSC Explainer](https://github.com/WICG/device-bound-session-credentials/blob/main/explainer.md)
- [WICG Proposal](https://github.com/WICG/device-bound-session-credentials)
- [Chrome Status](https://chromestatus.com/feature/5270503774167040)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
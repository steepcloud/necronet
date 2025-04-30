# Necronet

![Development Status](https://img.shields.io/badge/status-early_development-orange)
![Zig Version](https://img.shields.io/badge/zig-0.14.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An Oddworld-inspired network packet analyzer that visualizes network traffic as ingredients flowing through pipes. Security threats appear as contamination, allowing for intuitive monitoring of network health.

> **Note:** This project is in early development. The UI components are not yet functional. Currently, only the core backend systems and packet processing pipeline are implemented.

## Project Vision

Necronet reimagines network monitoring by representing:
- **Network Packets** as ingredients flowing through pipes
- **Connections** as pipes between systems
- **Security Threats** as contamination of ingredients
- **Network Devices** as industrial machinery

This visualization metaphor, inspired by the industrial aesthetic of Oddworld games, aims to make network monitoring more intuitive and engaging.

## Features

### Implemented
- ✅ High-performance packet capture engine
- ✅ Protocol parsers (HTTP, DNS, TCP/IP)
- ✅ Cross-platform IPC between components
- ✅ Threat detection engine with customizable rules
- ✅ Flow tracking and connection state monitoring
- ✅ Comprehensive test suite

### Planned/WIP
- 🚧 Visualization UI (Mudokon Command)
- 🚧 Real-time packet visualization
- 🚧 Security dashboard with threat indicators
- 🚧 Rule management interface
- 🚧 Capture filter configuration

## System Requirements

- **Zig 0.14.0** - Required to build the project
- **Windows or Linux** - Primary development platforms
- **libpcap/Npcap** - For packet capture functionality

## Architecture

Necronet consists of two main components:

- **Slig Barracks** (Backend)
  - Packet capture engine
  - Protocol analyzers
  - Flow tracking
  - Security monitoring

- **Mudokon Command** (Frontend) - *Not yet implemented*
  - Visualization interface
  - Security alerts dashboard
  - Network monitoring controls
  - Configuration interface

Components communicate via a custom IPC protocol that supports multiple transport mechanisms (Named Pipes, Sockets, Standard I/O) with both binary and JSON serialization options.

## Building the Project

1. Ensure Zig 0.14.0 is installed:
   ```bash
   zig version
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/necronet.git
   cd necronet
   ```

3. Build the project:
   ```bash
   zig build
   ```

4. Run tests:
   ```bash
   zig build test
   ```

## Usage

Currently, only the backend components are functional. Running the analyzer (CLI mode):

```bash
zig build run -- --no-gui
```

## Project Structure

```
necronet/
├── backend/         # Core packet processing
│   ├── capture.zig  # Packet capture module
│   ├── detection.zig # Security detection engine
│   └── parser.zig   # Protocol parsers
├── common/          # Shared type definitions
├── ipc/             # Inter-process communication
│   ├── ipc.zig      # IPC transport layer
│   └── messages.zig # Message protocol definitions
├── tests/           # Comprehensive test suite
└── ui/              # Frontend (WIP)
```

## Development Status

Necronet is in early development with focus on building robust backend components:

- **Complete:** Core packet capture, protocol parsing, IPC system, detection engine
- **In Progress:** Visualization layer, UI components, configuration management
- **Planned:** Security dashboard, alert management, rule configuration interface

The UI components are currently a work in progress and not functional yet.

## Contributing

Contributions are welcome! Check out the issues for tasks that need attention. Please ensure:

1. All tests pass with `zig build test --summary all`
2. New features include appropriate tests
3. Code follows existing documentation patterns

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by the industrial aesthetic of Oddworld games
- Built with the Zig programming language
- Special thanks to contributors and the Zig community

---

*"Follow me." - Abe*

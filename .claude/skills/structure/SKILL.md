---
name: structure
description: Project structure and directory layout for OneScan BurpSuite extension. Covers root directory layout, main module structure (extender/), package organization (burp.vaycore.onescan.*), key architecture components (BurpExtender entry point, FpManager, CollectManager, Config), UI components, configuration file locations, naming conventions (m prefix for members, s prefix for statics), and resource files. Use when navigating codebase, understanding architecture, or locating files.
---

# Project Structure

## Root Directory Layout

```
onescan/
├── .agent/                 # Agent analysis and planning documents
├── .claude/                # Claude Code skills
├── .git/                   # Git repository
├── .kiro/                  # Kiro IDE configuration and steering
├── burp-extender-api/      # Burp legacy API module
├── extender/               # Main plugin implementation
├── imgs/                   # Documentation images
├── montoya-api/            # Montoya API module
├── CLAUDE.md               # Development guidelines for Claude
├── LICENSE                 # Project license
├── pom.xml                 # Parent Maven POM
├── prompt.md               # Project requirements (do not delete)
└── README.md               # User documentation (Chinese)
```

## Main Module Structure (extender/)

```
extender/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── burp/                    # Root package
│   │   │       ├── BurpExtender.java    # Plugin entry point
│   │   │       └── vaycore/
│   │   │           └── onescan/         # Main package
│   │   │               ├── bean/        # Data models
│   │   │               ├── common/      # Common utilities
│   │   │               ├── manager/     # Core managers (FpManager, CollectManager, etc.)
│   │   │               └── ui/          # UI components
│   │   └── resources/
│   │       ├── i18n/                    # Internationalization
│   │       ├── fp_config.json           # Fingerprint rules
│   │       ├── header.txt               # Default headers
│   │       ├── host_allowlist.txt       # Host whitelist
│   │       ├── host_blocklist.txt       # Host blacklist
│   │       ├── payload.txt              # Default payloads
│   │       ├── public_suffix_list.json  # Domain suffix list
│   │       ├── remove_header.txt        # Headers to remove
│   │       └── user_agent.txt           # User agent list
│   └── test/
│       └── java/
│           └── burp/                    # Test classes
├── pom.xml                              # Module POM
└── target/                              # Build output
```

## Package Organization

- **burp.BurpExtender** - Plugin entry implementing IBurpExtender and other Burp interfaces
- **burp.vaycore.onescan.bean** - Data transfer objects and models
- **burp.vaycore.onescan.common** - Utilities, constants, helpers
- **burp.vaycore.onescan.manager** - Business logic managers (fingerprint, collection, config)
- **burp.vaycore.onescan.ui** - Swing UI components and panels

## Key Architecture Components

### Entry Point
- `burp.BurpExtender` - Implements multiple Burp interfaces, manages plugin lifecycle

### Core Managers
- `FpManager` - Fingerprint recognition system
- `CollectManager` - Data collection and categorization
- `Config` - Configuration management
- Thread pools for task execution (50 threads), low-frequency tasks (25 threads), fingerprint recognition (10 threads)

### UI Components
- `DataBoardTab` - Main control panel
- `ConfigPanel` - Configuration interface (Payload, Request, Host, Redirect, Other tabs)
- `FingerprintTab` - Fingerprint rule management
- `CollectTab` - Data collection display
- `TaskTable` - Task list with filtering and sorting

## Configuration Files

Plugin configuration stored in:
- **Priority 1**: `{plugin-jar-directory}/OneScan/`
- **Priority 2**: `~/.config/OneScan/` (Linux/macOS) or `C:\Users\{user}\.config\OneScan\` (Windows)

## Naming Conventions

- **Member variables**: `m` prefix (e.g., `mCallbacks`)
- **Static variables**: `s` prefix (e.g., `sRepeatFilter`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `TASK_THREAD_COUNT`)
- **Packages**: `burp.vaycore.onescan.*`

## Resource Files

Default configurations bundled in JAR:
- Fingerprint rules (JSON)
- Default payloads and headers
- Host allow/block lists
- User agent strings
- Public suffix list for domain parsing

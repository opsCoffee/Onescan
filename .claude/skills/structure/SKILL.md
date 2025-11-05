---
name: structure
description: Project structure and directory layout for OneScan BurpSuite extension. Single-module Maven project with simplified package structure. Covers root directory layout, source structure (src/), package organization (burp.common.*, burp.onescan.*), key architecture components (BurpExtender entry point, FpManager, CollectManager, Config), UI components, configuration file locations, naming conventions (m prefix for members, s prefix for statics), and resource files. Use when navigating codebase, understanding architecture, or locating files.
---

# Project Structure

## Root Directory Layout

```
onescan/
├── .agent/                 # Agent analysis and planning documents
├── .claude/                # Claude Code skills
├── .git/                   # Git repository
├── .kiro/                  # Kiro IDE configuration and steering
├── imgs/                   # Documentation images
├── src/                    # Source code directory
│   ├── main/
│   │   ├── java/
│   │   └── resources/
│   └── test/
├── target/                 # Build output directory
├── CLAUDE.md               # Development guidelines for Claude
├── LICENSE                 # Project license
├── pom.xml                 # Maven POM (single module)
├── prompt.md               # Project requirements (do not delete)
└── README.md               # User documentation (Chinese)
```

## Source Structure (src/)

```
src/
├── main/
│   ├── java/
│   │   └── burp/                        # Root package
│   │       ├── BurpExtender.java        # Plugin entry point
│   │       ├── common/                  # Common utilities and components
│   │       │   ├── config/              # Configuration management
│   │       │   ├── filter/              # Data filtering
│   │       │   ├── helper/              # Helper utilities
│   │       │   ├── layout/              # Custom layout managers
│   │       │   ├── log/                 # Logging
│   │       │   ├── utils/               # Utility classes
│   │       │   └── widget/              # Common UI widgets
│   │       └── onescan/                 # OneScan core functionality
│   │           ├── bean/                # Data models
│   │           ├── common/              # OneScan-specific utilities
│   │           ├── info/                # Info tab components
│   │           ├── manager/             # Core managers (FpManager, etc.)
│   │           └── ui/                  # UI components
│   │               ├── base/            # Base UI classes
│   │               ├── tab/             # Tab panels
│   │               └── widget/          # UI widgets
│   └── resources/
│       ├── i18n/                        # Internationalization
│       ├── fp_config.yaml               # Fingerprint rules (YAML format)
│       ├── header.txt                   # Default headers
│       ├── host_allowlist.txt           # Host whitelist
│       ├── host_blocklist.txt           # Host blacklist
│       ├── payload.txt                  # Default payloads
│       ├── public_suffix_list.json      # Domain suffix list
│       ├── remove_header.txt            # Headers to remove
│       └── user_agent.txt               # User agent list
└── test/
    └── java/
        └── burp/                        # Test classes
```

## Package Organization

### Common Packages (burp.common.*)
- **burp.common.config** - Configuration context and management
- **burp.common.filter** - Table filtering and rules
- **burp.common.helper** - Helper utilities (Domain, QPS, UI, etc.)
- **burp.common.layout** - Custom layout managers (VLayout, HLayout)
- **burp.common.log** - Logging utilities
- **burp.common.utils** - General utility classes
- **burp.common.widget** - Reusable UI widgets

### OneScan Packages (burp.onescan.*)
- **burp.BurpExtender** - Plugin entry implementing IBurpExtender and other Burp interfaces
- **burp.onescan.bean** - Data transfer objects and models
- **burp.onescan.common** - OneScan-specific utilities, constants, helpers
- **burp.onescan.manager** - Business logic managers (fingerprint, collection, config)
- **burp.onescan.ui** - Swing UI components and panels

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
- **Packages**: `burp.common.*` and `burp.onescan.*`

## Resource Files

Default configurations bundled in JAR:
- Fingerprint rules (JSON)
- Default payloads and headers
- Host allow/block lists
- User agent strings
- Public suffix list for domain parsing

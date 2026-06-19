<div align="center">

# binary-inspector

**Hex dump, magic-byte detection, entropy, strings, and pattern search — from one zero-dependency CLI.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue?labelColor=0B0A09)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?labelColor=0B0A09)](package.json)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933?labelColor=0B0A09)](package.json)

</div>

## Install

```bash
npx github:NickCirv/binary-inspector <file> [options]
```

Or install globally:

```bash
npm install -g github:NickCirv/binary-inspector
```

## Usage

```bash
# Hex dump (default)
binx image.png

# Detect file type from magic bytes
binx /bin/ls --type

# Entropy + file info
binx firmware.bin --info

# Extract printable strings (min length 8)
binx /bin/ls --strings --min-len 8

# Search for a hex pattern
binx archive.zip --search "50 4B 03 04"

# Full analysis as JSON
binx image.png --all --json
```

| Flag | Description |
|---|---|
| `--hex` | Hex dump (default when no other mode given) |
| `--type` | Detect file type from magic bytes (30+ signatures) |
| `--info` | File size, permissions, Shannon entropy |
| `--strings` | Find printable ASCII sequences |
| `--freq` | Byte frequency analysis, top 10 |
| `--search <hex>` | Search for a hex pattern, e.g. `"FF D8 FF"` |
| `--offset <n>` | Start at byte offset N |
| `--length <n>` | Read N bytes from offset |
| `--min-len <n>` | Min string length for `--strings` (default: 4) |
| `--all` | Run all analyses |
| `--json` | Output full analysis as JSON |
| `--no-color` | Disable color output |

## What it does

`binary-inspector` reads any file and lets you explore its raw bytes without installing anything beyond Node. It identifies 30+ formats by magic bytes (PNG, JPEG, ELF, Mach-O, ZIP, SQLite, WASM, and more), computes Shannon entropy to flag encrypted or compressed regions, extracts printable strings, and searches for arbitrary hex patterns — all piped through a readable color terminal output or clean JSON.

---
<sub>Zero dependencies · Node ≥ 18 · MIT · by <a href="https://github.com/NickCirv">NickCirv</a></sub>

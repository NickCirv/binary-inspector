# binary-inspector — implementation reference

Source revision: `2bb01807adee38706aab24a8c017b3a3aa811978`. This reference records source declarations; it is not a transcript of a successful run.

## Entrypoint and runtime

[package.json](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/package.json) declares `index.js`. Node.js `>=18` and npm.

Executable mapping: `binary-inspector` → `./index.js`, `binx` → `./index.js`.

## Supported workflow

Hex dumps; signature detection; printable strings; entropy and byte frequency; hex-pattern search.

Magic-byte detection is a fixed signature lookup, not a complete file-format parser. Entropy and printable strings are clues, not malware determinations. Reads the file into memory.

## Command reference

The commands below use the installed executable name. From the pinned checkout, replace it with the `node` entrypoint shown above. Options and command branches were cross-checked against captured source; examples are not execution transcripts.

| Flag | Description |
|---|---|
| `--hex` | Hex dump (default when no other mode given) |
| `--type` | Detect file type from magic bytes |
| `--info` | File size, permissions, Shannon entropy |
| `--strings` | Find printable ASCII sequences |
| `--freq` | Byte frequency analysis, top 10 |
| `--search <hex>` | Search for a hex pattern, e.g. `"FF D8 FF"` |
| `--offset <n>` | Start at byte offset N |
| `--length <n>` | Read N bytes from offset |
| `--min-len <n>` | Min string length for `--strings` (default: 4) |
| `--all` | Run all analyses |
| `--json` | Output full analysis as JSON |

## Package scripts

| Script | Exact command |
| --- | --- |
| `test` | `node --test` |

## Implementation sources

[index.js](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/index.js).

## Verification boundary

No repository code, tests, network operation, hook installer or migration was executed for this review. Source inspection supports the documented interface; runtime correctness and external-service compatibility remain unverified.

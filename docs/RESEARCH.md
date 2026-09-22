# binary-inspector — documentation research

Reviewed 21 September 2026. Public GitHub source only.

## Revision and scope

- Commit: [`2bb01807adee38706aab24a8c017b3a3aa811978`](https://github.com/NickCirv/binary-inspector/commit/2bb01807adee38706aab24a8c017b3a3aa811978).
- Tree: `6bcfbd9ee718ccbb5085867ba7df9da7ff58b0a9`; truncated: `false`.
- Capture: 6 of 6 eligible text files; all eligible text files.
- Method: package and entrypoint inspection, implementation-interface review, targeted behavior/limitation inspection, and test-source review. This is not an exhaustive correctness or security audit.
- Commands run against repository code: **none**. External services, deployment and npm publication were not verified.

## Claim and evidence map

| Documentation claim | Pinned evidence | Assessment |
| --- | --- | --- |
| Runtime, executable and development commands | [package.json](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/package.json) | Source declaration inspected; runtime unverified |
| Shows byte-level details of a local file for developers investigating unfamiliar formats. | [index.js](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/index.js) | Implementation interfaces inspected; behavior not executed |
| Hex dumps; signature detection; printable strings; entropy and byte frequency; hex-pattern search. | [index.js](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/index.js) | Source-backed scope, not a test result |
| Magic-byte detection is a fixed signature lookup, not a complete file-format parser. Entropy and printable strings are clues, not malware determinations. Reads the file into memory. | [index.js](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/index.js) | Material limits documented; service compatibility remains open |
| Existing checks | [test/smoke.test.js](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/test/smoke.test.js) | Test source read; no passing-run claim |

## Documentation inventory and disposition

| Existing document | Decision |
| --- | --- |
| [README.md](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/README.md) | Rewritten with source-specific purpose, direct checkout setup, limitations and verification status. Old section fragments retained where practical. |

Added `docs/REFERENCE.md` for the observed implementation and command surface, and this research record. Protected license and attribution files remain in their original locations without edits. No source or product UI was changed.

## Quality dimensions

| Dimension | Status | Evidence / next step |
| --- | --- | --- |
| Pinned provenance | Verified | Captured commit, tree and per-file hashes recorded below |
| Interface documentation | Partially verified | Source inspection only; run clean-checkout quickstart |
| Runtime behavior | Unverified | No repository execution in this review |
| Test results | Unverified | Existing tests were not run |
| Deployment / package availability | Unverified | No remote publish or live-service check |
| Visual / link checks | Unverified | Portfolio renderer and independent QA are separate from this authoring step |

## Editorial follow-up

Excluded --no-color from the operational table: it appears in help but the color gate reads NO_COLOR/TTY rather than that parsed flag.

## Unresolved issues

Magic-byte detection is a fixed signature lookup, not a complete file-format parser. Entropy and printable strings are clues, not malware determinations. Reads the file into memory.

## Captured source inventory

This lists captured provenance, not a claim that every line received a full audit. Binary/generated/excluded files are outside the eligible text capture.

| File | SHA-256 | Bytes |
| --- | --- | --- |
| [LICENSE](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/LICENSE) | `68729cab364d82364078b08d8580ccfa51dc69c81a7d64e8d8d47a1da6c9349d` | 1072 |
| [README.md](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/README.md) | `af598317a8862670256da04d18bfd3813e3fb87883bc3e2f554c7db2817e02f9` | 2172 |
| [package.json](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/package.json) | `cd5363909e21f7eae0ccf7d8a61c1bf3f17307d4bfc0ca6a085416f9f5854295` | 631 |
| [.github/workflows/ci.yml](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/.github/workflows/ci.yml) | `433fbf65635a767ef5cd787147104c248d0cea6bbd6523c6c862f915e0e3206a` | 384 |
| [index.js](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/index.js) | `aa40264e189d10b4baf7b241e5f159febaa337ea39eb7cc8edd37204e7624e53` | 18220 |
| [test/smoke.test.js](https://github.com/NickCirv/binary-inspector/blob/2bb01807adee38706aab24a8c017b3a3aa811978/test/smoke.test.js) | `4e107fe059a90eaaa70dc98e0563d1c6f6e66e9e692b7525f16ce8dcb3755ffa` | 453 |

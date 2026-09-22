![Nicholas Ashkar — binary-inspector](assets/nicholas-ashkar/banner.png)

# binary-inspector

Shows byte-level details of a local file for developers investigating unfamiliar formats.








<a id="usage"></a>

<a id="hex-dump-default"></a>

<a id="detect-file-type-from-magic-bytes"></a>

<a id="entropy--file-info"></a>

<a id="extract-printable-strings-min-length-8"></a>

<a id="search-for-a-hex-pattern"></a>

<a id="full-analysis-as-json"></a>

## What it does

- Hex dumps.
- Signature detection.
- Printable strings.
- Entropy and byte frequency.
- Hex-pattern search.


<a id="install"></a>

## Quickstart

Prerequisites: Node.js `>=18` and npm. The checkout below pins the source used for this documentation.

```sh
git clone https://github.com/NickCirv/binary-inspector.git
cd binary-inspector
git checkout 2bb01807adee38706aab24a8c017b3a3aa811978
node index.js package.json --length 64
```

**Expected behavior (illustrative, not captured):** Prints a hex view of the first 64 bytes of the repository manifest.

Examples are source-inspected, **not runtime-tested**. See the research record for verification gaps.

## Boundaries and data

Magic-byte detection is a fixed signature lookup, not a complete file-format parser. Entropy and printable strings are clues, not malware determinations. Reads the file into memory.

## Development

The manifest defines `npm test` as:

```sh
node --test
```

The captured suite is a smoke check, not end-to-end behavior coverage. Examples include “entry is valid JavaScript”, “--help exits 0”. Tests were not run for this documentation revision.

See [implementation and command reference](docs/REFERENCE.md) for the package scripts and inspected interfaces, and [research record](docs/RESEARCH.md) for the pinned source, document decisions and unresolved checks.

## License and contact

See [LICENSE](LICENSE) for the original terms and attribution. Legal text is unchanged.

[Nicholas Ashkar](https://nicholashkar.com/) · [Discuss a project](https://nicholashkar.com/#oxblood-contact)

#!/usr/bin/env node
// binary-inspector — hex dump, magic bytes, file type detection
// Pure Node.js ES modules, zero external dependencies

import { readFileSync, statSync } from 'fs';
import { resolve, basename } from 'path';
import { fileURLToPath } from 'url';

// ─── ANSI Colors ──────────────────────────────────────────────────────────────
const C = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  red:     '\x1b[31m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  blue:    '\x1b[34m',
  magenta: '\x1b[35m',
  cyan:    '\x1b[36m',
  white:   '\x1b[37m',
  bgBlue:  '\x1b[44m',
  gray:    '\x1b[90m',
};
const NO_COLOR = process.env.NO_COLOR || !process.stdout.isTTY;
const c = (color, str) => NO_COLOR ? str : `${color}${str}${C.reset}`;

// ─── Magic Bytes Signatures ───────────────────────────────────────────────────
const SIGNATURES = [
  { type: 'PNG',          mime: 'image/png',          magic: [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A] },
  { type: 'JPEG',         mime: 'image/jpeg',         magic: [0xFF,0xD8,0xFF] },
  { type: 'GIF87a',       mime: 'image/gif',          magic: [0x47,0x49,0x46,0x38,0x37,0x61] },
  { type: 'GIF89a',       mime: 'image/gif',          magic: [0x47,0x49,0x46,0x38,0x39,0x61] },
  { type: 'WebP',         mime: 'image/webp',         magic: [0x52,0x49,0x46,0x46], offset: 0, extra: { offset: 8, bytes: [0x57,0x45,0x42,0x50] } },
  { type: 'BMP',          mime: 'image/bmp',          magic: [0x42,0x4D] },
  { type: 'TIFF (LE)',    mime: 'image/tiff',         magic: [0x49,0x49,0x2A,0x00] },
  { type: 'TIFF (BE)',    mime: 'image/tiff',         magic: [0x4D,0x4D,0x00,0x2A] },
  { type: 'PDF',          mime: 'application/pdf',    magic: [0x25,0x50,0x44,0x46] },
  { type: 'ZIP',          mime: 'application/zip',    magic: [0x50,0x4B,0x03,0x04] },
  { type: 'ZIP (empty)',  mime: 'application/zip',    magic: [0x50,0x4B,0x05,0x06] },
  { type: 'ZIP (spanned)',mime: 'application/zip',    magic: [0x50,0x4B,0x07,0x08] },
  { type: 'GZIP',         mime: 'application/gzip',   magic: [0x1F,0x8B] },
  { type: 'BZIP2',        mime: 'application/x-bzip2',magic: [0x42,0x5A,0x68] },
  { type: 'XZ',           mime: 'application/x-xz',   magic: [0xFD,0x37,0x7A,0x58,0x5A,0x00] },
  { type: 'TAR',          mime: 'application/x-tar',  magic: [0x75,0x73,0x74,0x61,0x72], offset: 257 },
  { type: 'RAR',          mime: 'application/x-rar',  magic: [0x52,0x61,0x72,0x21,0x1A,0x07] },
  { type: '7-Zip',        mime: 'application/x-7z-compressed', magic: [0x37,0x7A,0xBC,0xAF,0x27,0x1C] },
  { type: 'ELF',          mime: 'application/x-elf',  magic: [0x7F,0x45,0x4C,0x46] },
  { type: 'Mach-O (32)',  mime: 'application/x-mach-binary', magic: [0xCE,0xFA,0xED,0xFE] },
  { type: 'Mach-O (64)',  mime: 'application/x-mach-binary', magic: [0xCF,0xFA,0xED,0xFE] },
  { type: 'Mach-O FAT',   mime: 'application/x-mach-binary', magic: [0xCA,0xFE,0xBA,0xBE] },
  { type: 'MP4',          mime: 'video/mp4',          magic: [0x66,0x74,0x79,0x70], offset: 4 },
  { type: 'MOV',          mime: 'video/quicktime',    magic: [0x66,0x74,0x79,0x70,0x71,0x74], offset: 4 },
  { type: 'AVI',          mime: 'video/x-msvideo',   magic: [0x52,0x49,0x46,0x46] },
  { type: 'MP3',          mime: 'audio/mpeg',         magic: [0xFF,0xFB] },
  { type: 'MP3 (ID3)',    mime: 'audio/mpeg',         magic: [0x49,0x44,0x33] },
  { type: 'OGG',          mime: 'audio/ogg',          magic: [0x4F,0x67,0x67,0x53] },
  { type: 'FLAC',         mime: 'audio/flac',         magic: [0x66,0x4C,0x61,0x43] },
  { type: 'WAV',          mime: 'audio/wav',          magic: [0x52,0x49,0x46,0x46] },
  { type: 'SQLite',       mime: 'application/x-sqlite3', magic: [0x53,0x51,0x4C,0x69,0x74,0x65,0x20,0x66,0x6F,0x72,0x6D,0x61,0x74,0x20,0x33,0x00] },
  { type: 'Class (Java)', mime: 'application/java-vm', magic: [0xCA,0xFE,0xBA,0xBE] },
  { type: 'WASM',         mime: 'application/wasm',   magic: [0x00,0x61,0x73,0x6D] },
  { type: 'DOCX/XLSX/PPTX', mime: 'application/vnd.openxmlformats', magic: [0x50,0x4B,0x03,0x04] },
  { type: 'RTF',          mime: 'application/rtf',    magic: [0x7B,0x5C,0x72,0x74,0x66,0x31] },
  { type: 'ICO',          mime: 'image/x-icon',       magic: [0x00,0x00,0x01,0x00] },
];

function detectMagic(buf) {
  for (const sig of SIGNATURES) {
    const off = sig.offset || 0;
    if (buf.length < off + sig.magic.length) continue;
    const match = sig.magic.every((b, i) => buf[off + i] === b);
    if (!match) continue;
    if (sig.extra) {
      const eoff = sig.extra.offset;
      if (buf.length < eoff + sig.extra.bytes.length) continue;
      const ematch = sig.extra.bytes.every((b, i) => buf[eoff + i] === b);
      if (!ematch) continue;
    }
    return sig;
  }
  return null;
}

// ─── Entropy ──────────────────────────────────────────────────────────────────
function calcEntropy(buf) {
  const freq = new Array(256).fill(0);
  for (const b of buf) freq[b]++;
  let entropy = 0;
  const len = buf.length;
  for (const f of freq) {
    if (f === 0) continue;
    const p = f / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ─── Hex Dump ─────────────────────────────────────────────────────────────────
function isPrintable(b) { return b >= 0x20 && b < 0x7F; }

function hexDump(buf, offset = 0, length = null, bytesPerRow = 16) {
  const end = length !== null ? Math.min(offset + length, buf.length) : buf.length;
  const lines = [];
  for (let i = offset; i < end; i += bytesPerRow) {
    const rowEnd = Math.min(i + bytesPerRow, end);
    const offsetStr = c(C.gray, i.toString(16).padStart(8, '0'));
    const hexParts = [];
    const asciiParts = [];
    for (let j = i; j < rowEnd; j++) {
      const byte = buf[j];
      const hex = byte.toString(16).padStart(2, '0');
      hexParts.push(isPrintable(byte) ? c(C.green, hex) : c(C.dim, hex));
      asciiParts.push(isPrintable(byte) ? c(C.cyan, String.fromCharCode(byte)) : c(C.gray, '.'));
    }
    // Pad last row
    const missing = bytesPerRow - (rowEnd - i);
    for (let p = 0; p < missing; p++) hexParts.push('  ');
    const hexGroups = [];
    for (let g = 0; g < bytesPerRow; g += 8) {
      hexGroups.push(hexParts.slice(g, g + 8).join(' '));
    }
    lines.push(`${offsetStr}  ${hexGroups.join('  ')}  ${c(C.gray,'|')}${asciiParts.join('')}${c(C.gray,'|')}`);
  }
  return lines.join('\n');
}

// ─── Strings ──────────────────────────────────────────────────────────────────
function findStrings(buf, minLen = 4) {
  const results = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const b = buf[i];
    const printable = b !== undefined && isPrintable(b);
    if (printable) {
      if (start === -1) start = i;
    } else {
      if (start !== -1 && i - start >= minLen) {
        results.push({ offset: start, length: i - start, value: buf.slice(start, i).toString('ascii') });
      }
      start = -1;
    }
  }
  return results;
}

// ─── Hex Pattern Search ───────────────────────────────────────────────────────
function searchHexPattern(buf, patternHex) {
  const pattern = patternHex.replace(/\s+/g, '').match(/.{2}/g).map(h => parseInt(h, 16));
  const results = [];
  outer: for (let i = 0; i <= buf.length - pattern.length; i++) {
    for (let j = 0; j < pattern.length; j++) {
      if (buf[i + j] !== pattern[j]) continue outer;
    }
    results.push(i);
  }
  return results;
}

// ─── Byte Frequency ───────────────────────────────────────────────────────────
function byteFrequency(buf, topN = 10) {
  const freq = new Array(256).fill(0);
  for (const b of buf) freq[b]++;
  return freq
    .map((count, byte) => ({ byte, count, pct: (count / buf.length * 100).toFixed(2) }))
    .filter(x => x.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, topN);
}

// ─── File Info ────────────────────────────────────────────────────────────────
function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function octalPerms(mode) {
  return (mode & 0o777).toString(8).padStart(3, '0');
}

// ─── CLI Args ─────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { flags: {}, positional: [] };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) { args.flags[key] = next; i += 2; }
      else { args.flags[key] = true; i++; }
    } else {
      args.positional.push(a); i++;
    }
  }
  return args;
}

// ─── Help ─────────────────────────────────────────────────────────────────────
function printHelp() {
  console.log(`
${c(C.bold + C.cyan, 'binary-inspector')} ${c(C.gray, 'v1.0.0')}  ${c(C.dim, '— hex dump, magic bytes, file type detection')}

${c(C.yellow, 'USAGE')}
  binx <file> [options]
  binary-inspector <file> [options]

${c(C.yellow, 'OPTIONS')}
  ${c(C.green, '--hex')}              Hex dump (default if no other mode)
  ${c(C.green, '--type')}             Detect file type from magic bytes
  ${c(C.green, '--info')}             File info: size, permissions, entropy
  ${c(C.green, '--strings')}          Find printable string sequences
  ${c(C.green, '--freq')}             Byte frequency analysis (top 10)
  ${c(C.green, '--search')} <hex>     Search for hex pattern (e.g. "FF D8 FF")
  ${c(C.green, '--offset')} <n>       Start at byte offset N
  ${c(C.green, '--length')} <n>       Read N bytes from offset
  ${c(C.green, '--min-len')} <n>      Min string length for --strings (default: 4)
  ${c(C.green, '--all')}              Run all analyses
  ${c(C.green, '--json')}             Output full analysis as JSON
  ${c(C.green, '--no-color')}         Disable color output

${c(C.yellow, 'EXAMPLES')}
  binx image.png --type
  binx /bin/ls --hex --offset 0 --length 64
  binx archive.zip --info --freq
  binx firmware.bin --strings --min-len 6
  binx data.bin --search "50 4B 03 04"
  binx binary --all --json
`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.length === 0 || rawArgs[0] === '--help' || rawArgs[0] === '-h') {
    printHelp(); process.exit(0);
  }

  const args = parseArgs(rawArgs);
  const filePath = args.positional[0];
  if (!filePath) { console.error(c(C.red, 'Error: no file specified')); process.exit(1); }

  const absPath = resolve(filePath);
  let stat;
  try { stat = statSync(absPath); } catch {
    console.error(c(C.red, `Error: cannot stat '${filePath}'`)); process.exit(1);
  }
  if (!stat.isFile()) { console.error(c(C.red, `Error: '${filePath}' is not a regular file`)); process.exit(1); }

  let buf;
  try { buf = readFileSync(absPath); } catch {
    console.error(c(C.red, `Error: cannot read '${filePath}'`)); process.exit(1);
  }

  const offset = parseInt(args.flags.offset || '0', 10);
  const length = args.flags.length ? parseInt(args.flags.length, 10) : null;
  const minLen = parseInt(args.flags['min-len'] || '4', 10);
  const jsonMode = !!args.flags.json;
  const all = !!args.flags.all;

  const doHex     = all || !!args.flags.hex     || (!args.flags.type && !args.flags.info && !args.flags.strings && !args.flags.freq && !args.flags.search && !all && !jsonMode);
  const doType    = all || !!args.flags.type;
  const doInfo    = all || !!args.flags.info;
  const doStrings = all || !!args.flags.strings;
  const doFreq    = all || !!args.flags.freq;
  const doSearch  = !!args.flags.search;

  if (jsonMode) {
    const sig = detectMagic(buf);
    const entropy = calcEntropy(buf.slice(offset, length !== null ? offset + length : undefined));
    const freq = byteFrequency(buf);
    const strings = findStrings(buf.slice(offset, length !== null ? offset + length : undefined), minLen);
    const out = {
      file: absPath,
      name: basename(absPath),
      size: stat.size,
      sizeHuman: formatSize(stat.size),
      permissions: octalPerms(stat.mode),
      magicType: sig ? sig.type : 'Unknown',
      mime: sig ? sig.mime : null,
      entropy: parseFloat(entropy.toFixed(4)),
      entropyLevel: entropy > 7.5 ? 'high (encrypted/compressed)' : entropy > 5 ? 'medium' : 'low (text/structured)',
      byteFrequency: freq,
      strings: strings.slice(0, 50),
    };
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  const sep = () => console.log(c(C.gray, '─'.repeat(72)));

  // File header
  console.log(`\n${c(C.bold, 'File:')} ${c(C.cyan, absPath)}`);
  sep();

  if (doInfo || all) {
    const entropy = calcEntropy(buf);
    const entropyLevel = entropy > 7.5
      ? c(C.red, 'HIGH — likely encrypted or compressed')
      : entropy > 5
      ? c(C.yellow, 'MEDIUM')
      : c(C.green, 'LOW — text or structured data');
    console.log(c(C.bold + C.yellow, '\n[ File Info ]'));
    console.log(`  Size:        ${c(C.white, formatSize(stat.size))} ${c(C.gray, `(${stat.size} bytes)`)}`);
    console.log(`  Permissions: ${c(C.white, octalPerms(stat.mode))}`);
    console.log(`  Entropy:     ${c(C.white, entropy.toFixed(4))} ${c(C.gray, '/ 8.0')} — ${entropyLevel}`);
    sep();
  }

  if (doType || all) {
    const sig = detectMagic(buf);
    console.log(c(C.bold + C.yellow, '\n[ Magic Bytes / File Type ]'));
    if (sig) {
      console.log(`  Type: ${c(C.green + C.bold, sig.type)}`);
      console.log(`  MIME: ${c(C.white, sig.mime)}`);
      const magicHex = sig.magic.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
      console.log(`  Magic: ${c(C.cyan, magicHex)}`);
    } else {
      console.log(`  Type: ${c(C.red, 'Unknown / No matching signature')}`);
    }
    const firstBytes = Array.from(buf.slice(0, 16)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    console.log(`  Header (first 16 bytes): ${c(C.gray, firstBytes)}`);
    sep();
  }

  if (doHex) {
    console.log(c(C.bold + C.yellow, '\n[ Hex Dump ]'));
    const sliceEnd = length !== null ? offset + length : Math.min(offset + 512, buf.length);
    const showLen = sliceEnd - offset;
    const totalShown = Math.min(showLen, buf.length - offset);
    if (totalShown < buf.length) {
      console.log(c(C.gray, `  Showing ${totalShown} of ${buf.length} bytes (use --offset/--length for more)\n`));
    }
    console.log(hexDump(buf, offset, length !== null ? length : Math.min(512, buf.length - offset)));
    sep();
  }

  if (doStrings) {
    const slice = buf.slice(offset, length !== null ? offset + length : undefined);
    const strs = findStrings(slice, minLen);
    console.log(c(C.bold + C.yellow, '\n[ Strings ]'));
    console.log(c(C.gray, `  Found ${strs.length} string sequences (min length: ${minLen})\n`));
    const display = strs.slice(0, 30);
    for (const s of display) {
      const off = c(C.gray, (offset + s.offset).toString(16).padStart(8, '0'));
      const val = c(C.green, s.value.length > 80 ? s.value.slice(0, 80) + '…' : s.value);
      console.log(`  ${off}  ${val}`);
    }
    if (strs.length > 30) console.log(c(C.gray, `  … and ${strs.length - 30} more`));
    sep();
  }

  if (doFreq) {
    const freq = byteFrequency(buf);
    console.log(c(C.bold + C.yellow, '\n[ Byte Frequency (Top 10) ]'));
    console.log(c(C.gray, '  Byte   Hex   Count       Pct    Bar'));
    for (const { byte, count, pct } of freq) {
      const label = isPrintable(byte) ? `'${String.fromCharCode(byte)}'` : '   ';
      const hexStr = byte.toString(16).padStart(2, '0').toUpperCase();
      const bar = '█'.repeat(Math.round(parseFloat(pct) / 2));
      console.log(`  ${c(C.white, label.padEnd(4))} ${c(C.cyan, hexStr)}  ${String(count).padStart(8)}  ${String(pct).padStart(6)}%  ${c(C.green, bar)}`);
    }
    sep();
  }

  if (doSearch) {
    const pattern = args.flags.search;
    let offsets;
    try {
      offsets = searchHexPattern(buf, pattern);
    } catch {
      console.error(c(C.red, `Error: invalid hex pattern '${pattern}'`)); process.exit(1);
    }
    console.log(c(C.bold + C.yellow, '\n[ Hex Pattern Search ]'));
    console.log(c(C.gray, `  Pattern: ${pattern.toUpperCase()}`));
    if (offsets.length === 0) {
      console.log(c(C.red, '  Not found'));
    } else {
      console.log(c(C.green, `  Found ${offsets.length} match(es):`));
      offsets.slice(0, 20).forEach(o => {
        console.log(`  Offset: ${c(C.cyan, '0x' + o.toString(16).padStart(8, '0'))} ${c(C.gray, '(' + o + ')')}`);
      });
      if (offsets.length > 20) console.log(c(C.gray, `  … and ${offsets.length - 20} more`));
    }
    sep();
  }

  console.log();
}

main().catch(err => {
  console.error(c(C.red, `Fatal: ${err.message}`));
  process.exit(1);
});

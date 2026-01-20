êconst fs = require('fs');
const path = require('path');

// Read the restored file
const filePath = 'C:\\Users\\.gemini\\antigravity\\conversations\\cb2df0e4-1022-4474-b91a-f6ab41e113aa.pb';
const data = fs.readFileSync(filePath);

console.log('=== Analyzing .pb File Format ===\n');
console.log(`File size: ${data.length.toLocaleString()} bytes`);
console.log(`First 50 bytes (hex): ${data.slice(0, 50).toString('hex')}`);

// Try to detect if it's compressed or encrypted
// Check for common compression signatures
const zlibSig = data[0] === 0x78; // zlib
const gzipSig = data[0] === 0x1f && data[1] === 0x8b; // gzip
const jsonSig = data[0] === 0x7b; // JSON starts with {
const protobufLikely = data[0] === 0x08 || data[0] === 0x0a; // protobuf field tags

console.log(`\nFormat detection:`);
console.log(`  - zlib compressed: ${zlibSig}`);
console.log(`  - gzip compressed: ${gzipSig}`);
console.log(`  - JSON format: ${jsonSig}`);
console.log(`  - Protocol Buffer: ${protobufLikely}`);

// Try to find any readable strings in the file
console.log(`\n=== Searching for readable text patterns ===`);

// Look for common patterns that might indicate text
const textPatterns = [];
let currentText = '';
for (let i = 0; i < Math.min(data.length, 100000); i++) {
    const byte = data[i];
    // Printable ASCII range (32-126) or newline/tab
    if ((byte >= 32 && byte <= 126) || byte === 10 || byte === 13 || byte === 9) {
        currentText += String.fromCharCode(byte);
    } else {
        if (currentText.length >= 10) {
            textPatterns.push({ offset: i - currentText.length, text: currentText.substring(0, 100) });
        }
        currentText = '';
    }
}

console.log(`Found ${textPatterns.length} text patterns in first 100KB:`);
textPatterns.slice(0, 20).forEach((p, i) => {
    console.log(`  [${p.offset}]: "${p.text.substring(0, 60)}${p.text.length > 60 ? '...' : ''}"`);
});

// Try zlib decompression
console.log(`\n=== Trying decompression ===`);
const zlib = require('zlib');

try {
    const inflated = zlib.inflateSync(data);
    console.log(`zlib inflate SUCCESS! Decompressed size: ${inflated.length}`);
    console.log(`First 200 chars: ${inflated.slice(0, 200).toString('utf8')}`);

    // Save decompressed file
    fs.writeFileSync(filePath + '.decoded', inflated);
    console.log(`Saved to: ${filePath}.decoded`);
} catch (e) {
    console.log(`zlib inflate failed: ${e.message}`);
}

try {
    const gunzipped = zlib.gunzipSync(data);
    console.log(`gzip decompress SUCCESS! Decompressed size: ${gunzipped.length}`);
} catch (e) {
    console.log(`gzip failed: ${e.message}`);
}

try {
    const unbroti = zlib.brotliDecompressSync(data);
    console.log(`brotli decompress SUCCESS! Decompressed size: ${unbroti.length}`);
} catch (e) {
    console.log(`brotli failed: ${e.message}`);
}

// Check entropy (high entropy = likely encrypted)
console.log(`\n=== Entropy Analysis ===`);
const byteCounts = new Array(256).fill(0);
for (let i = 0; i < Math.min(data.length, 100000); i++) {
    byteCounts[data[i]]++;
}
const total = Math.min(data.length, 100000);
let entropy = 0;
for (const count of byteCounts) {
    if (count > 0) {
        const p = count / total;
        entropy -= p * Math.log2(p);
    }
}
console.log(`Entropy: ${entropy.toFixed(4)} bits per byte`);
console.log(`  (Random/encrypted data: ~8.0, Compressed: 6-7, Plain text: 4-5)`);

if (entropy > 7.9) {
    console.log(`\n*** HIGH ENTROPY - File appears to be ENCRYPTED ***`);
    console.log(`The conversation data is encrypted and cannot be decoded without the encryption key.`);
    console.log(`The encryption key is likely tied to your Antigravity account or machine.`);
} else if (entropy > 6) {
    console.log(`\n*** MEDIUM ENTROPY - File appears to be COMPRESSED ***`);
} else {
    console.log(`\n*** LOW ENTROPY - File might contain readable data ***`);
}
ê"(000000000000000000000000000000000000000023file:///c:/Users/.gemini/antigravity/decode_chat.js:file:///c:/Users/.gemini
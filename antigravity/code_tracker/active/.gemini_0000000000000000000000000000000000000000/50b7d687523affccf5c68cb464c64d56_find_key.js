™const fs = require('fs');
const path = require('path');

// The encryption key might be in the state.vscdb SQLite database
// VSCode stores secrets in the state database with a specific prefix

const dbPath = 'C:\\Users\\Krish\\AppData\\Roaming\\Antigravity\\User\\globalStorage\\state.vscdb';

console.log('=== Analyzing state.vscdb for encryption keys ===\n');

// Read the database file as binary and search for key patterns
const dbData = fs.readFileSync(dbPath);
console.log(`Database size: ${dbData.length} bytes`);

// Search for common key patterns
const patterns = [
    'encryptionKey',
    'secretKey',
    'cascadeKey',
    'conversationKey',
    'brain',
    'secret.',
    'mcpEncryptionKey',
    'antigravity'
];

console.log('\nSearching for key-related strings:');
const dbText = dbData.toString('utf8');

for (const pattern of patterns) {
    const idx = dbText.indexOf(pattern);
    if (idx >= 0) {
        console.log(`\nFound "${pattern}" at position ${idx}:`);
        // Extract surrounding context
        const start = Math.max(0, idx - 20);
        const end = Math.min(dbData.length, idx + pattern.length + 100);
        const context = dbData.slice(start, end);
        console.log(`  Hex: ${context.toString('hex').substring(0, 200)}`);
        console.log(`  Text: ${context.toString('utf8').replace(/[^\x20-\x7E]/g, '.')}`);
    }
}

// Look for JSON objects containing keys
console.log('\n\nSearching for JSON key objects:');
const jsonPattern = /\{[^{}]*key[^{}]*\}/gi;
const jsonMatches = dbText.match(jsonPattern);
if (jsonMatches) {
    console.log(`Found ${jsonMatches.length} JSON objects with 'key':`);
    jsonMatches.slice(0, 10).forEach((m, i) => {
        // Only show if it looks like an actual key
        if (m.length < 500 && (m.includes('k') || m.includes('kty'))) {
            console.log(`  ${i + 1}: ${m.substring(0, 200)}`);
        }
    });
}

// Search for base64-encoded keys (JWK format starts with ey)
console.log('\n\nSearching for JWK keys (base64):');
const jwkPattern = /eyJ[A-Za-z0-9+/=]{50,500}/g;
const jwkMatches = dbText.match(jwkPattern);
if (jwkMatches) {
    console.log(`Found ${jwkMatches.length} potential JWK keys:`);
    jwkMatches.slice(0, 5).forEach((m, i) => {
        console.log(`  ${i + 1}: ${m.substring(0, 100)}...`);
        try {
            const decoded = Buffer.from(m, 'base64').toString('utf8');
            console.log(`     Decoded: ${decoded.substring(0, 100)}`);
        } catch (e) { }
    });
}

// Look specifically for service key storage pattern
console.log('\n\nSearching for secret storage entries:');
const secretPattern = /secret\.[^.]+\.\w+/gi;
const secretMatches = dbText.match(secretPattern);
if (secretMatches) {
    const unique = [...new Set(secretMatches)];
    console.log(`Found ${unique.length} secret storage entries:`);
    unique.forEach(s => console.log(`  - ${s}`));
}
™*cascade08"(000000000000000000000000000000000000000020file:///C:/Users/.gemini/antigravity/find_key.js:file:///C:/Users/.gemini
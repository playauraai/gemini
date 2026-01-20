ÿconst fs = require('fs');
const path = require('path');

// Read the extension.js file
const extPath = 'C:\\Users\\Krish\\AppData\\Local\\Programs\\Antigravity\\resources\\app\\extensions\\antigravity\\dist\\extension.js';
const content = fs.readFileSync(extPath, 'utf8');

console.log('=== Searching Antigravity Extension for Encryption Logic ===\n');

// Search patterns
const patterns = [
    { name: 'XOR operation', regex: /(\^=?\s*\d|xor)/gi },
    { name: 'Buffer operations', regex: /Buffer\.(from|alloc|concat)/g },
    { name: 'Crypto require', regex: /require\(['"](crypto|node:crypto)['"]\)/g },
    { name: 'Random bytes', regex: /randomBytes|getRandomValues/g },
    { name: 'Key derivation', regex: /(pbkdf2|scrypt|argon2|deriveKey)/gi },
    { name: 'HMAC', regex: /createHmac|hmac/gi },
    { name: 'Stream cipher', regex: /(createCipheriv|createDecipheriv)/g },
    { name: 'ChaCha20', regex: /chacha/gi },
    { name: 'Salsa20', regex: /salsa/gi }
];

for (const p of patterns) {
    const matches = content.match(p.regex);
    console.log(`${p.name}: ${matches ? matches.length : 0} matches`);
}

// Look specifically for code that reads/writes .pb files
console.log('\n=== Looking for .pb file handling ===');
const pbPattern = /\.pb['"]/g;
const pbMatches = content.match(pbPattern);
console.log(`.pb file references: ${pbMatches ? pbMatches.length : 0}`);

// Find where files are written in the .gemini folder
console.log('\n=== Looking for file save patterns ===');

// Search for 32-byte key patterns (256-bit encryption keys)
const keyPatterns = content.match(/new Uint8Array\(32\)|Buffer\.alloc\(32\)/g);
console.log(`32-byte key allocations: ${keyPatterns ? keyPatterns.length : 0}`);

// Look for the actual encryption/decryption function
console.log('\n=== Searching for encryption function patterns ===');

// Find functions that take binary data and return binary data
const funcPatterns = [
    { name: 'encrypt function', regex: /encrypt\s*[:=]\s*(?:async\s+)?function|function\s+encrypt/gi },
    { name: 'decrypt function', regex: /decrypt\s*[:=]\s*(?:async\s+)?function|function\s+decrypt/gi },
    { name: 'seal/unseal', regex: /(seal|unseal)\s*[:=]/gi },
    { name: 'obfuscate', regex: /obfuscat/gi },
    { name: 'encode/decode binary', regex: /(encodeBinary|decodeBinary)/gi }
];

for (const p of funcPatterns) {
    const matches = content.match(p.regex);
    if (matches && matches.length > 0) {
        console.log(`${p.name}: ${matches.length} - ${matches.slice(0, 3).join(', ')}`);
    }
}

// Try to find the installation_id which might be used as encryption key source
console.log('\n=== Looking for installation_id usage ===');
const instIdMatches = content.match(/.{50}installation_id.{100}/g);
if (instIdMatches) {
    console.log(`Found ${instIdMatches.length} references to installation_id:`);
    instIdMatches.slice(0, 3).forEach((m, i) => {
        console.log(`  ${i + 1}: ...${m.substring(0, 100)}...`);
    });
}

// Look for protobuf Message classes that handle conversations
console.log('\n=== Looking for Conversation protobuf message ===');
const convMsgMatches = content.match(/.{30}Conversation.{80}/g);
if (convMsgMatches) {
    console.log(`Found ${convMsgMatches.length} Conversation references`);
    // Look for unique ones
    const unique = new Set(convMsgMatches.filter(m => m.includes('class') || m.includes('Message')));
    console.log(`Unique conversation class patterns: ${unique.size}`);
}

console.log('\n=== Done ===');
ÿ"(00000000000000000000000000000000000000002:file:///c:/Users/.gemini/antigravity/analyze_encryption.js:file:///c:/Users/.gemini
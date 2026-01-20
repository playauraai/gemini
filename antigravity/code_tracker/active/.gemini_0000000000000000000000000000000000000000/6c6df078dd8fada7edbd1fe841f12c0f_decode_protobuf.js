Ü)/**
 * Attempt to decode the .pb conversation file using protobuf methods
 * The Antigravity extension uses protobuf-es for serialization
 */

const fs = require('fs');
const path = require('path');

const convPath = 'C:\\Users\\.gemini\\antigravity\\conversations\\cb2df0e4-1022-4474-b91a-f6ab41e113aa.pb';
const data = fs.readFileSync(convPath);

console.log('=== Protobuf-based Decoding ===\n');
console.log(`File size: ${data.length} bytes`);

// Look for protobuf structure patterns
// In protobuf, fields are encoded as (field_number << 3) | wire_type
// Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit

console.log('\n=== Scanning for protobuf field patterns ===');

function decodeVarint(buf, offset = 0) {
    let result = 0n;
    let shift = 0n;
    let i = offset;
    while (i < buf.length) {
        const byte = BigInt(buf[i]);
        result |= (byte & 0x7fn) << shift;
        i++;
        if ((byte & 0x80n) === 0n) break;
        shift += 7n;
    }
    return { value: result, bytesRead: i - offset };
}

// Try to interpret first bytes as protobuf field tags
for (let startOffset = 0; startOffset < 64; startOffset++) {
    const byte = data[startOffset];
    const fieldNum = byte >> 3;
    const wireType = byte & 0x7;

    if (fieldNum >= 1 && fieldNum <= 20 && wireType <= 5) {
        console.log(`Byte ${startOffset}: Field ${fieldNum}, Wire type ${wireType} (${['varint', '64-bit', 'len-delim', 'start-group', 'end-group', '32-bit'][wireType]})`);
    }
}

// The file might have a custom header before the protobuf data
// Let's look for common header patterns

console.log('\n=== Looking for header structure ===');

// Check if first 4/8 bytes are a length prefix
const len32 = data.readUInt32LE(0);
const len32BE = data.readUInt32BE(0);
console.log(`First 4 bytes as uint32 LE: ${len32}`);
console.log(`First 4 bytes as uint32 BE: ${len32BE}`);

// Check if there's a version number
console.log(`\nPossible version bytes:`);
for (let i = 0; i < 8; i++) {
    console.log(`  Byte ${i}: ${data[i]} (0x${data[i].toString(16)})`);
}

// Try to find readable strings by looking for common message fields
console.log('\n=== Searching for readable content patterns ===');

const searchPatterns = [
    'sessionId',
    'creationDate',
    'requests',
    'response',
    'message',
    'content',
    'user',
    'assistant',
    'timestamp'
];

for (const pattern of searchPatterns) {
    let found = false;
    for (let i = 0; i < data.length - pattern.length; i++) {
        let match = true;
        for (let j = 0; j < pattern.length; j++) {
            if (data[i + j] !== pattern.charCodeAt(j)) {
                match = false;
                break;
            }
        }
        if (match) {
            console.log(`Found "${pattern}" at offset ${i}`);
            // Show context
            const contextStart = Math.max(0, i - 10);
            const contextEnd = Math.min(data.length, i + pattern.length + 50);
            console.log(`  Context: ...${data.slice(contextStart, contextEnd).toString('utf8').replace(/[^\x20-\x7E]/g, '.')}...`);
            found = true;
            break;
        }
    }
}

// Check if the data might be protobuf with a nonce/IV prepended
console.log('\n=== Trying AES-GCM with 12-byte nonce ===');

const crypto = require('crypto');

// The key might be derived from the installation_id in a specific way
const installId = fs.readFileSync('C:\\Users\\.gemini\\antigravity\\installation_id', 'utf8').trim();

// Try different key derivation methods
const keyMethods = [
    { name: 'SHA-256 of install_id', key: crypto.createHash('sha256').update(installId).digest() },
    { name: 'SHA-256 of install_id bytes', key: crypto.createHash('sha256').update(Buffer.from(installId)).digest() },
    { name: 'HMAC-SHA256 with empty key', key: crypto.createHmac('sha256', '').update(installId).digest() },
    { name: 'install_id padded to 32', key: Buffer.from(installId.replace(/-/g, '').padEnd(32, '0').slice(0, 32)) }
];

for (const method of keyMethods) {
    // Try with first 12 bytes as IV
    try {
        const iv = data.slice(0, 12);
        const authTag = data.slice(data.length - 16);
        const ciphertext = data.slice(12, data.length - 16);

        const decipher = crypto.createDecipheriv('aes-256-gcm', method.key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

        console.log(`SUCCESS with ${method.name}!`);
        console.log(`Decrypted first 200 bytes: ${decrypted.slice(0, 200).toString('utf8')}`);
        fs.writeFileSync(convPath + '.decrypted', decrypted);
        process.exit(0);
    } catch (e) {
        // Failed, try next
    }
}

console.log('AES-GCM decryption failed with all key derivation methods');

// Final summary
console.log('\n=== Summary ===');
console.log('The file appears to be encrypted with a key that is NOT directly derived from installation_id.');
console.log('The encryption key is likely stored in the Windows Credential Manager or a secure enclave.');
console.log('\nTo validate the chat works, restart Antigravity and check if the conversation appears in history.');
Ü)*cascade08"(000000000000000000000000000000000000000027file:///C:/Users/.gemini/antigravity/decode_protobuf.js:file:///C:/Users/.gemini
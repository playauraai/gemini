Å&const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Read the conversation file and installation_id
const convPath = 'C:\\Users\\.gemini\\antigravity\\conversations\\cb2df0e4-1022-4474-b91a-f6ab41e113aa.pb';
const installIdPath = 'C:\\Users\\.gemini\\antigravity\\installation_id';

const convData = fs.readFileSync(convPath);
const installId = fs.readFileSync(installIdPath, 'utf8').trim();

console.log('=== Attempting to Decrypt Conversation ===\n');
console.log(`Installation ID: ${installId}`);
console.log(`Conversation file size: ${convData.length} bytes`);
console.log(`First 32 bytes (hex): ${convData.slice(0, 32).toString('hex')}`);

// Try different decryption approaches

// 1. Try XOR with installation_id
console.log('\n=== Method 1: XOR with installation_id ===');
const keyBuffer = Buffer.from(installId);
const xorResult = Buffer.alloc(Math.min(1000, convData.length));
for (let i = 0; i < xorResult.length; i++) {
    xorResult[i] = convData[i] ^ keyBuffer[i % keyBuffer.length];
}
console.log(`XOR result first 100 bytes: ${xorResult.slice(0, 100).toString('hex')}`);
// Check if it looks like valid data
const xorText = xorResult.toString('utf8');
if (xorText.includes('{') || xorText.includes('session')) {
    console.log('XOR might have worked! Contains JSON-like chars');
    console.log(`Text preview: ${xorText.substring(0, 200)}`);
}

// 2. Try AES-256-GCM with key derived from installation_id
console.log('\n=== Method 2: AES-GCM with installation_id key ===');
try {
    // The first 12-16 bytes might be the IV/nonce
    const iv = convData.slice(0, 12);
    const authTag = convData.slice(convData.length - 16);
    const ciphertext = convData.slice(12, convData.length - 16);

    // Derive key from installation_id
    const key = crypto.createHash('sha256').update(installId).digest();

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    console.log('AES-GCM decryption succeeded!');
    console.log(`Decrypted size: ${decrypted.length}`);
    console.log(`First 200 chars: ${decrypted.slice(0, 200).toString('utf8')}`);

    // Save the decrypted content
    fs.writeFileSync(convPath + '.decrypted.json', decrypted);
    console.log(`\nSaved to: ${convPath}.decrypted.json`);
} catch (e) {
    console.log(`AES-GCM failed: ${e.message}`);
}

// 3. Try AES-256-CBC 
console.log('\n=== Method 3: AES-CBC with various IV positions ===');
try {
    const iv = convData.slice(0, 16);
    const ciphertext = convData.slice(16);
    const key = crypto.createHash('sha256').update(installId).digest();

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    decipher.setAutoPadding(false);

    const decrypted = Buffer.concat([decipher.update(ciphertext.slice(0, 1024))]);
    console.log(`AES-CBC partial result: ${decrypted.slice(0, 50).toString('hex')}`);
} catch (e) {
    console.log(`AES-CBC failed: ${e.message}`);
}

// 4. Check if it's just raw protobuf with some header
console.log('\n=== Method 4: Check for protobuf structure ===');
// Protobuf field tags should appear at regular intervals
let possibleProtoStart = -1;
for (let i = 0; i < Math.min(1000, convData.length); i++) {
    // Common protobuf field tags for field 1 (0x08, 0x0a, 0x0d, 0x09)
    if (convData[i] === 0x08 || convData[i] === 0x0a) {
        // Check if the surrounding bytes look proto-like
        if (convData[i + 1] < 128 || convData[i + 2] < 128) {
            possibleProtoStart = i;
            console.log(`Possible protobuf start at byte ${i}: ${convData.slice(i, i + 20).toString('hex')}`);
            break;
        }
    }
}

// 5. Try different key sources
console.log('\n=== Method 5: Try machine-specific keys ===');

// Read user_settings.pb to see if there's a key there
const userSettingsPath = 'C:\\Users\\.gemini\\antigravity\\user_settings.pb';
if (fs.existsSync(userSettingsPath)) {
    const userSettings = fs.readFileSync(userSettingsPath);
    console.log(`user_settings.pb size: ${userSettings.length}`);
    console.log(`user_settings.pb content: ${userSettings.toString('hex')}`);

    // This looks like protobuf - try to parse field 1
    // 08 01 = field 1, varint, value 1
    // 48 F4 07 = field 9, varint, value 1012
    if (userSettings[0] === 0x08) {
        console.log('user_settings.pb appears to be valid protobuf');
    }
}

console.log('\n=== Analysis Complete ===');
console.log('The conversation file appears to be encrypted.');
console.log('The encryption key is likely stored in the Antigravity secret storage');
console.log('which is managed by the OS keychain/credential manager.');
Å&*cascade08"(000000000000000000000000000000000000000023file:///C:/Users/.gemini/antigravity/try_decrypt.js:file:///C:/Users/.gemini
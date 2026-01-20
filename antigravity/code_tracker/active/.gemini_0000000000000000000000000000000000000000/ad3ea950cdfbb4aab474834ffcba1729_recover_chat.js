Â#const fs = require('fs');
const path = require('path');

// File paths
const oldFile = 'D:\\GenemiMsrVmexit\\.gemini\\antigravity\\conversations\\cb2df0e4-1022-4474-b91a-f6ab41e113aa.pb';
const newFile = 'C:\\Users\\.gemini\\antigravity\\conversations\\cb2df0e4-1022-4474-b91a-f6ab41e113aa.pb';
const backupFile = 'C:\\Users\\.gemini\\antigravity\\conversations\\cb2df0e4-1022-4474-b91a-f6ab41e113aa.pb.corrupted';
const outputFile = 'C:\\Users\\.gemini\\antigravity\\conversations\\cb2df0e4-1022-4474-b91a-f6ab41e113aa.pb';

console.log('=== Antigravity Chat Recovery Tool ===\n');

// Read both files
const oldData = fs.readFileSync(oldFile);
const newData = fs.readFileSync(newFile);

console.log(`Old file (working backup): ${oldData.length.toLocaleString()} bytes`);
console.log(`New file (corrupted): ${newData.length.toLocaleString()} bytes`);

// Find where zeros start in new file
let zerosStart = newData.length;
for (let i = newData.length - 1; i >= 0; i--) {
    if (newData[i] !== 0) {
        zerosStart = i + 1;
        break;
    }
}

console.log(`\nNew file analysis:`);
console.log(`  - Actual data: ${zerosStart.toLocaleString()} bytes (${(zerosStart / 1024 / 1024).toFixed(2)} MB)`);
console.log(`  - Trailing zeros: ${(newData.length - zerosStart).toLocaleString()} bytes`);
console.log(`  - Data percentage: ${((zerosStart / newData.length) * 100).toFixed(1)}%`);

// Compare headers
console.log(`\nFile headers comparison:`);
console.log(`  Old: ${oldData.slice(0, 20).toString('hex').toUpperCase()}`);
console.log(`  New: ${newData.slice(0, 20).toString('hex').toUpperCase()}`);

const headersMatch = oldData.slice(0, 20).equals(newData.slice(0, 20));
console.log(`  Headers match: ${headersMatch ? 'YES' : 'NO'}`);

// Check if old data exists somewhere in new file
console.log(`\nSearching for old file signature in new file...`);
const oldSignature = oldData.slice(0, 32);
let foundAt = -1;
for (let i = 0; i < zerosStart - 32; i++) {
    if (newData.slice(i, i + 32).equals(oldSignature)) {
        foundAt = i;
        break;
    }
}

if (foundAt >= 0) {
    console.log(`  Found old signature at offset: ${foundAt}`);
} else {
    console.log(`  Old signature NOT found in new file`);
}

// Recovery options
console.log(`\n=== RECOVERY OPTIONS ===\n`);

console.log(`Option 1: RESTORE from backup`);
console.log(`  The old file (${(oldData.length / 1024 / 1024).toFixed(2)} MB) appears to be valid.`);
console.log(`  You will lose any newer conversations that were in the corrupted file.`);
console.log(`  Command: Copy old file to replace corrupted file\n`);

console.log(`Option 2: TRUNCATE corrupted file`);
console.log(`  Remove trailing zeros from corrupted file.`);
console.log(`  This keeps the ${(zerosStart / 1024 / 1024).toFixed(2)} MB of data in the new file.`);
console.log(`  May or may not work depending on if the header is valid.\n`);

// Ask user what to do
console.log(`=== RECOMMENDED ACTION ===`);
if (!headersMatch && oldData.length > zerosStart) {
    console.log(`The new file has different headers and less actual data than the backup.`);
    console.log(`RECOMMENDATION: Restore from the backup file.\n`);
    console.log(`To restore, run this script with --restore flag`);
} else {
    console.log(`Try truncating the corrupted file first.`);
}

// Handle command line args
if (process.argv.includes('--restore')) {
    console.log(`\n=== RESTORING FROM BACKUP ===`);

    // Backup the corrupted file first
    console.log(`Backing up corrupted file to: ${backupFile}`);
    fs.copyFileSync(newFile, backupFile);

    // Copy old file to new location
    console.log(`Restoring from: ${oldFile}`);
    fs.copyFileSync(oldFile, outputFile);

    console.log(`\nDONE! The conversation file has been restored from backup.`);
    console.log(`Your corrupted file was saved to: ${backupFile}`);
    console.log(`\nPlease restart Antigravity to see if the chat loads.`);
}

if (process.argv.includes('--truncate')) {
    console.log(`\n=== TRUNCATING CORRUPTED FILE ===`);

    // Backup first
    console.log(`Backing up corrupted file to: ${backupFile}`);
    fs.copyFileSync(newFile, backupFile);

    // Truncate
    const truncatedData = newData.slice(0, zerosStart);
    fs.writeFileSync(outputFile, truncatedData);

    console.log(`\nDONE! File truncated to ${zerosStart.toLocaleString()} bytes.`);
    console.log(`\nPlease restart Antigravity to see if the chat loads.`);
}
Â#"(000000000000000000000000000000000000000024file:///c:/Users/.gemini/antigravity/recover_chat.js:file:///c:/Users/.gemini
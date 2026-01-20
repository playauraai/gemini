Š#!/usr/bin/env python3
"""
Count shellcode bytes and find patch offsets
"""
import re

# Read the file
with open(r'C:\inject\Spoofers\SVMHypervisorV6Fixed2.cpp', 'r') as f:
    content = f.read()

# Extract shellcode array
match = re.search(r'v6Fixed2Shellcode\[\]\s*=\s*\{([^}]+)\}', content, re.DOTALL)
if not match:
    print("Could not find shellcode array!")
    exit(1)

shellcode_text = match.group(1)

# Extract all hex bytes
hex_pattern = re.compile(r'0x([0-9A-Fa-f]{2})')
bytes_list = [int(m.group(1), 16) for m in hex_pattern.finditer(shellcode_text)]

print(f"Total shellcode bytes: {len(bytes_list)}")
print()

# Find all mov rax, imm64 (0x48 0xB8) instructions
print("Looking for 'mov rax, imm64' (48 B8) instructions:")
for i in range(len(bytes_list) - 1):
    if bytes_list[i] == 0x48 and bytes_list[i+1] == 0xB8:
        # The immediate starts at i+2
        imm_offset = i + 2
        print(f"  Found at byte {i}: 48 B8 at offset {i}, immediate starts at offset {imm_offset}")

print()

# Find all mov rbx, imm64 (0x48 0xBB) instructions
print("Looking for 'mov rbx, imm64' (48 BB) instructions:")
for i in range(len(bytes_list) - 1):
    if bytes_list[i] == 0x48 and bytes_list[i+1] == 0xBB:
        imm_offset = i + 2
        print(f"  Found at byte {i}: 48 BB at offset {i}, immediate starts at offset {imm_offset}")

print()

# Find mov eax, imm32 (0xB8) that might be HSAVE_PA
print("Looking for 'mov eax, imm32' (B8) followed by 'mov edx, imm32' (BA):")
for i in range(len(bytes_list) - 10):
    if bytes_list[i] == 0xB8 and bytes_list[i+5] == 0xBA:
        print(f"  Found pair at offset {i} and {i+5}")
        print(f"    HSAVE_PA_LOW should be at offset {i+1}")
        print(f"    HSAVE_PA_HIGH should be at offset {i+6}")

print()
print("=" * 60)
print("RECOMMENDED OFFSETS:")
print("=" * 60)

# Verify current defines
hsave_low = None
hsave_high = None
vmcb_va = None
vmcb_pa = None

for i in range(len(bytes_list) - 10):
    # HSAVE pair
    if bytes_list[i] == 0xB8 and bytes_list[i+5] == 0xBA:
        if hsave_low is None:
            hsave_low = i + 1
            hsave_high = i + 6
            
# VMCB_VA (first 48 BB)
for i in range(len(bytes_list) - 1):
    if bytes_list[i] == 0x48 and bytes_list[i+1] == 0xBB:
        vmcb_va = i + 2
        break

# VMCB_PA (first 48 B8 after VMCB_VA)        
for i in range(vmcb_va + 8 if vmcb_va else 0, len(bytes_list) - 1):
    if bytes_list[i] == 0x48 and bytes_list[i+1] == 0xB8:
        vmcb_pa = i + 2
        break

print(f"#define HSAVE_PA_LOW_OFFSET  {hsave_low}")
print(f"#define HSAVE_PA_HIGH_OFFSET {hsave_high}")
print(f"#define VMCB_VA_OFFSET       {vmcb_va}")
print(f"#define VMCB_PA_OFFSET       {vmcb_pa}")

print()
print("Verification (bytes at those offsets should be 00):")
if hsave_low:
    print(f"  Bytes before HSAVE_LOW: {hex(bytes_list[hsave_low-1])} (expect B8)")
if vmcb_va:
    print(f"  Bytes before VMCB_VA: {hex(bytes_list[vmcb_va-2])} {hex(bytes_list[vmcb_va-1])} (expect 48 BB)")
if vmcb_pa:
    print(f"  Bytes before VMCB_PA: {hex(bytes_list[vmcb_pa-2])} {hex(bytes_list[vmcb_pa-1])} (expect 48 B8)")
Š25file:///c:/inject/Spoofers/count_shellcode_offsets.py
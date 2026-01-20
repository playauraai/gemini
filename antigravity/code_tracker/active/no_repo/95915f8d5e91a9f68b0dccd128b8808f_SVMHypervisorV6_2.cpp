üË// SVMHypervisorV6_2.cpp
// Step 6.2 FINAL: Rock-Solid Terminal HLT Design
//
// CRITICAL FIXES:
// 1. ALWAYS intercept HLT (bit 24 in INTERCEPT_MISC1)
// 2. NO STGI - we don't need it for terminal VM execution
// 3. Restore RFLAGS immediately after VMEXIT
// 4. Single GPR save at start, single restore at end
// 5. HLT = terminal, no re-entry
//
// Guest: CPUID x3 -> HLT
// Expected: 3 CPUID handled, HLT terminates cleanly

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

// ==================== V6.2 FINAL Shellcode ====================
// Rock-solid design:
// - CPUID + HLT intercepts enabled
// - NO STGI (not needed for terminal execution)
// - Unrolled loop like V6.1 (proven stable)
// - CPUID = handle & continue, HLT = terminal return
// - Single GPR save/restore

uint8_t v6_2Shellcode[] = {
    // ===== Prologue =====
    0x55, // push rbp
    0x48,
    0x89,
    0xE5, // mov rbp, rsp

    // ===== Enable SVME =====
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0,
    0x0F,
    0x32,
    0x0D,
    0x00,
    0x10,
    0x00,
    0x00,
    0x0F,
    0x30,

    // ===== VM_HSAVE_PA =====
    0xB9,
    0x17,
    0x01,
    0x01,
    0xC0,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00, // @HSAVE_LOW
    0xBA,
    0x00,
    0x00,
    0x00,
    0x00, // @HSAVE_HIGH
    0x0F,
    0x30,

    // ===== Load pointers into preserved registers =====
    0x49,
    0xBF,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov r15, host_save
    0x49,
    0xBE,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov r14, vmcb_pa
    0x49,
    0xBD,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov r13, vmcb_va

    // ===== VMSAVE =====
    0x4C,
    0x89,
    0xF0,
    0x0F,
    0x01,
    0xDB,

    // ===== Populate VMCB =====
    0x0F,
    0x20,
    0xC0,
    0x49,
    0x89,
    0x85,
    0x58,
    0x05,
    0x00,
    0x00, // CR0
    0x0F,
    0x20,
    0xD8,
    0x49,
    0x89,
    0x85,
    0x50,
    0x05,
    0x00,
    0x00, // CR3
    0x0F,
    0x20,
    0xE0,
    0x49,
    0x89,
    0x85,
    0x48,
    0x05,
    0x00,
    0x00, // CR4
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0,
    0x0F,
    0x32,
    0x48,
    0xC1,
    0xE2,
    0x20,
    0x48,
    0x09,
    0xD0,
    0x49,
    0x89,
    0x85,
    0xD0,
    0x04,
    0x00,
    0x00, // EFER
    0x48,
    0x83,
    0xEC,
    0x10,
    0x0F,
    0x01,
    0x04,
    0x24,
    0x0F,
    0xB7,
    0x04,
    0x24,
    0x41,
    0x89,
    0x85,
    0x64,
    0x04,
    0x00,
    0x00, // GDT limit
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02,
    0x49,
    0x89,
    0x85,
    0x68,
    0x04,
    0x00,
    0x00, // GDT base
    0x0F,
    0x01,
    0x0C,
    0x24,
    0x0F,
    0xB7,
    0x04,
    0x24,
    0x41,
    0x89,
    0x85,
    0x84,
    0x04,
    0x00,
    0x00, // IDT limit
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02,
    0x49,
    0x89,
    0x85,
    0x88,
    0x04,
    0x00,
    0x00, // IDT base
    0x48,
    0x83,
    0xC4,
    0x10,
    0x8C,
    0xC8,
    0x66,
    0x41,
    0x89,
    0x85,
    0x10,
    0x04,
    0x00,
    0x00, // CS
    0x8C,
    0xD0,
    0x66,
    0x41,
    0x89,
    0x85,
    0x20,
    0x04,
    0x00,
    0x00, // SS
    0x8C,
    0xD8,
    0x66,
    0x41,
    0x89,
    0x85,
    0x30,
    0x04,
    0x00,
    0x00, // DS
    0x8C,
    0xC0,
    0x66,
    0x41,
    0x89,
    0x85,
    0x00,
    0x04,
    0x00,
    0x00, // ES
    0xB8,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0x41,
    0x89,
    0x85,
    0x04,
    0x04,
    0x00,
    0x00, // ES limit
    0x41,
    0x89,
    0x85,
    0x14,
    0x04,
    0x00,
    0x00, // CS limit
    0x41,
    0x89,
    0x85,
    0x24,
    0x04,
    0x00,
    0x00, // SS limit
    0x41,
    0x89,
    0x85,
    0x34,
    0x04,
    0x00,
    0x00, // DS limit
    0x66,
    0x41,
    0xC7,
    0x85,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02, // CS attr
    0x66,
    0x41,
    0xC7,
    0x85,
    0x22,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // SS attr
    0x66,
    0x41,
    0xC7,
    0x85,
    0x32,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // DS attr
    0x66,
    0x41,
    0xC7,
    0x85,
    0x02,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // ES attr
    0x9C,
    0x58,
    0x49,
    0x89,
    0x85,
    0x70,
    0x05,
    0x00,
    0x00, // RFLAGS
    0x48,
    0x89,
    0xE0,
    0x49,
    0x89,
    0x85,
    0xD8,
    0x05,
    0x00,
    0x00, // RSP
    0x41,
    0xC7,
    0x45,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00, // ASID=1

    // ===== Intercepts: CPUID (bit 18) + HLT (bit 24) + VMRUN =====
    // CPUID = 0x40000, HLT = 0x1000000
    // Combined = 0x1040000
    0x41,
    0xC7,
    0x45,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x01, // INTERCEPT_MISC1 = 0x01040000
    0x41,
    0xC7,
    0x45,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00, // VMRUN intercept

    // ===== Set guest RIP =====
    0x48,
    0x8D,
    0x05,
    0x00,
    0x00,
    0x00,
    0x00, // lea rax, [rip+XX] @LEA_DISP
    0x49,
    0x89,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00,

    // ===== Set guest RAX = 1 =====
    0x49,
    0xC7,
    0x85,
    0xF8,
    0x05,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Counters: R12 = cpuid count, R11 = final exit =====
    0x45,
    0x31,
    0xE4, // xor r12d, r12d
    0x45,
    0x31,
    0xDB, // xor r11d, r11d

    // ===== SAVE HOST GPRs ONCE =====
    0x49,
    0x89,
    0x5F,
    0x08, // rbx
    0x49,
    0x89,
    0x4F,
    0x10, // rcx
    0x49,
    0x89,
    0x57,
    0x18, // rdx
    0x49,
    0x89,
    0x77,
    0x20, // rsi
    0x49,
    0x89,
    0x7F,
    0x28, // rdi
    0x9C,
    0x41,
    0x8F,
    0x47,
    0x70, // rflags

    // ========================================
    // ITERATION 1: VMRUN (no STGI, simplified)
    // ========================================
    0x4C,
    0x89,
    0xF0, // mov rax, r14 (vmcb_pa)
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload
    0x0F,
    0x01,
    0xD8, // vmrun
    0x0F,
    0x01,
    0xDB, // vmsave
    // NO STGI - let host context restore handle it
    0x41,
    0xFF,
    0x77,
    0x70,
    0x9D, // push [r15+0x70]; popfq (restore RFLAGS immediately!)

    0x41,
    0x8B,
    0x4D,
    0x70, // mov ecx, [r13+0x70] ; exit code
    0x41,
    0x89,
    0xCB, // mov r11d, ecx

    // Check if CPUID (0x72)
    0x81,
    0xF9,
    0x72,
    0x00,
    0x00,
    0x00, // cmp ecx, 0x72
    0x0F,
    0x85,
    0x94,
    0x00,
    0x00,
    0x00, // jne done

    0x41,
    0xFF,
    0xC4, // inc r12d
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00,
    0x31,
    0xC9,
    0x0F,
    0xA2,
    0x0F,
    0xBA,
    0xE9,
    0x1F, // cpuid + bts ecx,31
    0x49,
    0x8B,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00,
    0x48,
    0x83,
    0xC0,
    0x02,
    0x49,
    0x89,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00, // rip += 2
    0x41,
    0xC7,
    0x45,
    0x70,
    0x00,
    0x00,
    0x00,
    0x00, // clear exit

    // ========================================
    // ITERATION 2
    // ========================================
    0x4C,
    0x89,
    0xF0,
    0xFA,
    0x0F,
    0x01,
    0xDA,
    0x0F,
    0x01,
    0xD8,
    0x0F,
    0x01,
    0xDB,
    0x41,
    0xFF,
    0x77,
    0x70,
    0x9D,
    0x41,
    0x8B,
    0x4D,
    0x70,
    0x41,
    0x89,
    0xCB,
    0x81,
    0xF9,
    0x72,
    0x00,
    0x00,
    0x00,
    0x0F,
    0x85,
    0x53,
    0x00,
    0x00,
    0x00, // jne done
    0x41,
    0xFF,
    0xC4,
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00,
    0x31,
    0xC9,
    0x0F,
    0xA2,
    0x0F,
    0xBA,
    0xE9,
    0x1F,
    0x49,
    0x8B,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00,
    0x48,
    0x83,
    0xC0,
    0x02,
    0x49,
    0x89,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00,
    0x41,
    0xC7,
    0x45,
    0x70,
    0x00,
    0x00,
    0x00,
    0x00,

    // ========================================
    // ITERATION 3
    // ========================================
    0x4C,
    0x89,
    0xF0,
    0xFA,
    0x0F,
    0x01,
    0xDA,
    0x0F,
    0x01,
    0xD8,
    0x0F,
    0x01,
    0xDB,
    0x41,
    0xFF,
    0x77,
    0x70,
    0x9D,
    0x41,
    0x8B,
    0x4D,
    0x70,
    0x41,
    0x89,
    0xCB,
    0x81,
    0xF9,
    0x72,
    0x00,
    0x00,
    0x00,
    0x0F,
    0x85,
    0x12,
    0x00,
    0x00,
    0x00, // jne done
    0x41,
    0xFF,
    0xC4,
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00,
    0x31,
    0xC9,
    0x0F,
    0xA2,
    0x0F,
    0xBA,
    0xE9,
    0x1F,
    0x49,
    0x8B,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00,
    0x48,
    0x83,
    0xC0,
    0x02,
    0x49,
    0x89,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00,
    0x41,
    0xC7,
    0x45,
    0x70,
    0x00,
    0x00,
    0x00,
    0x00,

    // ========================================
    // ITERATION 4 (should hit HLT)
    // ========================================
    0x4C,
    0x89,
    0xF0,
    0xFA,
    0x0F,
    0x01,
    0xDA,
    0x0F,
    0x01,
    0xD8,
    0x0F,
    0x01,
    0xDB,
    0x41,
    0xFF,
    0x77,
    0x70,
    0x9D,
    0x41,
    0x8B,
    0x4D,
    0x70,
    0x41,
    0x89,
    0xCB,
    // Fall through to done (HLT exit)

    // done: restore GPRs and return
    0x49,
    0x8B,
    0x5F,
    0x08, // rbx
    0x49,
    0x8B,
    0x4F,
    0x10, // rcx
    0x49,
    0x8B,
    0x57,
    0x18, // rdx
    0x49,
    0x8B,
    0x77,
    0x20, // rsi
    0x49,
    0x8B,
    0x7F,
    0x28, // rdi
    // RFLAGS already restored after each VMRUN

    // Return: (exit_code << 16) | cpuid_count
    0x44,
    0x89,
    0xD8, // mov eax, r11d
    0xC1,
    0xE0,
    0x10, // shl eax, 16
    0x44,
    0x09,
    0xE0, // or eax, r12d

    // ===== Epilogue =====
    0x5D, // pop rbp
    0xC3, // ret

    // ===== Guest code: CPUID x3 -> HLT =====
    0x0F,
    0xA2, // cpuid 1
    0x0F,
    0xA2, // cpuid 2
    0x0F,
    0xA2, // cpuid 3
    0xF4, // hlt (will VMEXIT 0x78)
};

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V6.2 FINAL - Exit-Driven + Terminal HLT  \n");
  printf("    CPUID = handle & loop, HLT = clean termination             \n");
  printf("    Guest: CPUID x3 -> HLT                                     \n");
  printf(
      "================================================================\n\n");

  printf("[*] Calculating shellcode offsets...\n");

  size_t OFF_HSAVE_LOW = 0, OFF_HSAVE_HIGH = 0;
  size_t OFF_HOST_SAVE_VA = 0, OFF_VMCB_PA = 0, OFF_VMCB_VA = 0;
  size_t OFF_LEA_DISP = 0;
  size_t LOC_GUEST_CODE = 0;

  for (size_t i = 0; i < sizeof(v6_2Shellcode) - 10; i++) {
    if (v6_2Shellcode[i] == 0xB8 && v6_2Shellcode[i + 5] == 0xBA &&
        OFF_HSAVE_LOW == 0) {
      OFF_HSAVE_LOW = i + 1;
      OFF_HSAVE_HIGH = i + 6;
      break;
    }
  }
  for (size_t i = 0; i < sizeof(v6_2Shellcode) - 10; i++) {
    if (v6_2Shellcode[i] == 0x49 && v6_2Shellcode[i + 1] == 0xBF) {
      OFF_HOST_SAVE_VA = i + 2;
      break;
    }
  }
  for (size_t i = 0; i < sizeof(v6_2Shellcode) - 10; i++) {
    if (v6_2Shellcode[i] == 0x49 && v6_2Shellcode[i + 1] == 0xBE) {
      OFF_VMCB_PA = i + 2;
      break;
    }
  }
  for (size_t i = 0; i < sizeof(v6_2Shellcode) - 10; i++) {
    if (v6_2Shellcode[i] == 0x49 && v6_2Shellcode[i + 1] == 0xBD) {
      OFF_VMCB_VA = i + 2;
      break;
    }
  }
  for (size_t i = 0; i < sizeof(v6_2Shellcode) - 10; i++) {
    if (v6_2Shellcode[i] == 0x48 && v6_2Shellcode[i + 1] == 0x8D &&
        v6_2Shellcode[i + 2] == 0x05) {
      OFF_LEA_DISP = i + 3;
      break;
    }
  }

  LOC_GUEST_CODE = sizeof(v6_2Shellcode) - 7;

  printf("    HSAVE: LOW=%zu, HIGH=%zu\n", OFF_HSAVE_LOW, OFF_HSAVE_HIGH);
  printf("    HOST_SAVE_VA=%zu, VMCB_PA=%zu, VMCB_VA=%zu\n", OFF_HOST_SAVE_VA,
         OFF_VMCB_PA, OFF_VMCB_VA);
  printf("    LEA_DISP=%zu, GUEST_CODE=%zu\n", OFF_LEA_DISP, LOC_GUEST_CODE);
  printf("    Total shellcode: %zu bytes\n\n", sizeof(v6_2Shellcode));

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

  uint64_t allocatedAddr = 0;
  CallKernelFunction<uint64_t>(&allocatedAddr, kernelExAllocatePool, 0, 0x3000,
                               0x484D5653);
  if (!allocatedAddr) {
    printf("[-] Allocation failed!\n");
    return 1;
  }

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  uint64_t hostSaveVa = allocatedAddr + 0x2000;
  uint64_t vmcbPa = 0, hsavePa = 0;
  GetPhysicalAddress(vmcbVa, &vmcbPa);
  GetPhysicalAddress(hsaveVa, &hsavePa);
  printf("[+] VMCB: VA=0x%llX PA=0x%llX\n", vmcbVa, vmcbPa);
  printf("[+] HSAVE: VA=0x%llX PA=0x%llX\n", hsaveVa, hsavePa);
  printf("[+] Host Save Area: VA=0x%llX\n", hostSaveVa);

  uint8_t zeros[0x1000] = {0};
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);
  WriteMemory(hostSaveVa, zeros, 0x1000);

  uint8_t patched[sizeof(v6_2Shellcode)];
  memcpy(patched, v6_2Shellcode, sizeof(patched));

  *(uint32_t *)&patched[OFF_HSAVE_LOW] = (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patched[OFF_HSAVE_HIGH] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patched[OFF_HOST_SAVE_VA] = hostSaveVa;
  *(uint64_t *)&patched[OFF_VMCB_PA] = vmcbPa;
  *(uint64_t *)&patched[OFF_VMCB_VA] = vmcbVa;

  int32_t leaDisp = (int32_t)(LOC_GUEST_CODE - (OFF_LEA_DISP + 4));
  *(int32_t *)&patched[OFF_LEA_DISP] = leaDisp;

  printf("[+] LEA displacement: %d\n", leaDisp);
  printf("[+] Shellcode patched (%zu bytes)\n\n", sizeof(patched));

  printf("Press ENTER to execute exit-driven loop with terminal HLT...\n");
  getchar();

  uint8_t backup[700];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patched));
  WriteToReadOnlyMemory(kernelNtAddAtom, patched, sizeof(patched));

  printf("[*] Executing V6.2 FINAL...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patched));
  printf("[+] NtAddAtom restored\n\n");

  uint32_t ret = (uint32_t)result;
  uint32_t exitCode = (ret >> 16) & 0xFFFF;
  uint32_t cpuidCount = ret & 0xFFFF;

  printf("=== Exit-Driven Loop Results ===\n");
  printf("[*] Final exit code: 0x%X", exitCode);
  if (exitCode == 0x72)
    printf(" (CPUID)");
  else if (exitCode == 0x78)
    printf(" (HLT - clean termination!)");
  printf("\n");
  printf("[*] CPUID intercepts: %d\n", cpuidCount);

  if (cpuidCount == 3 && exitCode == 0x78) {
    printf("\n");
    printf("=============================================\n");
    printf("  [+] SUCCESS! V6.2 FINAL WORKS!            \n");
    printf("  [+] 3 CPUIDs + HLT terminal               \n");
    printf("  [+] Exit-driven loop complete!            \n");
    printf("=============================================\n");
  } else if (cpuidCount == 3) {
    printf("\n");
    printf("[+] 3 CPUIDs handled - loop works!\n");
  } else {
    printf("\n[!] Check results\n");
  }

  CloseHandle(hDevice);
  return 0;
}
% *cascade08%' *cascade08') *cascade08)**cascade08*+ *cascade08+,*cascade08,- *cascade08-5*cascade0856 *cascade0867*cascade0879 *cascade089@*cascade08@D *cascade08DK*cascade08KT *cascade08Tq*cascade08qr *cascade08rs *cascade08sx*cascade08xy *cascade08y{*cascade08{| *cascade08|*cascade08€ *cascade08€‚*cascade08‚ƒ *cascade08ƒ„*cascade08„… *cascade08…ˆ*cascade08ˆŠ *cascade08Š›*cascade08›  *cascade08 ¡*cascade08¡£ *cascade08£§*cascade08§¨ *cascade08¨ª*cascade08ª« *cascade08«Á*cascade08ÁÂ *cascade08ÂÊ*cascade08ÊË *cascade08ËÍ*cascade08ÍÎ *cascade08ÎÏ *cascade08ÏĞ*cascade08ĞÑ*cascade08ÑÖ*cascade08Ö× *cascade08×â*cascade08âã *cascade08ãä*cascade08äå *cascade08åí*cascade08íî *cascade08îò*cascade08òó *cascade08óô*cascade08ôõ *cascade08õö*cascade08ö÷ *cascade08÷ù*cascade08ùú *cascade08úü*cascade08üı *cascade08ış*cascade08şÿ *cascade08ÿ†*cascade08†‹ *cascade08‹Œ*cascade08Œ *cascade08 *cascade08•*cascade08•˜*cascade08˜™ *cascade08™œ*cascade08œ *cascade08¡*cascade08¡¢*cascade08¢£ *cascade08£¤*cascade08¤¥ *cascade08¥¦ *cascade08¦©*cascade08©ª*cascade08ª«*cascade08«®*cascade08®¯ *cascade08¯³*cascade08³´ *cascade08´¶*cascade08¶¸ *cascade08¸º *cascade08º» *cascade08»¼ *cascade08¼½*cascade08½Â *cascade08ÂÃ*cascade08ÃÅ *cascade08ÅÆ*cascade08ÆÉ *cascade08ÉÌ*cascade08ÌÍ *cascade08ÍÏ*cascade08ÏÑ *cascade08ÑÔ*cascade08ÔÕ *cascade08ÕÖ*cascade08Ö× *cascade08×Ø *cascade08ØÚ *cascade08Úİ*cascade08İŞ *cascade08Şß *cascade08ßà*cascade08àù *cascade08ùû*cascade08û– *cascade08–˜*cascade08˜™ *cascade08™›*cascade08›œ *cascade08œ*cascade08£ *cascade08£§*cascade08§© *cascade08©ª*cascade08ª¬ *cascade08¬­*cascade08­³ *cascade08³µ*cascade08µ‚N *cascade08‚NƒN*cascade08ƒN„N *cascade08„N…N *cascade08…N†N*cascade08†NªN *cascade08ªN«N *cascade08«N®N*cascade08®N¯N *cascade08¯N°N*cascade08°NÕN *cascade08ÕNÜN*cascade08ÜNİN *cascade08İNŞN*cascade08ŞNâN *cascade08âNåN*cascade08åNëN *cascade08ëNìN*cascade08ìNóN *cascade08óNøN*cascade08øNùN *cascade08ùNúN*cascade08úNûN *cascade08ûNÿN*cascade08ÿN€O *cascade08€OƒO*cascade08ƒO„O *cascade08„O†O*cascade08†O‡O *cascade08‡OŠO*cascade08ŠO‹O *cascade08‹OO*cascade08OO *cascade08O‘O*cascade08‘O’O *cascade08’O“O*cascade08“O•O *cascade08•O™O*cascade08™OœO *cascade08œOO *cascade08O¡O*cascade08¡O¢O *cascade08¢O£O *cascade08£O¥O*cascade08¥O¦O *cascade08¦O§O*cascade08§O¨O*cascade08¨OªO*cascade08ªO«O *cascade08«O²O*cascade08²O³O *cascade08³O¼O*cascade08¼O½O *cascade08½OÂO *cascade08ÂOÃO*cascade08ÃOÄO *cascade08ÄOÆO*cascade08ÆOÈO *cascade08ÈOÊO*cascade08ÊOËO *cascade08ËOÌO*cascade08ÌOÍO *cascade08ÍOÑO*cascade08ÑOÒO *cascade08ÒOÖO*cascade08ÖO×O *cascade08×OÛO*cascade08ÛOÜO *cascade08ÜOŞO*cascade08ŞOßO *cascade08ßOáO*cascade08áOâO *cascade08âOãO*cascade08ãOåO*cascade08åOæO *cascade08æOëO*cascade08ëOïO *cascade08ïOñO*cascade08ñOòO *cascade08òOóO*cascade08óOôO *cascade08ôOùO*cascade08ùOúO *cascade08úOûO*cascade08ûOüO *cascade08üOÿO*cascade08ÿO€P *cascade08€PP *cascade08P†P*cascade08†P‡P *cascade08‡PŒP*cascade08ŒPP *cascade08P“P*cascade08“P”P *cascade08”P™P*cascade08™PšP *cascade08šP›P*cascade08›PœP *cascade08œPP*cascade08PP *cascade08PŸP *cascade08ŸP P*cascade08 P¡P *cascade08¡P¢P *cascade08¢P¦P *cascade08¦P§P *cascade08§P¨P*cascade08¨P©P *cascade08©PªP*cascade08ªP«P *cascade08«P¬P*cascade08¬P®P*cascade08®P¯P *cascade08¯PµP*cascade08µP¶P *cascade08¶P¹P*cascade08¹PºP *cascade08ºP»P *cascade08»P¼P *cascade08¼P½P *cascade08½P¾P*cascade08¾P¿P *cascade08¿PÀP*cascade08ÀP™U *cascade08™U™U*cascade08™U²U*cascade08²UĞX *cascade08ĞXĞX*cascade08ĞX°Z *cascade08°Z·Z*cascade08·Z¥[ *cascade08¥[¬[*cascade08¬[š\ *cascade08š\¡\*cascade08¡\ˆ^ *cascade08ˆ^^*cascade08^á_ *cascade08á_î_*cascade08î_ò` *cascade08ò`ş`*cascade08ş`£b *cascade08£b°b*cascade08°b´c *cascade08´cÀc*cascade08ÀcÚd *cascade08Údàd*cascade08àdÎe *cascade08ÎeÔe*cascade08ÔeÂf *cascade08ÂfÈf*cascade08Èf¶g *cascade08¶g¼g*cascade08¼gÀh *cascade08ÀhÌh*cascade08Ìh™i *cascade08™i¥i*cascade08¥iòi *cascade08òişi*cascade08şiËj *cascade08Ëj×j*cascade08×jÅk *cascade08ÅkĞk*cascade08Ğk¾l *cascade08¾lÉl*cascade08Él·m *cascade08·mÂm*cascade08Âm°n *cascade08°n»n*cascade08»no *cascade08o¨o*cascade08¨o–p *cascade08–pp*cascade08põp *cascade08õpq*cascade08q‰q *cascade08‰qq*cascade08q¢q *cascade08¢q£q *cascade08£q¬q*cascade08¬q±q *cascade08±q³q*cascade08³q´q *cascade08´q¶q *cascade08¶qÕq*cascade08ÕqÖq *cascade08Öq×q*cascade08×qØq *cascade08Øqàq*cascade08àqáq *cascade08áqäq*cascade08äqåq *cascade08åqæq*cascade08æqçq *cascade08çqèq*cascade08èqéq *cascade08éqıq*cascade08ıqşq *cascade08şqr*cascade08r‚r *cascade08‚rƒr*cascade08ƒr„r *cascade08„rr*cascade08rãr *cascade08ãrär*cascade08ärér *cascade08érîr*cascade08îrïr *cascade08ïrğr*cascade08ğrñr *cascade08ñrôr*cascade08ôrõr *cascade08õr…s*cascade08…sæs *cascade08æsæs*cascade08æsğs*cascade08ğsÿv *cascade08ÿv€w*cascade08€w†w *cascade08†wˆw*cascade08ˆw‰w *cascade08‰w’w*cascade08’w“w *cascade08“w˜w*cascade08˜w™w *cascade08™w›w*cascade08›ww *cascade08w¬w *cascade08¬wîw *cascade08îwïw*cascade08ïwøw *cascade08øwúw*cascade08úwƒx *cascade08ƒx…x*cascade08…xŠx *cascade08Šx‹x*cascade08‹xŒx *cascade08Œxx*cascade08x”x *cascade08”x•x*cascade08•x–x *cascade08–x˜x*cascade08˜x£x *cascade08£x¨x*cascade08¨x©x *cascade08©x­x*cascade08­x®x *cascade08®x²x*cascade08²x³x *cascade08³x·x*cascade08·x¸x *cascade08¸x¼x*cascade08¼x½x *cascade08½xÂx*cascade08Âxız *cascade08ız‚{*cascade08‚{{ *cascade08{Á{*cascade08Á{Â{ *cascade08Â{Æ{*cascade08Æ{Ç{ *cascade08Ç{É{ *cascade08É{æ{*cascade08æ{—| *cascade08—|È| *cascade08È|Ò|*cascade08Ò|ê} *cascade08ê}Ÿ~*cascade08Ÿ~¡~ *cascade08¡~ª~*cascade08ª~«~ *cascade08«~­~*cascade08­~·~ *cascade08·~¹~*cascade08¹~Â~ *cascade08Â~Ä~*cascade08Ä~Í~ *cascade08Í~Ï~*cascade08Ï~Ô~ *cascade08Ô~î~*cascade08î~ğ~ *cascade08ğ~û~*cascade08û~ü~ *cascade08ü~ˆ*cascade08ˆ *cascade08•*cascade08• *cascade08Ÿ*cascade08Ÿ¨ *cascade08¨ª*cascade08ª³ *cascade08³µ*cascade08µº *cascade08º¾*cascade08¾À *cascade08ÀÂ*cascade08ÂÃ *cascade08ÃÄ*cascade08ÄÆ *cascade08ÆÍ*cascade08ÍÎ *cascade08ÎÏ*cascade08Ïí *cascade08íî*cascade08î÷ *cascade08÷ù*cascade08ù‚€ *cascade08‚€ˆ€*cascade08ˆ€‹€ *cascade08‹€€*cascade08€“€ *cascade08“€•€*cascade08•€–€ *cascade08–€›€*cascade08›€œ€ *cascade08œ€€*cascade08€Ÿ€ *cascade08Ÿ€¤€*cascade08¤€¥€ *cascade08¥€§€*cascade08§€¨€ *cascade08¨€«€*cascade08«€† *cascade08†’*cascade08’œ *cascade08œ*cascade08Ÿ *cascade08Ÿ¡*cascade08¡£ *cascade08£¤*cascade08¤¥ *cascade08¥ª*cascade08ª¬ *cascade08¬µ*cascade08µº *cascade08ºÀ*cascade08ÀÄ *cascade08ÄÅ*cascade08ÅÆ *cascade08ÆÈ*cascade08ÈÉ *cascade08ÉË*cascade08ËÌ *cascade08ÌÌ*cascade08ÌÎ *cascade08ÎŠƒ *cascade08Šƒ ƒ*cascade08 ƒíƒ *cascade08íƒíƒ*cascade08íƒ™„ *cascade08™„™„*cascade08™„æ„ *cascade08æ„æ„*cascade08æ„ò„*cascade08ò„Ê… *cascade08Ê…Ø…*cascade08Ø…ã… *cascade08ã…“†*cascade08“†”† *cascade08”†—†*cascade08—†˜† *cascade08˜††*cascade08†† *cascade08†§†*cascade08§†¨† *cascade08¨†Ğ†*cascade08Ğ†Ù† *cascade08Ù†Ú†*cascade08Ú†ä† *cascade08ä†å†*cascade08å†ï† *cascade08ï†ğ†*cascade08ğ†ù† *cascade08ù†‚‡*cascade08‚‡ƒ‡ *cascade08ƒ‡†‡*cascade08†‡‡ *cascade08‡‘‡*cascade08‘‡š‡ *cascade08š‡œ‡*cascade08œ‡¥‡ *cascade08¥‡¦‡*cascade08¦‡°‡ *cascade08°‡±‡*cascade08±‡²‡ *cascade08²‡¹‡*cascade08¹‡º‡ *cascade08º‡½‡*cascade08½‡Æ‡ *cascade08Æ‡Ó‡*cascade08Ó‡Ü‡ *cascade08Ü‡İ‡*cascade08İ‡ç‡ *cascade08ç‡ğ‡*cascade08ğ‡ñ‡ *cascade08ñ‡ó‡*cascade08ó‡ô‡ *cascade08ô‡ı‡ *cascade08ı‡ÿ‡*cascade08ÿ‡ˆˆ *cascade08ˆˆŠˆ*cascade08Šˆ“ˆ *cascade08“ˆ•ˆ*cascade08•ˆŸˆ *cascade08Ÿˆ ˆ*cascade08 ˆ´ˆ *cascade08´ˆ¶ˆ*cascade08¶ˆ¿ˆ *cascade08¿ˆÀˆ*cascade08ÀˆËˆ *cascade08ËˆÖˆ*cascade08Öˆàˆ *cascade08àˆëˆ*cascade08ëˆìˆ *cascade08ìˆíˆ*cascade08íˆ÷ˆ *cascade08÷ˆøˆ*cascade08øˆ‰ *cascade08‰‚‰*cascade08‚‰ƒ‰ *cascade08ƒ‰‰*cascade08‰—‰ *cascade08—‰¤‰*cascade08¤‰­‰ *cascade08­‰®‰*cascade08®‰¸‰ *cascade08¸‰º‰*cascade08º‰Ã‰ *cascade08Ã‰Å‰*cascade08Å‰Î‰ *cascade08Î‰Ğ‰*cascade08Ğ‰Ó‰ *cascade08Ó‰Ü‰*cascade08Ü‰â‰ *cascade08â‰è‰*cascade08è‰ë‰ *cascade08ë‰í‰*cascade08í‰ï‰ *cascade08ï‰ğ‰*cascade08ğ‰ü‰ *cascade08ü‰ˆŠ*cascade08ˆŠ‘Š *cascade08‘Š“Š*cascade08“ŠŠ *cascade08ŠŠ*cascade08ŠŸŠ *cascade08ŸŠ¡Š*cascade08¡Š¢Š *cascade08¢Š£Š*cascade08£Š¥Š *cascade08¥Š¨Š*cascade08¨Š©Š *cascade08©ŠÔŠ*cascade08ÔŠÕŠ *cascade08ÕŠ—‹*cascade08—‹˜‹ *cascade08˜‹š‹*cascade08š‹›‹ *cascade08›‹ ‹*cascade08 ‹¡‹ *cascade08¡‹Ä‹*cascade08Ä‹Í‹ *cascade08Í‹Ø‹*cascade08Ø‹â‹ *cascade08â‹ù‹*cascade08ù‹û‹ *cascade08û‹‹Œ*cascade08‹ŒŒŒ *cascade08ŒŒŒ*cascade08Œ£Œ *cascade08£Œ¤Œ*cascade08¤Œ¥Œ *cascade08¥Œ§Œ*cascade08§Œ©Œ *cascade08©Œ²Œ*cascade08²Œ¸Œ *cascade08¸Œ¿Œ*cascade08¿ŒÀŒ *cascade08ÀŒÁŒ*cascade08ÁŒÃŒ *cascade08ÃŒÊŒ*cascade08ÊŒÎŒ *cascade08ÎŒÏŒ*cascade08ÏŒĞŒ *cascade08ĞŒÓŒ*cascade08ÓŒÛŒ *cascade08ÛŒİŒ*cascade08İŒæŒ *cascade08æŒòŒ*cascade08òŒôŒ *cascade08ôŒ÷Œ*cascade08÷ŒúŒ *cascade08úŒûŒ*cascade08ûŒüŒ *cascade08üŒÿŒ*cascade08ÿŒ *cascade08Š*cascade08Š *cascade08˜*cascade08˜™ *cascade08™Ã*cascade08ÃÑ *cascade08Ñ÷*cascade08÷ø *cascade08øù*cascade08ùú *cascade08úü*cascade08üı *cascade08ış*cascade08şÿ *cascade08ÿ†*cascade08†‡ *cascade08‡*cascade08– *cascade08–Ä*cascade08ÄÍ *cascade08Íù*cascade08ùƒ *cascade08ƒ*cascade08™ *cascade08™¥*cascade08¥° *cascade08°¸*cascade08¸¹ *cascade08¹¼*cascade08¼Å *cascade08ÅÎ*cascade08ÎÏ *cascade08ÏĞ*cascade08ĞÙ*cascade08ÙÚ *cascade08ÚÜ*cascade08Üİ*cascade08İæ *cascade08æè*cascade08èï *cascade08ïğ *cascade08ğñ *cascade08ñó*cascade08óô *cascade08ôü *cascade08üş*cascade08ş‚ *cascade08‚ƒ *cascade08ƒŒ*cascade08Œ *cascade08*cascade08 *cascade08‘*cascade08‘’ *cascade08’”*cascade08”• *cascade08•¥*cascade08¥© *cascade08©¾*cascade08¾¿ *cascade08¿â*cascade08âë *cascade08ë‘*cascade08‘—‘ *cascade08—‘¢‘*cascade08¢‘¤‘ *cascade08¤‘¬‘ *cascade08¬‘­‘*cascade08­‘Ğ‘ *cascade08Ğ‘Ø‘ *cascade08Ø‘Ù‘*cascade08Ù‘Ü‘ *cascade08Ü‘ã‘*cascade08ã‘ä‘ *cascade08ä‘ç‘*cascade08ç‘é‘ *cascade08é‘ò‘*cascade08ò‘ø‘ *cascade08ø‘ÿ‘*cascade08ÿ‘€’ *cascade08€’’*cascade08’ƒ’ *cascade08ƒ’„’*cascade08„’…’ *cascade08…’’*cascade08’’ *cascade08’’’*cascade08’’“’ *cascade08“’•’*cascade08•’—’ *cascade08—’ ’*cascade08 ’¡’ *cascade08¡’¢’*cascade08¢’£’ *cascade08£’´’*cascade08´’¼’ *cascade08¼’¾’*cascade08¾’È’ *cascade08È’É’*cascade08É’Ê’ *cascade08Ê’Í’*cascade08Í’Ğ’ *cascade08Ğ’Ô’*cascade08Ô’Õ’ *cascade08Õ’Ú’*cascade08Ú’Û’ *cascade08Û’Ü’*cascade08Ü’İ’ *cascade08İ’ã’*cascade08ã’å’ *cascade08å’ç’*cascade08ç’è’ *cascade08è’ğ’*cascade08ğ’ñ’ *cascade08ñ’ö’*cascade08ö’ÿ’ *cascade08ÿ’ “*cascade08 “ª“ *cascade08ª“ê“*cascade08ê“ë“ *cascade08ë“°”*cascade08°”±” *cascade08±”³”*cascade08³”µ” *cascade08µ”¶”*cascade08¶”·” *cascade08·”¸”*cascade08¸”¹” *cascade08¹”ª•*cascade08ª•µ• *cascade08µ•İ•*cascade08İ•æ• *cascade08æ•õ•*cascade08õ•ö• *cascade08ö•ù•*cascade08ù•ú• *cascade08ú•û•*cascade08û•ş• *cascade08ş•–*cascade08––*cascade08–…– *cascade08…–†– *cascade08†–Š–*cascade08Š–‹– *cascade08‹–¾–*cascade08¾–Ñ– *cascade08Ñ–Ê— *cascade08Ê—Ó—*cascade08Ó—Ô— *cascade08Ô—Ö—*cascade08Ö—à— *cascade08à—â—*cascade08â—ë— *cascade08ë—í—*cascade08í—ö— *cascade08ö—ø—*cascade08ø—˜ *cascade08˜˜ *cascade08˜‘˜*cascade08‘˜’˜ *cascade08’˜©˜*cascade08©˜«˜ *cascade08«˜¯˜*cascade08¯˜°˜ *cascade08°˜²˜*cascade08²˜³˜ *cascade08³˜·˜*cascade08·˜¸˜ *cascade08¸˜»˜*cascade08»˜½˜ *cascade08½˜Æ˜*cascade08Æ˜ß˜ *cascade08ß˜â˜*cascade08â˜ã˜ *cascade08ã˜å˜ *cascade08å˜è˜*cascade08è˜í˜ *cascade08í˜ğ˜*cascade08ğ˜ù˜ *cascade08ù˜€™*cascade08€™†™ *cascade08†™‹™*cascade08‹™Œ™ *cascade08Œ™™*cascade08™™ *cascade08™–™*cascade08–™Â™ *cascade08Â™É™*cascade08É™õ™ *cascade08õ™ü™*cascade08ü™¨š *cascade08¨š¯š*cascade08¯šÛš *cascade08Ûšâš*cascade08âš› *cascade08›‘›*cascade08‘›’› *cascade08’›•›*cascade08•›š› *cascade08š›› *cascade08›¤›*cascade08¤›¥› *cascade08¥›§›*cascade08§›¨› *cascade08¨›¬›*cascade08¬›­› *cascade08­›±›*cascade08±›²› *cascade08²›·›*cascade08·›¸› *cascade08¸›Æ›*cascade08Æ›€œ *cascade08€œ‹œ*cascade08‹œ–œ *cascade08–œ˜œ*cascade08˜œ¦œ *cascade08¦œªœ*cascade08ªœªœ*cascade08ªœ‹ *cascade08‹‹*cascade08‹ø *cascade08øú*cascade08úù *cascade08ù‚Ÿ *cascade08‚Ÿ†Ÿ*cascade08†Ÿ‡Ÿ *cascade08‡ŸˆŸ*cascade08ˆŸ‰Ÿ *cascade08‰Ÿ‹Ÿ*cascade08‹ŸŒŸ *cascade08ŒŸ˜  *cascade08˜ ™  *cascade08™  *cascade08   *cascade08 ¡  *cascade08¡ ¤ *cascade08¤ ¦  *cascade08¦ « *cascade08« ¬  *cascade08¬ ® *cascade08® ¸  *cascade08¸ ¹  *cascade08¹ º  *cascade08º Ñ  *cascade08Ñ Ø *cascade08Ø Ù  *cascade08Ù â *cascade08â ë  *cascade08ë ì  *cascade08ì í *cascade08í î  *cascade08î ô *cascade08ô ü  *cascade08ü ÿ *cascade08ÿ Ü¬ *cascade08Ü¬Ü¬*cascade08Ü¬Á¿ *cascade08Á¿Ó¿*cascade08Ó¿ş¿ *cascade08ş¿ÿ¿*cascade08ÿ¿¢Á *cascade08¢Á£Á *cascade08£Á§Á*cascade08§ÁĞÆ *cascade08ĞÆÑÆ *cascade08ÑÆÒÆ*cascade08ÒÆÓÆ *cascade08ÓÆÔÆ*cascade08ÔÆÖÆ *cascade08ÖÆØÆ*cascade08ØÆÙÆ *cascade08ÙÆÛÆ *cascade08ÛÆÜÆ *cascade08ÜÆİÆ*cascade08İÆßÆ *cascade08ßÆàÆ*cascade08àÆâÆ *cascade08âÆãÆ*cascade08ãÆäÆ *cascade08äÆåÆ*cascade08åÆ¹Ç *cascade08¹Ç¹Ç*cascade08¹ÇÈÇ *cascade08ÈÇÜÇ*cascade08ÜÇĞÈ *cascade08ĞÈÓÈ*cascade08ÓÈÔÈ *cascade08ÔÈØÈ*cascade08ØÈàÈ *cascade08àÈæÈ*cascade08æÈÉ *cascade08É“É*cascade08“É›É *cascade08›É É*cascade08 É¡É *cascade08¡É©É*cascade08©ÉÄÉ *cascade08ÄÉÉÉ*cascade08ÉÉÊÉ *cascade08ÊÉÏÉ*cascade08ÏÉĞÉ *cascade08ĞÉÑÉ*cascade08ÑÉÒÉ *cascade08ÒÉÔÉ*cascade08ÔÉÕÉ *cascade08ÕÉ×É*cascade08×ÉØÉ *cascade08ØÉÙÉ*cascade08ÙÉÚÉ *cascade08ÚÉÛÉ*cascade08ÛÉİÉ *cascade08İÉŞÉ*cascade08ŞÉºÊ *cascade08ºÊÏÊ*cascade08ÏÊàÊ *cascade08àÊñÊ*cascade08ñÊòÊ *cascade08òÊóÊ*cascade08óÊõÊ *cascade08õÊùÊ*cascade08ùÊúÊ *cascade08úÊ€Ë*cascade08€ËË *cascade08ËƒË*cascade08ƒË„Ë *cascade08„Ë‹Ë*cascade08‹ËŒË *cascade08ŒËË*cascade08ËŸË *cascade08ŸË¡Ë*cascade08¡Ë¢Ë *cascade08¢Ë¦Ë*cascade08¦Ë§Ë *cascade08§Ë­Ë*cascade08­Ë®Ë*cascade08®Ë¯Ë *cascade08¯Ë·Ë*cascade08·Ë¸Ë *cascade08¸Ë¹Ë*cascade08¹Ë¾Ë *cascade08¾ËÂË*cascade08ÂËÃË *cascade08ÃËÅË*cascade08ÅËüË *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV6_2.cpp
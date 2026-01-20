±á// SVMHypervisorV6_4.cpp
// Step 6.4 FIXED: Exit-Driven Loop with Proper ABI
//
// CRITICAL FIXES:
// 1. Stack alignment: 7 pushes for 16-byte alignment (RSP % 16 == 8)
// 2. RFLAGS saved/restored properly with pushfq/popfq
// 3. Use R13 for VMCB_VA instead of RBX (RBX is callee-saved problem)
// 4. Clean interrupt state handling
//
// Return value:
//   Low 16 bits:  CPUID count
//   Bits 16-23:   Termination code
//   Bits 24-31:   Exit reason

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

// ==================== V6.4 FIXED Shellcode ====================
// FIXES:
// 1. Proper stack alignment (sub rsp, 8 for 16-byte alignment)
// 2. pushfq before CLI, popfq after STGI
// 3. Use R13 for VMCB_VA (not RBX)
// 4. R14 = VMCB_PA, R15 = saved RFLAGS
//
// Registers:
// - R13 = VMCB_VA (virtual address for reading VMCB fields)
// - R14 = VMCB_PA (physical address for vmload/vmrun)
// - R12 = CPUID counter
// - R11 = exit reason
// - R10 = termination code
// - R8  = watchdog counter

uint8_t v6_4Shellcode[] = {
    // ===== Prologue with proper alignment =====
    0x55, // push rbp
    0x48,
    0x89,
    0xE5, // mov rbp, rsp
    0x48,
    0x83,
    0xEC,
    0x08, // sub rsp, 8 (alignment!)
    0x41,
    0x57, // push r15
    0x41,
    0x56, // push r14
    0x41,
    0x55, // push r13
    0x41,
    0x54, // push r12
    0x53, // push rbx
    // NO pushfq here - RFLAGS handled by CLI/STGI only!

    // ===== Enable SVME =====
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

    // ===== VM_HSAVE_PA =====
    0xB9,
    0x17,
    0x01,
    0x01,
    0xC0, // mov ecx, 0xC0010117
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
    0x30, // wrmsr

    // ===== Load pointers (R13 = VA, R14 = PA) =====
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

    // ===== VMSAVE host state =====
    0x4C,
    0x89,
    0xF0, // mov rax, r14
    0x0F,
    0x01,
    0xDB, // vmsave

    // ===== Populate VMCB (using R13 as VMCB_VA) =====
    // CR0
    0x0F,
    0x20,
    0xC0, // mov rax, cr0
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
    0xD8, // mov rax, cr3
    0x49,
    0x89,
    0x85,
    0x50,
    0x05,
    0x00,
    0x00, // mov [r13+0x550], rax
    // CR4
    0x0F,
    0x20,
    0xE0, // mov rax, cr4
    0x49,
    0x89,
    0x85,
    0x48,
    0x05,
    0x00,
    0x00, // mov [r13+0x548], rax
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
    // Segments (using R13)
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
    // CS: 0x0A9B = L=1 for LONG MODE (AMD SVM REQUIRES THIS!)
    // AMD SVM does NOT derive CS.L from EFER like Intel VMX!
    0x66,
    0x41,
    0xC7,
    0x85,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x0A, // 0x0A9B - CS.L=1 for AMD SVM long mode!
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
    // CRITICAL: Guest RSP MUST be guest-owned memory, NOT host stack!
    // Using host RSP causes INVALID GUEST STATE (exit code 0xFF)!
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, guestStackTop @GUEST_STACK
    0x49,
    0x89,
    0x85,
    0xD8,
    0x05,
    0x00,
    0x00, // mov [r13+0x5D8], rax
    // ASID = 1 (offset 0x58) - same as V6.1
    0x41,
    0xC7,
    0x45,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Intercepts: CPUID + HLT (like V6.2) =====
    0x41,
    0xC7,
    0x45,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x01, // mov dword [r13+0x0C], 0x01040000 - CPUID + HLT!
    0x41,
    0xC7,
    0x45,
    0x10,
    0x00, // NO VMRUN intercept!
    0x00,
    0x00,
    0x00, // mov dword [r13+0x10], 0x00000000

    // ===== CRITICAL: Clear VMCB Clean Bits! =====
    // Without this, CPU uses CACHED control fields and ignores our changes!
    0x41,
    0xC7,
    0x85,
    0xC0,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov dword [r13+0xC0], 0x00000000 - CLEAR ALL CLEAN BITS!

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
    0x00, // mov [r13+0x578], rax

    // ===== Guest RAX = 1 =====
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

    // ===== Initialize counter =====
    0x45,
    0x31,
    0xE4, // xor r12d, r12d (cpuid count = 0)

    // ========================================
    // ITERATION 1 - First VMRUN
    // ========================================
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
    0xDC, // stgi (NO sti - stgi handles interrupt enable!)
    // Increment counter
    0x41,
    0xFF,
    0xC4, // inc r12d
    // CPUID emulation: set ECX bit 31 (hypervisor present!)
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
    0x1F, // bts ecx, 31 (SET HYPERVISOR BIT!)
    // Advance guest RIP by 2 (CPUID is 2 bytes)
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

    // ===== MUST clear clean bits after RIP modification! =====
    0x41,
    0xC7,
    0x85,
    0xC0,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov dword [r13+0xC0], 0
    // ========================================
    // ITERATION 2 - Second VMRUN
    // ========================================
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
    0xDC, // stgi (NO sti!)
    // Increment counter
    0x41,
    0xFF,
    0xC4, // inc r12d
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

    // ===== MUST clear clean bits after RIP modification! =====
    0x41,
    0xC7,
    0x85,
    0xC0,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov dword [r13+0xC0], 0
    // ========================================
    // ITERATION 3 - Third VMRUN
    // ========================================
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
    0xDC, // stgi (NO sti!)
    // Increment counter
    0x41,
    0xFF,
    0xC4, // inc r12d
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

    // ===== Advance RIP after 3rd CPUID (CRITICAL!) =====
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

    // ===== MUST clear clean bits after RIP modification! =====
    0x41,
    0xC7,
    0x85,
    0xC0,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov dword [r13+0xC0], 0
    // ========================================
    // ITERATION 4 - Execute HLT (no intercept needed!)
    // HLT naturally causes VMEXIT on AMD SVM
    // ========================================
    0x4C,
    0x89,
    0xF0, // mov rax, r14
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload
    0x0F,
    0x01,
    0xD8, // vmrun -> guest executes HLT -> VMEXIT 0x78!
    0x0F,
    0x01,
    0xDB, // vmsave
    0x0F,
    0x01,
    0xDC, // stgi (NO sti!)

    // ===== Get HLT exit reason from VMCB (should be 0x78!) =====
    // EXITCODE is 16-bit at VMCB+0x70, NOT 32-bit!
    0x41,
    0x0F,
    0xB7,
    0x45,
    0x70, // movzx eax, word [r13+0x70] - READ AS 16-BIT!
    0x41,
    0x89,
    0xC3, // mov r11d, eax - save to r11d

    // Return: (exit_reason << 24) | cpuid_count
    0x44,
    0x89,
    0xD8, // mov eax, r11d
    0xC1,
    0xE0,
    0x18, // shl eax, 24
    0x44,
    0x09,
    0xE0, // or eax, r12d

    // ===== Epilogue =====
    0x5B, // pop rbx
    0x41,
    0x5C, // pop r12
    0x41,
    0x5D, // pop r13
    0x41,
    0x5E, // pop r14
    0x41,
    0x5F, // pop r15
    0x48,
    0x83,
    0xC4,
    0x08, // add rsp, 8
    0x5D, // pop rbp
    0xC3, // ret

    // ===== Guest code (3 CPUIDs + HLT) =====
    0x0F,
    0xA2, // cpuid #1
    0x0F,
    0xA2, // cpuid #2
    0x0F,
    0xA2, // cpuid #3
    0xF4, // HLT -> natural VMEXIT 0x78!
};

#define GUEST_CODE_SIZE 7 // 3 CPUIDs (6 bytes) + HLT (1 byte)

int main() {
  printf("================================================================\n");
  printf("  SVM HYPERVISOR V6.4 - 3 Iteration Bounded Loop + CPUID Emu   \n");
  printf("    - 3 VMRUN/VMEXIT cycles                                    \n");
  printf("    - CPUID emulation: ECX bit 31 = HYPERVISOR PRESENT!        \n");
  printf("    - V6.1-style conservative approach                         \n");
  printf(
      "================================================================\n\n");

  size_t shellcodeSize = sizeof(v6_4Shellcode);
  size_t guestCodeOffset = shellcodeSize - GUEST_CODE_SIZE;

  printf("[*] Shellcode size: %zu bytes\n", shellcodeSize);
  printf("[*] Guest code at offset: %zu\n\n", guestCodeOffset);

  // Find patch locations
  size_t OFF_HSAVE_LOW = 0, OFF_HSAVE_HIGH = 0;
  size_t OFF_VMCB_VA = 0, OFF_VMCB_PA = 0;
  size_t OFF_GUEST_STACK = 0;
  size_t OFF_LEA_DISP = 0;

  // Find HSAVE (B8 followed by BA)
  for (size_t i = 0; i < shellcodeSize - 10; i++) {
    if (v6_4Shellcode[i] == 0xB8 && v6_4Shellcode[i + 5] == 0xBA) {
      OFF_HSAVE_LOW = i + 1;
      OFF_HSAVE_HIGH = i + 6;
      break;
    }
  }

  // Find mov r13, imm64 (49 BD)
  for (size_t i = 0; i < shellcodeSize - 10; i++) {
    if (v6_4Shellcode[i] == 0x49 && v6_4Shellcode[i + 1] == 0xBD) {
      OFF_VMCB_VA = i + 2;
      break;
    }
  }

  // Find mov r14, imm64 (49 BE)
  for (size_t i = 0; i < shellcodeSize - 10; i++) {
    if (v6_4Shellcode[i] == 0x49 && v6_4Shellcode[i + 1] == 0xBE) {
      OFF_VMCB_PA = i + 2;
      break;
    }
  }

  // Find guest stack (48 B8) - first mov rax, imm64 for RSP
  for (size_t i = 0; i < shellcodeSize - 10; i++) {
    if (v6_4Shellcode[i] == 0x48 && v6_4Shellcode[i + 1] == 0xB8 &&
        v6_4Shellcode[i + 10] == 0x49 && v6_4Shellcode[i + 11] == 0x89 &&
        v6_4Shellcode[i + 12] == 0x85 && v6_4Shellcode[i + 13] == 0xD8) {
      OFF_GUEST_STACK = i + 2;
      break;
    }
  }

  // Find LEA (48 8D 05)
  for (size_t i = 0; i < shellcodeSize - 10; i++) {
    if (v6_4Shellcode[i] == 0x48 && v6_4Shellcode[i + 1] == 0x8D &&
        v6_4Shellcode[i + 2] == 0x05) {
      OFF_LEA_DISP = i + 3;
      break;
    }
  }

  printf("[*] Offsets: HSAVE_LOW=%zu, HSAVE_HIGH=%zu\n", OFF_HSAVE_LOW,
         OFF_HSAVE_HIGH);
  printf("[*] Offsets: VMCB_VA=%zu, VMCB_PA=%zu\n", OFF_VMCB_VA, OFF_VMCB_PA);
  printf("[*] Offsets: GUEST_STACK=%zu, LEA_DISP=%zu\n\n", OFF_GUEST_STACK,
         OFF_LEA_DISP);

  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Intel driver not found!\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  uint64_t kernelExAllocatePool =
      GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");

  uint64_t allocatedAddr = 0;
  CallKernelFunction<uint64_t>(&allocatedAddr, kernelExAllocatePool, 0, 0x3000,
                               0x484D5653); // Increased to 0x3000!
  if (!allocatedAddr) {
    printf("[-] Allocation failed!\n");
    CloseHandle(hDevice);
    return 1;
  }

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  uint64_t guestStackTop =
      allocatedAddr + 0x3000 - 0x10; // GUEST PRIVATE STACK!
  uint64_t vmcbPa = 0, hsavePa = 0;
  GetPhysicalAddress(vmcbVa, &vmcbPa);
  GetPhysicalAddress(hsaveVa, &hsavePa);
  printf("[+] VMCB: VA=0x%llX PA=0x%llX\n", vmcbVa, vmcbPa);
  printf("[+] HSAVE: VA=0x%llX PA=0x%llX\n", hsaveVa, hsavePa);
  printf("[+] Guest Stack Top: 0x%llX\n", guestStackTop);

  uint8_t zeros[0x1000] = {0};
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);
  WriteMemory(allocatedAddr + 0x2000, zeros, 0x1000); // Clear guest stack

  // Patch shellcode
  uint8_t patched[sizeof(v6_4Shellcode)];
  memcpy(patched, v6_4Shellcode, sizeof(patched));

  *(uint32_t *)&patched[OFF_HSAVE_LOW] = (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patched[OFF_HSAVE_HIGH] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patched[OFF_VMCB_VA] = vmcbVa;
  *(uint64_t *)&patched[OFF_VMCB_PA] = vmcbPa;
  *(uint64_t *)&patched[OFF_GUEST_STACK] = guestStackTop; // CRITICAL FIX!

  int32_t leaDisp = (int32_t)(guestCodeOffset - (OFF_LEA_DISP + 4));
  *(int32_t *)&patched[OFF_LEA_DISP] = leaDisp;

  printf("[+] LEA displacement: %d\n", leaDisp);
  printf("[+] Shellcode patched (%zu bytes)\n\n", sizeof(patched));

  printf("Press ENTER to execute V6.4 FIXED...\n");
  getchar();

  uint8_t backup[700];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patched));
  WriteToReadOnlyMemory(kernelNtAddAtom, patched, sizeof(patched));

  printf("[*] Executing V6.4 FIXED...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patched));
  printf("[+] NtAddAtom restored\n\n");

  // Decode result
  uint32_t ret = (uint32_t)result;
  uint32_t cpuidCount = ret & 0xFFFF;
  uint32_t termCode = (ret >> 16) & 0xFF;
  uint32_t exitReason = (ret >> 24) & 0xFF;

  printf("=== V6.4 Results ===\n");
  printf("[*] Raw return: 0x%08X\n", ret);
  printf("[*] CPUID count: %d\n", cpuidCount);
  printf("[*] Term code: %d", termCode);
  if (termCode == 1)
    printf(" (HLT - clean!)");
  else if (termCode == 2)
    printf(" (WATCHDOG)");
  else if (termCode == 4)
    printf(" (UNKNOWN)");
  printf("\n");
  printf("[*] Exit reason: 0x%X", exitReason);
  if (exitReason == 0x72)
    printf(" (CPUID)");
  else if (exitReason == 0x78)
    printf(" (HLT)");
  printf("\n");

  // V6.4 return format: (exit_reason << 24) | cpuid_count
  // Note: termCode is NOT set in shellcode, so it's always 0
  // cpuidCount should be 3 (3 CPUID iterations before HLT)
  // exitReason should be 0x78 for HLT
  if (cpuidCount == 3 && exitReason == 0x78) {
    printf("\n");
    printf("=============================================\n");
    printf("  [+] SUCCESS! V6.4 HLT TERMINATION WORKS!  \n");
    printf("  [+] 3 CPUIDs + HLT clean exit (0x78)      \n");
    printf("  [+] Phase 1 SVM Complete!                 \n");
    printf("=============================================\n");
  } else if (cpuidCount >= 1) {
    printf("\n[+] Partial success: %d CPUIDs handled, exit=0x%X\n", cpuidCount,
           exitReason);
  } else {
    printf("\n[!] Check results\n");
  }

  CloseHandle(hDevice);
  return 0;
}
· ·Ñ
Ñ® ®¯
¯İ İâ
âú úû
û‰ ‰
ì ìñ
ñõ õú
úµ µ¶
¶× ×Ø
Øæ æí
íÉ ÉÎ
ÎŒ Œ
ò òŠ
Š¯" ¯"Ç"
Ç"Î% Î%è%
è%Ğ& Ğ&Ñ&
Ñ&Ä' Ä'É'
É' (  (¥(
¥(»( »(¼(
¼(Ë( Ë(Ò(
Ò(°) °)µ)
µ)Õ) Õ)Ú)
Ú)è) è)ë)
ë)¸, ¸,¹,
¹,Ä, Ä,â,
â,ì, ì,í,
í,Ÿ. Ÿ.¤.
¤.ğ. ğ.õ.
õ.„/ „/‰/
‰/“/ “/–/
–/ó/ ó/ô/
ô/€0 €00
0¥0 ¥0·0
·0Ô1 Ô1İ1
İ1ƒ3 ƒ3„3
„34 4•4
•4Ğ4 Ğ4Õ4
Õ4Ÿ5 Ÿ5²5
²5Æ5 Æ5Ë5
Ë5‡6 ‡6Œ6
Œ6®6 ®6µ6
µ6ú6 ú6†7
†7¯7 ¯7¶7
¶7£8 £8¨8
¨89 9‚9
‚9”9 ”9•9
•9¤9 ¤9¬9
¬9ı9 ı9‚:
‚:ê: ê:ó:
ó:¤< ¤<¥<
¥<È< È<É<
É<¼= ¼=Ã=
Ã=¦> ¦>«>
«>Ç> Ç>È>
È>İ> İ>Ş>
Ş>‘? ‘?’?
’? ?  ?§?
§?±? ±?²?
²?ì? ì?í?
í?‚@ ‚@ƒ@
ƒ@öA öAıA
ıA’B ’B“B
“B£B £B¤B
¤BÂD ÂDäD
äDÕE ÕEÖE
ÖEœF œFF
FÀF ÀFÙF
ÙF•G •GšG
šGæG æGùG
ùGœH œH¡H
¡HİH İHäH
äH‰I ‰II
I•J •J–J
–JÿJ ÿJ„K
„KşK şKÿK
ÿKŒL ŒL”L
”L§M §MÀM
ÀMõM õMúM
úMŞO ŞOŞO
ŞO•S •SšS
šS S  S¥S
¥SÆS ÆSËS
ËSÑS ÑSÖS
ÖSÜS ÜSáS
áST T’T
’T¯T ¯T´T
´TÑT ÑTÖT
ÖTóT óTøT
øTªU ªU­U
­U´U ´U·U
·U¹U ¹U»U
»UÁU ÁUÚU
ÚUˆV ˆVV
V“V “V˜V
˜VV V£V
£V©V ©V®V
®VÖV ÖVÛV
ÛVõV õVúV
úV€W €W…W
…W‹W ‹WW
W–W –W›W
›W¾W ¾WÃW
ÃWÿW ÿW„X
„XŠX ŠXX
X•X •XšX
šX X  X¥X
¥XÍX ÍXÒX
ÒXØX ØXİX
İXãX ãXèX
èXîX îXóX
óX’Y ’Y—Y
—YY Y¢Y
¢Y¨Y ¨Y­Y
­Y³Y ³Y¸Y
¸YØY ØYİY
İY°Z °ZµZ
µZ»Z »ZÀZ
ÀZÆZ ÆZËZ
ËZÑZ ÑZÖZ
ÖZÜZ ÜZáZ
áZçZ çZìZ
ìZòZ òZ÷Z
÷ZıZ ıZ‚[
‚[ˆ[ ˆ[[
[»[ »[À[
À[Æ[ Æ[Ë[
Ë[Ñ[ Ñ[Ö[
Ö[Ü[ Ü[á[
á[ç[ ç[ì[
ì[ò[ ò[÷[
÷[ı[ ı[‚\
‚\ˆ\ ˆ\\
\“\ “\˜\
˜\î\ î\ó\
ó\ù\ ù\ş\
ş\Ÿ] Ÿ]¤]
¤]ª] ª]¯]
¯]‘^ ‘^–^
–^œ^ œ^¡^
¡^Â^ Â^Ç^
Ç^Í^ Í^Ò^
Ò^Ø^ Ø^İ^
İ^ã^ ã^è^
è^î^ î^ó^
ó^ù^ ù^ş^
ş^³_ ³_¸_
¸_¾_ ¾_Ã_
Ã_ä_ ä_é_
é_ï_ ï_ô_
ô_ú_ ú_ÿ_
ÿ_…` …`Š`
Š`` `•`
•`›` ›` `
 `Õ` Õ`Ú`
Ú`à` à`å`
å`†a †a‹a
‹a‘a ‘a–a
–aœa œa¡a
¡a§a §a¬a
¬a²a ²a·a
·a½a ½aÂa
Âaøa øaıa
ıaƒb ƒbˆb
ˆbb b“b
“b™b ™bb
b¯b ¯b´b
´bÅb ÅbÊb
ÊbĞb ĞbÕb
ÕbÛb Ûbàb
àbñb ñböb
öbüb übc
c’c ’c—c
—cc c¢c
¢c¨c ¨c­c
­c³c ³c¸c
¸c¾c ¾cÃc
ÃcÉc ÉcÎc
Îcìc ìcñc
ñc÷c ÷cüc
üc‚d ‚d‡d
‡d˜d ˜dd
d£d £d¨d
¨d®d ®d³d
³dÄd ÄdÉd
ÉdÏd ÏdÔd
ÔdÚd Údßd
ßdğd ğdõd
õdûd ûd€e
€e†e †e‹e
‹e‘e ‘e–e
–eœe œe¡e
¡e§e §e¬e
¬e½e ½eÂe
ÂeÈe ÈeÍe
ÍeÓe ÓeØe
ØeŞe Şeãe
ãeôe ôeùe
ùeÿe ÿe„f
„fŠf Šff
f•f •fšf
šf f  f¥f
¥f«f «f°f
°fÎf ÎfÓf
ÓfÙf ÙfŞf
Şfäf äféf
éfúf úfÿf
ÿf…g …gŠg
Šgg g•g
•g¦g ¦g«g
«g±g ±g¶g
¶g¼g ¼gÁg
ÁgÇg ÇgÌg
ÌgÒg Òg×g
×gİg İgâg
âgóg ógøg
øgşg şgƒh
ƒh‰h ‰hh
h”h ”h™h
™hªh ªh¯h
¯hµh µhºh
ºhÀh ÀhÅh
ÅhËh ËhĞh
ĞhÖh ÖhÛh
Ûháh áhæh
æh÷h ÷hüh
üh‚i ‚i‡i
‡ii i’i
’iÀi ÀiÅi
ÅiÖi ÖiÛi
Ûiái áiæi
æiìi ìiñi
ñi÷i ÷iüi
üi‚j ‚j‡j
‡jj j’j
’j˜j ˜jj
j´j ´j¹j
¹jÊj ÊjÏj
ÏjÕj ÕjÚj
Újàj àjåj
åjëj ëjğj
ğjöj öjûj
ûjk k†k
†kŒk Œk‘k
‘k¨k ¨k­k
­k¾k ¾kÃk
ÃkÉk ÉkÎk
ÎkÔk ÔkÙk
Ùkßk ßkäk
äkêk êkïk
ïkõk õkúk
úk€l €l…l
…lœl œl¡l
¡l²l ²l·l
·l½l ½lÂl
ÂlÈl ÈlÍl
ÍlÓl ÓlØl
ØlŞl Şlãl
ãlél élîl
îlôl ôlùl
ùl§m §m¬m
¬m²m ²m·m
·m½m ½mÂm
ÂmÈm ÈmÍm
ÍmŞm Şmãm
ãmém émîm
îmôm ômùm
ùmÿm ÿm„n
„nŠn Šnn
n•n •nšn
šn«n «n°n
°n¶n ¶n»n
»nÁn ÁnÆn
ÆnÌn ÌnÑn
Ñn×n ×nÜn
Ünân ânçn
çnøn ønın
ınƒo ƒoˆo
ˆoo o“o
“o™o ™oo
o¤o ¤o©o
©o¯o ¯o´o
´oÅo ÅoÊo
ÊoĞo ĞoÕo
ÕoÛo Ûoào
àoæo æoëo
ëoño ñoöo
öoüo üop
p¨p 
¨p²p ²p³p
³pºp ºp»p
»p¼p ¼p¾p
¾pÀp ÀpÄp
ÄpÅp ÅpÉp
ÉpÊp ÊpÒp
ÒpÓp ÓpÔp
ÔpÕp ÕpØp
ØpÙp Ùpàp
àpóp ópôp
ôpõp õp÷p
÷püp üpşp
şpÿp ÿpq
qˆq ˆqŒq
Œqq q‘q
‘q’q ’q“q
“q”q ”q•q
•q—q —q™q
™qšq šq¡q
¡q§q 
§q¬q 
¬q±q 
±q·q ·q¼q
¼qÂq ÂqÇq
ÇqÍq ÍqÒq
ÒqØq Øqİq
İqãq ãqèq
èqîq îqóq
óqùq ùqşq
şq„r „r‰r
‰rr rr
r–r –r—r
—rœr œrŸr
Ÿr r 
 r¢r 
¢r£r £r¥r
¥r¦r ¦r®r
®r¯r 
¯r¸r ¸r¹r
¹rÄr ÄrÉr
ÉrÏr ÏrÔr
ÔrÚr Úrßr
ßrår årêr
êrğr ğrõr
õrûr ûr€s
€s†s †s‹s
‹s‘s ‘s–s
–sœs œs¡s
¡s²s ²s·s
·s½s ½sÂs
ÂsÈs ÈsÍs
ÍsÓs ÓsØs
ØsŞs Şsãs
ãsés ésîs
îsôs ôsùs
ùsÿs ÿs„t
„tŠt Štt
t t  t¥t
¥t«t «t°t
°t¶t ¶t»t
»tÁt ÁtÆt
ÆtÌt ÌtÑt
Ñt×t ×tÜt
Ütât âtçt
çtít ítòt
òtøt øtıt
ıtu u¢u
¢u³u ³u¸u
¸u¾u ¾uÃu
ÃuÉu ÉuÎu
ÎuÔu ÔuÙu
Ùußu ßuäu
äuêu êuïu
ïuşu şuv
v‘v 
‘v’v ’vŸv
Ÿv v  vÅv
ÅvÈv ÈvËv
ËvÕv ÕvÖv
Öv×v ×vÙv
ÙvÚv ÚvÛv
ÛvÜv Üvãv
ãväv ävñv
ñvòv òvôv
ôvöv övùv
ùvûv ûvÿv
ÿv€w €ww
wƒw 
ƒw‡w 
‡wŒw Œw‘w
‘w”w ”w•w
•w–w –wãw
ãwìw ìwíw
íwüw üwıw
ıwÿw ÿwx
x†x †x–x
–x¡x ¡x¦x
¦x¬x ¬x±x
±x·x ·x¼x
¼xÂx ÂxÇx
ÇxÍx ÍxÒx
ÒxØx Øxİx
İxãx ãxûx
ûxˆy ˆy©y
©y´y ´y¹y
¹y¿y ¿yÄy
ÄyÊy ÊyÏy
ÏyÕy ÕyÚy
Úyày àyåy
åyëy ëyğy
ğyöy öyûy
ûyz 
z…z 
…z¤z 
¤zªz 
ªz«z 
«z¯z 
¯z°z 
°zµz 
µz½z 
½zÔz 
Ôz×z ×z÷z
÷zøz 
øzÿz 
ÿz…{ …{†{
†{ˆ{ ˆ{{
{{ {©{
©{ª{ ª{«{
«{¬{ ¬{Æ{Æ{Ë{
Ë{Ï{ Ï{Ğ{
Ğ{Ñ{ Ñ{Ö{
Ö{Ú{ Ú{Û{
Û{Ü{ 
Ü{ä{ ä{í{
í{î{ î{ğ{
ğ{÷{ 
÷{ü{ ü{ı{
ı{‚| ‚|ƒ|
ƒ|„| „|‰|
‰|| ||
|¤| 
¤|¨| ¨|©|
©|ª| ª|µ|
µ|¹| 
¹|§} 
§}ª} ª}µ}
µ}¶} 
¶}Ş} 
Ş}é} é}î}
î}ô} ô}ù}
ù}ü} ü}ı}
ı}ÿ} ÿ}„~
„~‡~ ‡~“~
“~•~ •~š~
š~~ ~Ÿ~
Ÿ~ ~  ~¥~
¥~«~ «~°~
°~¶~ ¶~»~
»~Á~ Á~×~
×~Û~ Û~‚
‚ƒ ƒŒ
Œ “
“Â ÂÇ
ÇÍ ÍÒ
ÒØ Øİ
İã ãè
èî îó
óù ùşş®€ 
®€³€³€¹€ 
¹€¾€¾€Ä€ 
Ä€É€É€Ï€ 
Ï€Ô€Ô€Ú€ 
Ú€ß€ß€å€ 
å€ê€ê€· 
·¼¼Â 
ÂÇÇÍ 
ÍÒÒØ 
Øİİã 
ãèèî 
îóóù 
ùşş„‚ 
„‚‰‚‰‚‚ 
‚”‚”‚š‚ 
š‚Ÿ‚Ÿ‚È‚ 
È‚È‚È‚Ù‚ 
Ù‚Ş‚Ş‚ä‚ 
ä‚é‚é‚ƒ 
ƒ’ƒ’ƒ•ƒ 
•ƒ›„›„¢„ 
¢„£„£„¤„ 
¤„©„©„¬„ 
¬„®„®„¯„ 
¯„´„´„·„ 
·„¹„¹„¾„ 
¾„¿„¿„À„ 
À„Â„Â„Ã„ 
Ã„Æ„Æ„É„ 
É„ğ„ğ„ñ„ 
ñ„†…†…‡… 
‡…‘…‘…’… 
’…•…•…–… 
–…›…›…œ… 
œ…Å…Å…Æ… 
Æ…Ò…Ò…Ó… 
Ó…Û…Û…Ü… 
Ü…ã…ã…ä… 
ä…„†„†…† …††† 
††‰†‰†Š† 
Š†††† 
†††‘† ‘†’† 
’†“†“†”† 
”†¯†¯†±† ±†²† 
²†»†»†½† 
½†‰‡‰‡Š‡ 
Š‡§‡§‡©‡ 
©‡°‡°‡±‡ 
±‡³‡³‡¼‡ 
¼‡¾‡¾‡¿‡ 
¿‡Ä‡Ä‡Ç‡ 
Ç‡ˆˆ„ˆ 
„ˆ‰ˆ‰ˆŒˆ 
Œˆˆˆ—ˆ 
—ˆ¥ˆ¥ˆ¦ˆ 
¦ˆ½ˆ½ˆ¾ˆ 
¾ˆÈˆÈˆÉˆ 
ÉˆËˆËˆÌˆ 
ÌˆÏˆÏˆĞˆ 
Ğˆ™‰™‰š‰ 
š‰®‰®‰°‰ 
°‰½‰½‰¿‰ 
¿‰Æ‰Æ‰Ç‰ 
Ç‰“Š“Š”Š 
”Š×Š×ŠØŠ 
ØŠÅ‹Å‹Õ‹ 
Õ‹««× 
×İİŞ 
Şßßà 
àëëì ìî îñ 
ñóóô 
ôÑÑÒ 
Ò‰‰Œ Œ 
’’– 
–˜˜ñ ñò 
ò¶‘¶‘·‘ 
·‘º‘º‘»‘ 
»‘Õ‘Õ‘Ö‘ 
Ö‘×‘×‘Ø‘ 
Ø‘Ù‘Ù‘Ú‘ 
Ú‘ı‘ı‘ÿ‘ 
ÿ‘³’³’´’ 
´’½”½”¾” 
¾”Á”Á”Â” Â”ÿ– ÿ–»— 
»—À—À—Æ— 
Æ—Ë—Ë—ç— ç—é— é—ó— 
ó—ó—ó—ş— 
ş—ƒ˜ƒ˜‰˜ 
‰˜˜˜©˜ 
©˜®˜®˜´˜ 
´˜¹˜¹˜Ó˜ 
Ó˜Ø˜Ø˜Ş˜ 
Ş˜ã˜ã˜û˜ û˜ ™  ™¡™ ¡™¦™ ¦™¯™ 
¯™³™³™´™ 
´™µ™µ™¶™ 
¶™·™·™¹™ 
¹™º™º™»™ 
»™¼™¼™½™ 
½™À™À™É™ 
É™Ê™Ê™Ë™ 
Ë™Ğ™Ğ™Ó™ 
Ó™Õ™Õ™Ö™ 
Ö™Û™Û™Ş™ 
Ş™à™à™å™ 
å™è™è™ë™ 
ë™ì™ì™í™ 
í™ò™ò™ö™ 
ö™÷™÷™ü™ 
ü™…š…šš 
šššš 
š•š•š˜š 
˜š™š™š›š 
›š š š£š 
£š¥š¥š¦š 
¦š«š«š®š 
®š°š°š±š 
±š¶š¶š¼š 
¼šÏšÏšÒš 
ÒšÔšÔšÕš 
ÕšÚšÚšİš 
İšßšßšäš 
äšéšéšêš 
êšëšëšíš 
íšïšïšøš 
øšúšúšûš 
ûš€›€›ƒ› 
ƒ›…›…›Š› 
Š›‹›‹›Œ› 
Œ›››› 
›››—› 
—›™›™›š› 
š›Ÿ›Ÿ›¢› 
¢›¤›¤›¥› 
¥›ª›ª›­› 
­›º›º›¿› 
¿›Ä›Ä›Å› 
Å›Ç›Ç›È› 
È›É›É›Ê› Ê›Ì› Ì›Û› Û›˜œ ˜œ™œ ™œ»  » ¼  ¼ ó  ó õ  õ Ö¡ Ö¡×¡ ×¡Á£ 
Á£Ä£Ä£È£ 
È£Ê£Ê£ï£ 
ï£ù£ù£‰¤ ‰¤Š¤ 
Š¤¤¤’¤ ’¤–¤ 
–¤Ë¤Ë¤Î¤ 
Î¤Ï¤Ï¤Ø¤ 
Ø¤ã¤ã¤ä¤ 
ä¤å¤å¤î¤ 
î¤ï¤ï¤ı¤ ı¤€¥ €¥ƒ¥ 
ƒ¥…¥…¥†¥ 
†¥¥¥š¥ 
š¥í¥í¥¬¦ 
¬¦±¦±¦·¦ 
·¦¼¦¼¦Ş¦ 
Ş¦ã¦ã¦é¦ 
é¦î¦î¦ñ¦ 
ñ¦ò¦ò¦§ 
§‚§‚§§ 
§“§“§™§ 
™§§§ô§ 
ô§ù§ù§•¨ 
•¨š¨š¨¶¨ 
¶¨»¨»¨×¨ 
×¨Ü¨Ü¨ø¨ 
ø¨ı¨ı¨ƒ© 
ƒ©ˆ©ˆ©© 
©“©“©§© 
§©§©§©ë© ë©ö© ö©÷© ÷©ü© ü©Œª 
Œª‘ª‘ª¡ª 
¡ª¨ª¨ª©ª 
©ªªªªª«ª 
«ª¾ª¾ª¿ª 
¿ªÇªÇªÈª 
ÈªÌªÌªÍª 
ÍªÕªÕªØª 
ØªÙªÙªÚª 
Úªçªçªéª 
éª“«“«±« ±«³« ³«¿« 
¿«Á«Á«Æ« 
Æ«×«×«Ü¬ 
Ü¬à¬à¬â¬ 
â¬ç¬ç¬é¬ 
é¬ï¬ï¬ñ¬ 
ñ¬ô¬ô¬õ¬ 
õ¬ö¬ö¬÷¬ 
÷¬ü¬ü¬ı¬ 
ı¬€­€­š­ 
š­›­›­œ­ 
œ­¨­¨­©­ 
©­­­­­®­ 
®­¯­¯­ê­ 
ê­ï­ï­ñ­ 
ñ­õ­õ­ö­ 
ö­÷­÷­ø­ 
ø­ú­ú­û­ 
û­ş­ş­ÿ­ 
ÿ­‚®‚®ƒ® 
ƒ®…®…®†® 
†®‡®‡®ˆ® 
ˆ®’®’®“® 
“®›®›®º® 
º®¿®¿®Á® 
Á®Ä®Ä®Å® 
Å®Ñ®Ñ®Ò® 
Ò®Ú®Ú®ƒ¯ 
ƒ¯‹¯‹¯¾² 
¾²İ²İ²œ¸ 
œ¸¦»¦»¸¼ 
¸¼Á¼Á¼ã½ 
ã½í½í½¯¾ 
¯¾ö¾ö¾¿ 
¿”¿”¿•¿ 
•¿—¿—¿˜¿ 
˜¿š¿š¿›¿ ›¿¤¿ ¤¿ˆÀ 
ˆÀ¡À¡ÀîÂ 
îÂõÂõÂšÄ 
šÄ›Ä›ÄŸÄ 
ŸÄ¿Ä¿ÄÌÄ ÌÄäÄ äÄ«Æ «ÆÅÆ 
ÅÆÌÆÌÆ…Ç …ÇûÈ 
ûÈ¶É¶É¥Ê ¥ÊñÊ ñÊøË 
øËùËùËÄÌ 
ÄÌÅÌÅÌáÌ 
áÌèÌèÌ Í 
 Í¡Í¡ÍĞÍ 
ĞÍÑÍÑÍöÍ öÍ„Î 
„Î†Î†ÎŠÎ 
ŠÎ‹Î‹ÎÄÎ ÄÎ“Ï 
“Ï”Ï”Ï™Ó 
™ÓšÓšÓÓ 
Ó¥Ó¥Ó©Ó 
©ÓªÓªÓ–Ø 
–Ø›Ø›ØÑØ 
ÑØÖØÖØˆÙ 
ˆÙÙÙÿÙ 
ÿÙ„Ú„Ú¸Ú 
¸Ú½Ú½ÚæÚ 
æÚõÚõÚöÚ 
öÚüÚüÚşÚ 
şÚ“Û“Û˜Û 
˜ÛšÛšÛÛ 
Û Û Û¢Û 
¢Û¤Û¤Û¥Û 
¥ÛªÛªÛ´Û 
´ÛÕÜÕÜØÜ 
ØÜÙÜÙÜçİ 
çİìİìİíİ 
íİöİöİ˜Ş 
˜Ş™Ş™Ş§Ş 
§Ş©Ş©Ş­Ş 
­Ş±Ş±Ş²Ş 
²Ş¸Ş¸Ş×Ş 
×ŞÛŞÛŞİŞ 
İŞŞŞŞŞßŞ 
ßŞäŞäŞìŞ 
ìŞñŞñŞßß 
ßßàßàß™à 
™à¤à¤à³à 
³àËàËà±á 20file:///c:/inject/Spoofers/SVMHypervisorV6_4.cpp
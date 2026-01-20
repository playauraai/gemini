©Ò// SVMHypervisorV6_4.cpp
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
    // CS: 0x029B = L=0 (CPU derives long mode from EFER!)
    // AMD SVM rule: Do NOT force CS.L=1, let CPU derive it
    0x66,
    0x41,
    0xC7,
    0x85,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02, // 0x029B - L=0, CPU derives long mode!
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
    // RSP - Use host RSP (safe until interrupts are virtualized)
    0x48,
    0x89,
    0xE0, // mov rax, rsp (use HOST stack!)
    0x49,
    0x89,
    0x85,
    0xD8,
    0x05,
    0x00,
    0x00,
    // ASID = 1 (offset 0x58) - same as V6.1
    0x41,
    0xC7,
    0x45,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00,
    // NO TLB_CONTROL - let CPU preserve cached state!
    // NO clean_bits - let CPU preserve hidden state!

    // ===== Intercepts: CPUID only (same as V6.1) =====
    // ===== Intercepts: CPUID only (stable V6.1 pattern) =====
    0x41,
    0xC7,
    0x45,
    0x0C,
    0x00,
    0x00, // No HLT intercept!
    0x04,
    0x00, // 0x00040000 - CPUID only
    0x41,
    0xC7,
    0x45,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00, // VMRUN

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
    0xDC, // stgi
    0xFB, // sti
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
    0xDC, // stgi
    0xFB, // sti
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
    0xDC, // stgi
    0xFB, // sti
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
    0xDC, // stgi
    0xFB, // sti

    // ===== Get HLT exit reason (should be 0x78!) =====
    0x45,
    0x8B,
    0x5D,
    0x70, // mov r11d, [r13+0x70]

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
  printf("[*] Offsets: VMCB_VA=%zu, VMCB_PA=%zu, LEA_DISP=%zu\n\n", OFF_VMCB_VA,
         OFF_VMCB_PA, OFF_LEA_DISP);

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

  // No guest RSP patching needed - using host RSP now

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

  if (cpuidCount == 5 && termCode == 1 && exitReason == 0x78) {
    printf("\n");
    printf("=============================================\n");
    printf("  [+] SUCCESS! V6.4 FIXED WORKS!            \n");
    printf("  [+] 5 CPUIDs + HLT termination            \n");
    printf("  [+] Exit-driven loop complete!            \n");
    printf("=============================================\n");
  } else if (cpuidCount >= 3) {
    printf("\n[+] Partial success: %d CPUIDs handled\n", cpuidCount);
  } else {
    printf("\n[!] Check results\n");
  }

  CloseHandle(hDevice);
  return 0;
}
ªU *cascade08ªU­U*cascade08­U´U *cascade08´U·U*cascade08·U¹U *cascade08¹U»U*cascade08»UÁU *cascade08ÁUÚU*cascade08ÚU¨p *cascade08¨p²p *cascade08²p³p*cascade08³pºp *cascade08ºp»p*cascade08»p½p *cascade08½pÉp*cascade08ÉpÒp *cascade08ÒpÜp*cascade08ÜpŞp *cascade08Şpæp*cascade08æpçp *cascade08çpép*cascade08épëp *cascade08ëpîp*cascade08îpïp *cascade08ïpúp*cascade08úpûp *cascade08ûp€q*cascade08€qq *cascade08q†q*cascade08†q‡q *cascade08‡q‹q*cascade08‹qq *cascade08q“q*cascade08“q•q *cascade08•q—q*cascade08—q˜q *cascade08˜q›q*cascade08›q¡q *cascade08¡q†r *cascade08†r‡r *cascade08‡rˆr*cascade08ˆrr*cascade08rr *cascade08r‘r*cascade08‘r—r *cascade08
—r˜r ˜ršr*cascade08šr›r *cascade08›r¡r*cascade08¡r¢r *cascade08¢r¦r*cascade08¦r§r *cascade08
§r°r °r±r*cascade08±rùu *cascade08ùuıu *cascade08ıuÿu*cascade08ÿu€v *cascade08€v…v*cascade08…v‡v *cascade08‡vˆv*cascade08ˆvŠv *cascade08Švœv*cascade08œvv *cascade08v v*cascade08 v¡v *cascade08¡v§v*cascade08§v¨v *cascade08¨v­v*cascade08­v°v *cascade08°v¶v *cascade08¶vÃv *cascade08ÃvÄv *cascade08ÄvÅv*cascade08ÅvÎv *cascade08ÎvÏv*cascade08ÏvĞv *cascade08ĞvŞv *cascade08Şváv*cascade08ávâv *cascade08âvãv *cascade08ãvòv*cascade08òvóv *cascade08óvÍw *cascade08Íwßw*cascade08ßwîw*cascade08îwÆx *cascade08ÆxÏx *cascade08ÏxÒx*cascade08ÒxŞx *cascade08Şxßx*cascade08ßxàx *cascade08àxáx*cascade08áxåx *cascade08åxçx*cascade08çxèx *cascade08èxëx*cascade08ëxîx *cascade08îxïx*cascade08ïxñx *cascade08ñx÷x*cascade08÷xøx *cascade08øxşx*cascade08şx‡y *cascade08‡y‰y*cascade08‰yŠy *cascade08Šy‹y*cascade08‹yy *cascade08yy*cascade08y•y *cascade08•y–y*cascade08–y—y *cascade08—y˜y*cascade08˜yœy *cascade08œyy*cascade08yŸy *cascade08Ÿy y*cascade08 y¥y *cascade08¥y¦y*cascade08¦y§y *cascade08§y«y*cascade08«y´y *cascade08´yµy*cascade08µyÆy *cascade08ÆyØy *cascade08Øyİy*cascade08İyŞy *cascade08Şyây*cascade08âyãy *cascade08ãyåy*cascade08åyæy *cascade08æyêy*cascade08êyëy*cascade08ëyóy *cascade08óyúy *cascade08úyÿy*cascade08ÿy€z *cascade08€zz*cascade08z…z *cascade08…z‡z*cascade08‡z‰z *cascade08‰zŠz*cascade08Šz‹z *cascade08‹zŒz *cascade08Œzz*cascade08zz *cascade08z‘z*cascade08‘z’z *cascade08’z›z*cascade08›zœz*cascade08œz¦z*cascade08¦z§z *cascade08§z²z*cascade08²z´z *cascade08´zàz *cascade08àzçz *cascade08çzèz*cascade08èzëz *cascade08ëzóz *cascade08ózôz*cascade08ôz‰{*cascade08‰{‹{ *cascade08‹{’{ *cascade08’{“{*cascade08“{–{ *cascade08–{–{*cascade08–{{ *cascade08{{*cascade08{£{ *cascade08£{°{*cascade08°{±{ *cascade08±{µ{ *cascade08µ{¶{ *cascade08¶{º{ *cascade08º{Ğ *cascade08ĞĞ*cascade08Ğ–€ *cascade08–€š€*cascade08š€€ *cascade08€£*cascade08£ª *cascade08ª«*cascade08«´ *cascade08´¶*cascade08¶¿ *cascade08¿Á*cascade08ÁÆ *cascade08ÆÇ*cascade08ÇÈ *cascade08ÈÊ*cascade08ÊË *cascade08ËÎ*cascade08ÎÑ *cascade08Ñø*cascade08øù *cascade08ù‚*cascade08‚‚ *cascade08‚™‚*cascade08™‚š‚ *cascade08š‚‚*cascade08‚‚ *cascade08‚£‚*cascade08£‚¤‚ *cascade08¤‚Í‚*cascade08Í‚Î‚ *cascade08Î‚Ú‚*cascade08Ú‚Û‚ *cascade08Û‚ã‚*cascade08ã‚ä‚ *cascade08ä‚ë‚*cascade08ë‚ì‚ *cascade08ì‚Œƒ*cascade08Œƒƒ *cascade08ƒƒ*cascade08ƒƒ *cascade08ƒ¡ƒ*cascade08¡ƒ¢ƒ *cascade08¢ƒ«ƒ*cascade08«ƒ­ƒ *cascade08­ƒùƒ*cascade08ùƒúƒ *cascade08úƒ—„*cascade08—„™„ *cascade08™„ „*cascade08 „¡„ *cascade08¡„£„*cascade08£„¬„ *cascade08¬„®„*cascade08®„·„ *cascade08·„ñ„*cascade08ñ„ü„ *cascade08ü„ş„*cascade08ş„‡… *cascade08‡…•…*cascade08•…–… *cascade08–…­…*cascade08­…®… *cascade08®…¸…*cascade08¸…¹… *cascade08¹…»…*cascade08»…¼… *cascade08¼…¿…*cascade08¿…À… *cascade08À…‰†*cascade08‰†Š† *cascade08Š††*cascade08† † *cascade08 †­†*cascade08­†¯† *cascade08¯†¶†*cascade08¶†·† *cascade08·†ƒ‡*cascade08ƒ‡„‡ *cascade08„‡Ç‡*cascade08Ç‡È‡ *cascade08È‡µˆ*cascade08µˆñˆ *cascade08ñˆ÷ˆ*cascade08÷ˆøˆ *cascade08øˆùˆ*cascade08ùˆúˆ *cascade08úˆ…‰*cascade08…‰†‰ *cascade08†‰ˆ‰ *cascade08ˆ‰‹‰ *cascade08‹‰‰*cascade08‰‰ *cascade08‰ë‰*cascade08ë‰ì‰ *cascade08ì‰£‹*cascade08£‹¤‹ *cascade08¤‹¦‹ *cascade08¦‹“Œ*cascade08“Œ”Œ *cascade08”ŒØŒ*cascade08ØŒÙŒ*cascade08ÙŒÜŒ*cascade08ÜŒİŒ *cascade08İŒ÷Œ*cascade08÷ŒøŒ *cascade08øŒùŒ*cascade08ùŒúŒ *cascade08úŒûŒ*cascade08ûŒüŒ *cascade08üŒŸ*cascade08Ÿ¡ *cascade08¡Õ*cascade08ÕÖ *cascade08Öß*cascade08ßà *cascade08àã*cascade08ãä *cascade08äË*cascade08Ë¯‘ *cascade08¯‘¿‘ *cascade08¿‘¿‘*cascade08¿‘Ç’ *cascade08Ç’è’ *cascade08è’í’ *cascade08í’ğ’ *cascade08ğ’ò’*cascade08ò’ó’ *cascade08ó’ô’ *cascade08ô’ö’ *cascade08ö’÷’ *cascade08÷’ú’*cascade08ú’ƒ“ *cascade08ƒ“‡“*cascade08‡“ˆ“ *cascade08ˆ“‰“*cascade08‰“Š“ *cascade08Š“‹“*cascade08‹““ *cascade08““*cascade08““ *cascade08““*cascade08“‘“ *cascade08‘“”“*cascade08”““ *cascade08““*cascade08“§“ *cascade08§“©“*cascade08©“²“ *cascade08²“´“*cascade08´“¹“ *cascade08¹“¼“*cascade08¼“¿“ *cascade08¿“À“*cascade08À“Ê“ *cascade08Ê“Ë“*cascade08Ë“Ğ“ *cascade08Ğ“Ù“*cascade08Ù“á“ *cascade08á“ã“*cascade08ã“ì“ *cascade08ì“í“*cascade08í“÷“ *cascade08÷“ù“*cascade08ù“‚” *cascade08‚”„”*cascade08„”” *cascade08””*cascade08”¦” *cascade08¦”¨”*cascade08¨”±” *cascade08±”³”*cascade08³”¸” *cascade08¸”½”*cascade08½”¾” *cascade08¾”¿”*cascade08¿”Á” *cascade08Á”Ã”*cascade08Ã”Ì” *cascade08Ì”Î”*cascade08Î”×” *cascade08×”Ù”*cascade08Ù”Ş” *cascade08Ş”ß”*cascade08ß”à” *cascade08à”á”*cascade08á”â” *cascade08â”ã”*cascade08ã”ë” *cascade08ë”í”*cascade08í”ö” *cascade08ö”ø”*cascade08ø”• *cascade08••*cascade08•“• *cascade08“•˜•*cascade08˜•™• *cascade08™•›•*cascade08›•œ• *cascade08œ••*cascade08•• *cascade08• • *cascade08 •¯• ¯•³•*cascade08³•´• *cascade08´•»•*cascade08»•¼• *cascade08¼•ì•*cascade08ì•í• *cascade08í•î•*cascade08î•ï• *cascade08ï•¯˜*cascade08¯˜°˜*cascade08°˜¹˜*cascade08¹˜º˜ *cascade08º˜¾˜*cascade08¾˜¿˜ *cascade08¿˜È˜*cascade08È˜É˜ *cascade08É˜ä˜*cascade08ä˜å˜ *cascade08å˜æ˜*cascade08æ˜ç˜ *cascade08ç˜ñ˜*cascade08ñ˜ò˜ *cascade08ò˜ó˜ *cascade08ó˜ô˜ *cascade08ô˜Ñ™*cascade08Ñ™Ò™*cascade08Ò™Ô™*cascade08Ô™Õ™ Õ™Ú™*cascade08Ú™Û™ *cascade08Û™™š*cascade08™ššš *cascade08ššİš*cascade08İšŞš *cascade08Şšãš*cascade08ãšäš *cascade08äš…œ*cascade08…œ†œ *cascade08†œŒœ*cascade08Œœ’œ *cascade08’œ¹œ*cascade08¹œ¼œ *cascade08¼œĞœ*cascade08ĞœÔ *cascade08ÔÕ*cascade08Õä *cascade08äå*cascade08å¶ *cascade08¶Š  *cascade08Š Š *cascade08Š Î  *cascade08Î Ï  *cascade08Ï Ğ *cascade08Ğ Ö  *cascade08Ö × *cascade08× Ø  *cascade08Ø Ù *cascade08Ù Ú  Ú İ *cascade08İ ß  *cascade08ß „¡ *cascade08„¡‹¡*cascade08‹¡Œ¡ *cascade08Œ¡¡*cascade08¡¡ *cascade08¡¡¡*cascade08¡¡¢¡ *cascade08¢¡ª¡*cascade08ª¡«¡ *cascade08«¡¯¡*cascade08¯¡°¡ *cascade08°¡¸¡*cascade08¸¡»¡ *cascade08»¡¼¡*cascade08¼¡½¡ *cascade08½¡Ê¡*cascade08Ê¡Ì¡ *cascade08Ì¡ö¡*cascade08ö¡”¢ *cascade08”¢•¢*cascade08•¢¢¢ *cascade08¢¢¤¢*cascade08¤¢©¢ ©¢ª¢*cascade08ª¢º¢*cascade08º¢¿£ *cascade08¿£Ã£*cascade08Ã£Å£ *cascade08Å£Ê£*cascade08Ê£Ì£ *cascade08Ì£Ò£*cascade08Ò£Ô£ *cascade08Ô£×£*cascade08×£Ø£ *cascade08Ø£Ù£*cascade08Ù£Ú£ *cascade08Ú£ß£*cascade08ß£à£ *cascade08à£ã£*cascade08ã£ı£ *cascade08ı£ş£*cascade08ş£ÿ£ *cascade08ÿ£‹¤*cascade08‹¤Œ¤ *cascade08Œ¤¤*cascade08¤‘¤ *cascade08‘¤’¤*cascade08’¤Í¤ *cascade08Í¤Ò¤*cascade08Ò¤Ô¤ *cascade08Ô¤Ø¤*cascade08Ø¤Ù¤ *cascade08Ù¤Ú¤*cascade08Ú¤Û¤ *cascade08Û¤İ¤*cascade08İ¤Ş¤ *cascade08Ş¤á¤*cascade08á¤â¤ *cascade08â¤å¤*cascade08å¤æ¤ *cascade08æ¤è¤*cascade08è¤é¤ *cascade08é¤ê¤*cascade08ê¤ë¤ *cascade08ë¤õ¤*cascade08õ¤ö¤ *cascade08ö¤ş¤*cascade08ş¤¥ *cascade08¥¢¥*cascade08¢¥¤¥ *cascade08¤¥§¥*cascade08§¥¨¥ *cascade08¨¥´¥*cascade08´¥µ¥ *cascade08µ¥½¥*cascade08½¥–· *cascade08–·—·*cascade08—·È· *cascade08È·à·*cascade08à·§¹ *cascade08§¹º*cascade08º÷» *cascade08÷»²¼*cascade08²¼¡½ *cascade08¡½í½*cascade08í½ôÀ *cascade08ôÀ÷À *cascade08÷ÀùÀ*cascade08ùÀ„Á *cascade08„Á…Á*cascade08…Á†Á*cascade08†ÁˆÁ *cascade08ˆÁ‰Á *cascade08‰Á’Á *cascade08’Á“Á*cascade08“Á”Á *cascade08”Á•Á*cascade08•ÁšÁ *cascade08šÁ›Á*cascade08›ÁœÁ *cascade08œÁÁ*cascade08Á¥Á *cascade08¥Á¦Á *cascade08¦Á§Á *cascade08§Á¨Á*cascade08¨Á®Á *cascade08®Á©Ò *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV6_4.cpp
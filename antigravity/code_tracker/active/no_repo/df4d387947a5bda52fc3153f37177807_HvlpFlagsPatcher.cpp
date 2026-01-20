¶H// HvlpFlagsPatcher.cpp - Patch HvlpFlags to spoof hypervisor running
// Patches the exact addresses found by MasterCacheFinder
// Simple, focused, safe!

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
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

bool WriteKernelByte(uint64_t address, uint8_t value) {
  INTEL_VIRT_TO_PHYS vtop = {0};
  vtop.case_number = INTEL_CASE_VIRT_TO_PHYS;
  vtop.address_to_translate = address;

  DWORD bytesReturned = 0;
  DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &vtop, sizeof(vtop), &vtop,
                  sizeof(vtop), &bytesReturned, nullptr);

  uint64_t physAddr = vtop.return_physical_address;

  INTEL_MAP_PHYS mapInfo = {0};
  mapInfo.case_number = INTEL_CASE_MAP_PHYSICAL;
  mapInfo.physical_address_to_map =
      (physAddr != 0) ? (physAddr & ~0xFFFULL) : (address & ~0xFFFULL);
  mapInfo.size = 0x1000;

  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &mapInfo, sizeof(mapInfo),
                       &mapInfo, sizeof(mapInfo), &bytesReturned, nullptr)) {
    // Direct write fallback
    void *pinnedBuffer =
        VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pinnedBuffer)
      return false;
    *(uint8_t *)pinnedBuffer = value;
    VirtualLock(pinnedBuffer, 0x1000);

    INTEL_COPY_MEMORY copyInfo = {0};
    copyInfo.case_number = INTEL_CASE_COPY;
    copyInfo.source = (uint64_t)pinnedBuffer;
    copyInfo.destination = address;
    copyInfo.length = 1;

    BOOL result =
        DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &copyInfo, sizeof(copyInfo),
                        nullptr, 0, &bytesReturned, nullptr);
    VirtualUnlock(pinnedBuffer, 0x1000);
    VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
    return result != FALSE;
  }

  if (mapInfo.return_virtual_address == 0)
    return false;

  uint64_t pageOffset = address & 0xFFF;
  uint64_t targetAddr = mapInfo.return_virtual_address + pageOffset;

  void *pinnedBuffer =
      VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  *(uint8_t *)pinnedBuffer = value;
  VirtualLock(pinnedBuffer, 0x1000);

  INTEL_COPY_MEMORY copyInfo = {0};
  copyInfo.case_number = INTEL_CASE_COPY;
  copyInfo.source = (uint64_t)pinnedBuffer;
  copyInfo.destination = targetAddr;
  copyInfo.length = 1;

  BOOL result =
      DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &copyInfo, sizeof(copyInfo),
                      nullptr, 0, &bytesReturned, nullptr);
  VirtualUnlock(pinnedBuffer, 0x1000);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  return result != FALSE;
}

uint64_t GetModuleBase(const char *moduleName) {
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
      break;
    }
  }
  free(modules);
  return base;
}

int main() {
  printf("================================================================\n");
  printf("       HVLPFLAGS PATCHER                                        \n");
  printf("    Patches HvlpFlags to spoof Hypervisor Running              \n");
  printf(
      "================================================================\n\n");

  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Intel driver not running! Use: sc start iqvw64e\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  uint64_t ntBase = GetModuleBase("ntoskrnl.exe");
  if (!ntBase) {
    printf("[-] ntoskrnl not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] ntoskrnl.exe: 0x%llX\n\n", ntBase);

  // Scan and patch HvlpFlags
  printf("=== SCANNING FOR HvlpFlags ===\n\n");

  uint32_t scanSize = 0x400000; // 4MB
  uint8_t *buffer = (uint8_t *)malloc(scanSize);
  if (!buffer) {
    CloseHandle(hDevice);
    return 1;
  }

  printf("[*] Reading ntoskrnl...\n");
  uint32_t bytesRead = 0;
  for (uint32_t offset = 0; offset < scanSize; offset += 0x1000) {
    if (!SafeReadKernel(ntBase + offset, buffer + offset, 0x1000))
      break;
    bytesRead = offset + 0x1000;
  }
  printf("[+] Read 0x%X bytes\n\n", bytesRead);

  int patchCount = 0;
  uint64_t patchedAddrs[20] = {0};

  // Pattern: F6 05 xx xx xx xx 01 (test byte ptr [rip+xxx], 1)
  for (uint32_t i = 0; i < bytesRead - 10; i++) {
    if (buffer[i] == 0xF6 && buffer[i + 1] == 0x05 && buffer[i + 6] == 0x01) {
      uint8_t nextByte = buffer[i + 7];
      if (nextByte == 0x74 || nextByte == 0x75 || nextByte == 0x0F) {
        int32_t ripOffset = *(int32_t *)(buffer + i + 2);
        uint64_t targetAddr = ntBase + i + 7 + ripOffset;

        // Check if already patched
        bool alreadyDone = false;
        for (int j = 0; j < patchCount; j++) {
          if (patchedAddrs[j] == targetAddr) {
            alreadyDone = true;
            break;
          }
        }
        if (alreadyDone)
          continue;

        uint8_t currentVal = 0;
        if (SafeReadKernel(targetAddr, &currentVal, 1)) {
          if (currentVal == 0) {
            printf("[*] HvlpFlags @ 0x%llX = %d -> patching to 1...\n",
                   targetAddr, currentVal);

            if (WriteKernelByte(targetAddr, 1)) {
              uint8_t verify = 0;
              SafeReadKernel(targetAddr, &verify, 1);
              if (verify == 1) {
                printf("    [+] SUCCESS! Now = %d (Hypervisor Running!)\n",
                       verify);
                patchedAddrs[patchCount++] = targetAddr;
              } else {
                printf("    [-] Verify failed, still = %d\n", verify);
              }
            }
          } else {
            printf("[*] HvlpFlags @ 0x%llX = %d (already set)\n", targetAddr,
                   currentVal);
            patchedAddrs[patchCount++] = targetAddr;
          }
        }

        if (patchCount >= 10)
          break;
      }
    }
  }

  free(buffer);

  printf(
      "\n================================================================\n");
  printf("    PATCHED %d HvlpFlags locations                              \n",
         patchCount);
  printf("    Windows now reports: Hypervisor = RUNNING                  \n");
  printf("================================================================\n");

  CloseHandle(hDevice);
  return 0;
}
¶H2/file:///c:/inject/Spoofers/HvlpFlagsPatcher.cpp
”\// HypervisorBypass.cpp - DYNAMIC Pattern-based (like HVCIBypass)
// Finds patterns and patches in same scan pass
// Uses EXACT same approach as working HVCIBypass

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

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

// ==================== Intel Driver Functions (EXACT COPY FROM HVCIBypass)
// ====================

bool SafeReadKernel(uint64_t address, void *buffer, uint64_t size) {
  if (size > 0x1000)
    size = 0x1000;
  void *pinnedBuffer =
      VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  VirtualLock(pinnedBuffer, 0x1000);

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

  VirtualUnlock(pinnedBuffer, 0x1000);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  Sleep(1);
  return result != FALSE;
}

// EXACT COPY from working HVCIBypass
bool WriteKernelByte(uint64_t address, uint8_t value) {
  INTEL_VIRT_TO_PHYS vtop = {0};
  vtop.case_number = INTEL_CASE_VIRT_TO_PHYS;
  vtop.address_to_translate = address;

  DWORD bytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &vtop, sizeof(vtop), &vtop,
                       sizeof(vtop), &bytesReturned, nullptr)) {
    // Try direct write
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

  uint64_t physAddr = vtop.return_physical_address;
  if (physAddr == 0)
    return false;

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

// WMI Cache refresh
void KillProcess(const wchar_t *name) {
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return;
  PROCESSENTRY32W pe = {sizeof(pe)};
  if (Process32FirstW(hSnap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, name) == 0) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
        if (hProc) {
          TerminateProcess(hProc, 0);
          CloseHandle(hProc);
        }
      }
    } while (Process32NextW(hSnap, &pe));
  }
  CloseHandle(hSnap);
}

void RefreshCache() {
  printf("\n[*] Refreshing WMI cache...\n");
  KillProcess(L"wmiprvse.exe");
  system("net stop winmgmt /y >nul 2>&1");
  Sleep(500);
  system("net start winmgmt >nul 2>&1");
  printf("    [+] WMI cache refreshed\n");
}

// ==================== Registry Spoofing ====================

void SpoofRegistry() {
  printf("\n[*] Setting registry keys...\n");
  HKEY hKey;
  DWORD value;

  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0,
                      NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey,
                      NULL) == ERROR_SUCCESS) {
    value = 2; // Status = Running
    RegSetValueExW(hKey, L"VirtualizationBasedSecurityStatus", 0, REG_DWORD,
                   (BYTE *)&value, sizeof(value));
    printf("    [+] VBS Status = 2 (Running)\n");
    RegCloseKey(hKey);
  }

  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenar"
                      L"ios\\HypervisorEnforcedCodeIntegrity",
                      0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey,
                      NULL) == ERROR_SUCCESS) {
    value = 2; // Running
    RegSetValueExW(hKey, L"Running", 0, REG_DWORD, (BYTE *)&value,
                   sizeof(value));
    printf("    [+] HVCI Running = 2\n");
    RegCloseKey(hKey);
  }
}

// ==================== Main ====================

int main() {
  printf("================================================================\n");
  printf("       HYPERVISOR BYPASS (Dynamic Pattern)                      \n");
  printf("    Scans and patches HvlpFlags in one pass                    \n");
  printf(
      "================================================================\n\n");

  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Intel driver not running!\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  uint32_t ntSize = 0;
  uint64_t ntBase = GetKernelModuleBase("ntoskrnl.exe", &ntSize);
  if (!ntBase) {
    printf("[-] ntoskrnl.exe not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] ntoskrnl.exe: 0x%llX (size: 0x%X)\n", ntBase, ntSize);

  // Read 4MB of ntoskrnl (same as HVCIBypass approach)
  uint32_t scanSize = min(ntSize, 0x400000u); // 4MB like HVCIBypass
  printf("\n[*] Reading ntoskrnl.exe (4MB)...\n");

  uint8_t *ntBuffer = (uint8_t *)malloc(scanSize);
  if (!ntBuffer) {
    CloseHandle(hDevice);
    return 1;
  }

  uint32_t bytesRead = 0;
  for (uint32_t offset = 0; offset < scanSize; offset += 0x1000) {
    if (!SafeReadKernel(ntBase + offset, ntBuffer + offset, 0x1000))
      break;
    bytesRead = offset + 0x1000;
    if ((offset % 0x100000) == 0 && offset > 0) {
      printf("  Progress: %d%%\n", (offset * 100) / scanSize);
    }
  }
  printf("[+] Read 0x%X bytes\n", bytesRead);

  // Find and patch HvlpFlags patterns
  printf("\n=== PATCHING HYPERVISOR FLAGS ===\n\n");

  int patchCount = 0;
  uint64_t lastPatchedTarget = 0;

  // Pattern: F6 05 xx xx xx xx 01 74/75/0F (test byte ptr [rip+xxx], 1)
  // Patch the TARGET variable to 1
  for (uint64_t i = 0; i < bytesRead - 10 && patchCount < 3; i++) {
    if (ntBuffer[i] == 0xF6 && ntBuffer[i + 1] == 0x05 &&
        ntBuffer[i + 6] == 0x01) {
      uint8_t nextByte = ntBuffer[i + 7];
      if (nextByte == 0x74 || nextByte == 0x75 || nextByte == 0x0F) {
        int32_t ripOffset = *(int32_t *)(ntBuffer + i + 2);
        uint64_t targetAddr = ntBase + i + 7 + ripOffset;

        // Skip if same target as last patch
        if (targetAddr == lastPatchedTarget)
          continue;

        // Read current value
        uint8_t currentVal = 0;
        if (!SafeReadKernel(targetAddr, &currentVal, 1))
          continue;

        printf("[*] HvlpFlags check at 0x%llX\n", ntBase + i);
        printf("    Target: 0x%llX = %d\n", targetAddr, currentVal);

        // Only patch if currently 0
        if (currentVal == 0) {
          if (WriteKernelByte(targetAddr, 1)) {
            uint8_t verify = 0;
            SafeReadKernel(targetAddr, &verify, 1);
            if (verify == 1) {
              printf("    [PATCHED] 0 -> 1\n\n");
              patchCount++;
              lastPatchedTarget = targetAddr;
            }
          }
        } else {
          printf("    [OK] Already %d\n\n", currentVal);
          patchCount++;
          lastPatchedTarget = targetAddr;
        }
      }
    }
  }

  printf("[*] Patched %d unique hypervisor flags\n", patchCount);

  // Registry spoof
  SpoofRegistry();

  // Refresh cache
  RefreshCache();

  printf(
      "\n================================================================\n");
  printf("HYPERVISOR BYPASS APPLIED!\n");
  printf("================================================================\n");
  printf("\n=> Now run HVCIBypass.exe then try Valorant!\n");

  free(ntBuffer);
  CloseHandle(hDevice);
  return 0;
}
”\2/file:///c:/inject/Spoofers/HypervisorBypass.cpp
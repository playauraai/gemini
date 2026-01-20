нг// SVMHypervisorV6.cpp
// Step 6: Initialize VMCB + Execute VMRUN
// THE BIG ONE - This sets CPUID hypervisor bit!

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

// VMCB offsets (AMD Manual)
#define VMCB_CTRL_INTERCEPT_MISC1 0x00C // Intercept misc instructions
#define VMCB_CTRL_INTERCEPT_MISC2                                              \
  0x010 // Intercept misc instructions 2 (CPUID here!)
#define VMCB_CTRL_GUEST_ASID 0x058
#define VMCB_CTRL_EXITCODE 0x070
#define VMCB_CTRL_EXITINFO1 0x078
#define VMCB_CTRL_EXITINFO2 0x080
#define VMCB_CTRL_NRIP 0x0C8 // Next RIP

#define VMCB_SAVE_ES_SELECTOR 0x400
#define VMCB_SAVE_CS_SELECTOR 0x410
#define VMCB_SAVE_SS_SELECTOR 0x420
#define VMCB_SAVE_DS_SELECTOR 0x430
#define VMCB_SAVE_GDTR_BASE 0x460
#define VMCB_SAVE_GDTR_LIMIT 0x468
#define VMCB_SAVE_IDTR_BASE 0x478
#define VMCB_SAVE_IDTR_LIMIT 0x480
#define VMCB_SAVE_EFER 0x4D0
#define VMCB_SAVE_CR4 0x548
#define VMCB_SAVE_CR3 0x550
#define VMCB_SAVE_CR0 0x558
#define VMCB_SAVE_RFLAGS 0x570
#define VMCB_SAVE_RIP 0x578
#define VMCB_SAVE_RSP 0x5D8
#define VMCB_SAVE_RAX 0x5F8
#define VMCB_SAVE_PAT 0x668

// Intercept bits
#define INTERCEPT_CPUID (1 << 18) // Bit 18 in MISC2

// VMEXIT codes
#define VMEXIT_CPUID 0x72
#define VMEXIT_VMRUN 0x80

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

bool WriteKernelWord(uint64_t address, uint16_t value) {
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

// ==================== Shellcode ====================

// Shellcode: Enable SVME + Set VM_HSAVE_PA
uint8_t setupHsaveShellcode[] = {
    0x50, 0x51, 0x52,                        // push rax, rcx, rdx
    0xB9, 0x80, 0x00, 0x00, 0xC0,            // mov ecx, EFER
    0x0F, 0x32,                              // rdmsr
    0x0D, 0x00, 0x10, 0x00, 0x00,            // or eax, SVME
    0x0F, 0x30,                              // wrmsr
    0xB9, 0x17, 0x01, 0x01, 0xC0,            // mov ecx, VM_HSAVE_PA
    0xB8, 0x00, 0x00, 0x00, 0x00,            // mov eax, <low32> @23
    0xBA, 0x00, 0x00, 0x00, 0x00,            // mov edx, <high32> @28
    0x0F, 0x30,                              // wrmsr
    0x48, 0x31, 0xC0,                        // xor rax, rax
    0x5A, 0x59, 0x48, 0x83, 0xC4, 0x08, 0xC3 // pop rdx, rcx, skip rax, ret
};

// Shellcode: VMRUN
// Takes VMCB PA in rax, executes vmload + vmrun
// Returns exit code
uint8_t vmrunShellcode[] = {
    // Save registers
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx
    0x53, // push rbx
    0x56, // push rsi
    0x57, // push rdi

    // Load VMCB PA into rax (will be patched at offset 8)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // mov rax, vmcb_pa @8

    // vmload - Load guest state from VMCB
    0x0F, 0x01, 0xDA, // vmload rax

    // vmrun - Enter guest mode
    0x0F, 0x01, 0xD8, // vmrun rax

    // vmsave - Save guest state back (after VMEXIT)
    0x0F, 0x01, 0xDB, // vmsave rax

    // Return 0 for success (vmexit happened)
    0x48, 0x31, 0xC0, // xor rax, rax

    // Restore
    0x5F,                   // pop rdi
    0x5E,                   // pop rsi
    0x5B,                   // pop rbx
    0x5A,                   // pop rdx
    0x59,                   // pop rcx
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8
    0xC3                    // ret
};

#define HSAVE_LOW32_OFFSET 23
#define HSAVE_HIGH32_OFFSET 28
#define VMCB_PA_OFFSET 8

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
  printf("       SVM HYPERVISOR V6 - VMCB Init + VMRUN                  \n");
  printf("    *** THE BIG ONE - Sets CPUID Hypervisor Bit! ***          \n");
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

  // ======================== Step 4: Set VM_HSAVE_PA ========================
  printf("\n=== Step 4: Set VM_HSAVE_PA MSR ===\n");
  uint8_t hsaveShellcode[sizeof(setupHsaveShellcode)];
  memcpy(hsaveShellcode, setupHsaveShellcode, sizeof(hsaveShellcode));
  *(uint32_t *)&hsaveShellcode[HSAVE_LOW32_OFFSET] =
      (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&hsaveShellcode[HSAVE_HIGH32_OFFSET] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);

  uint8_t backup[64];
  ReadMemory(kernelNtAddAtom, backup, sizeof(hsaveShellcode));
  WriteToReadOnlyMemory(kernelNtAddAtom, hsaveShellcode,
                        sizeof(hsaveShellcode));

  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(hsaveShellcode));
  printf("[+] SVME enabled + VM_HSAVE_PA set\n");

  // ======================== Step 5: Initialize VMCB ========================
  printf("\n=== Step 5: Initialize VMCB ===\n");

  // Control Area
  // ASID must be non-zero
  WriteKernelDword(vmcbVa + VMCB_CTRL_GUEST_ASID, 1);
  printf("[+] ASID = 1\n");

  // Intercept CPUID (bit 18 in INTERCEPT_MISC2 at offset 0x10)
  WriteKernelDword(vmcbVa + VMCB_CTRL_INTERCEPT_MISC2, INTERCEPT_CPUID);
  printf("[+] CPUID intercept enabled\n");

  // State Save Area - Minimal guest state
  // For first test, use host's current state
  // RIP = address after VMRUN (return point)
  // RSP = current stack
  // RFLAGS = current flags
  // CR0, CR3, CR4, EFER = current values

  // Just set minimal required values
  // Use segment selectors that Windows uses (kernel mode)
  WriteKernelWord(vmcbVa + VMCB_SAVE_CS_SELECTOR, 0x10); // Kernel code
  WriteKernelWord(vmcbVa + VMCB_SAVE_SS_SELECTOR, 0x18); // Kernel stack
  WriteKernelWord(vmcbVa + VMCB_SAVE_DS_SELECTOR, 0x2B); // Data
  WriteKernelWord(vmcbVa + VMCB_SAVE_ES_SELECTOR, 0x2B); // Data

  // CR0: PE + PG + NE (protected mode, paging, numeric error)
  WriteKernelQword(vmcbVa + VMCB_SAVE_CR0, 0x80050033);
  printf("[+] CR0 set\n");

  // EFER: LME + LMA + NXE + SVME (long mode + NX + SVM)
  WriteKernelQword(vmcbVa + VMCB_SAVE_EFER, 0x1D01); // LME|LMA|NXE|SCE|SVME
  printf("[+] EFER set\n");

  // RFLAGS: Just interrupts bit
  WriteKernelQword(vmcbVa + VMCB_SAVE_RFLAGS, 0x202); // IF = 1
  printf("[+] RFLAGS set\n");

  // PAT: Standard value
  WriteKernelQword(vmcbVa + VMCB_SAVE_PAT, 0x0007040600070406ULL);
  printf("[+] PAT set\n");

  printf("[+] VMCB initialized\n");

  // ======================== Step 6: Execute VMRUN ========================
  printf("\n=== Step 6: Execute VMRUN ===\n");
  printf("[*] Hypervisor present (before): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  // Patch vmrun shellcode with VMCB PA
  uint8_t runShellcode[sizeof(vmrunShellcode)];
  memcpy(runShellcode, vmrunShellcode, sizeof(runShellcode));
  *(uint64_t *)&runShellcode[VMCB_PA_OFFSET] = vmcbPa;

  printf("[*] VMCB PA in shellcode: 0x%llX\n", vmcbPa);

  printf(
      "\n================================================================\n");
  printf("WARNING: About to execute VMRUN!\n");
  printf("This may BSOD if VMCB is not properly initialized.\n");
  printf("Press ENTER to continue or Ctrl+C to abort...\n");
  printf("================================================================\n");
  getchar();

  // Backup and execute
  ReadMemory(kernelNtAddAtom, backup, sizeof(runShellcode));
  WriteToReadOnlyMemory(kernelNtAddAtom, runShellcode, sizeof(runShellcode));

  printf("[*] Executing VMRUN...\n");
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(runShellcode));
  printf("[+] NtAddAtom restored\n");

  printf("[*] Result: 0x%X\n", result);

  // Check hypervisor bit
  printf("\n=== Final Status ===\n");
  printf("[*] Hypervisor present (after): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  // Read VMEXIT code from VMCB
  uint64_t exitCode = 0;
  ReadMemory(vmcbVa + VMCB_CTRL_EXITCODE, &exitCode, sizeof(exitCode));
  printf("[*] VMEXIT code: 0x%llX\n", exitCode);

  if (exitCode == VMEXIT_CPUID) {
    printf("[+] VMEXIT due to CPUID - Intercept working!\n");
  }

  CloseHandle(hDevice);
  return 0;
}
нг*cascade082.file:///C:/inject/Spoofers/SVMHypervisorV6.cpp
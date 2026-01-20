Î±// SVMHypervisorV5_9.cpp
// Step 5.9 SAFE: CPUID Intercept (NO emulation yet)
//
// This version:
// 1. Guest executes CPUID with RAX=1
// 2. VMEXIT (code 0x72)
// 3. Read guest RAX from VMCB (should be 1)
// 4. Advance RIP by 2
// 5. Return guest RAX value
//
// NO CPUID execution in host! NO register clobber!
// This proves we can read guest state safely.

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

// ==================== V5.9 SAFE Shellcode ====================
// CPUID Intercept only - NO emulation, NO CPUID in host
//
// Flow:
// 1. Setup VMCB, set guest RAX=1 (CPUID leaf 1)
// 2. VMRUN -> guest executes CPUID -> VMEXIT
// 3. Read guest RAX from VMCB
// 4. Advance RIP by 2
// 5. Return (exit_code << 16) | guest_rax

uint8_t v5_9Shellcode[] = {
    // ===== Prologue - Save ALL host GPRs =====
    0x55, // push rbp
    0x48,
    0x89,
    0xE5, // mov rbp, rsp
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx
    0x53, // push rbx
    0x56, // push rsi
    0x57, // push rdi
    0x41,
    0x50, // push r8
    0x41,
    0x51, // push r9
    0x41,
    0x52, // push r10
    0x41,
    0x53, // push r11

    // ===== Step 1: Enable EFER.SVME =====
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080
    0x0F,
    0x32, // rdmsr
    0x0D,
    0x00,
    0x10,
    0x00,
    0x00, // or eax, 0x1000
    0x0F,
    0x30, // wrmsr

    // ===== Step 2: Write VM_HSAVE_PA MSR =====
    0xB9,
    0x17,
    0x01,
    0x01,
    0xC0, // mov ecx, 0xC0010117
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00, // mov eax, low  @HSAVE_LOW
    0xBA,
    0x00,
    0x00,
    0x00,
    0x00, // mov edx, high @HSAVE_HIGH
    0x0F,
    0x30, // wrmsr

    // ===== Step 3: Load VMCB_PA into RAX =====
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, vmcb_pa @VMCB_PA

    // ===== Step 4: VMSAVE to capture hidden state =====
    0x0F,
    0x01,
    0xDB, // vmsave rax

    // ===== Step 5: Load VMCB_VA into RBX =====
    0x48,
    0xBB,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rbx, vmcb_va @VMCB_VA

    // ===== Steps 6-16: Populate VMCB (same as V5.8) =====
    // CR0
    0x0F,
    0x20,
    0xC0,
    0x48,
    0x89,
    0x83,
    0x58,
    0x05,
    0x00,
    0x00,
    // CR3
    0x0F,
    0x20,
    0xD8,
    0x48,
    0x89,
    0x83,
    0x50,
    0x05,
    0x00,
    0x00,
    // CR4
    0x0F,
    0x20,
    0xE0,
    0x48,
    0x89,
    0x83,
    0x48,
    0x05,
    0x00,
    0x00,
    // EFER
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0,
    0x0F,
    0x32,
    0x48,
    0xC1,
    0xE2,
    0x20,
    0x48,
    0x09,
    0xD0,
    0x48,
    0x89,
    0x83,
    0xD0,
    0x04,
    0x00,
    0x00,
    // GDTR
    0x48,
    0x83,
    0xEC,
    0x10,
    0x0F,
    0x01,
    0x04,
    0x24,
    0x0F,
    0xB7,
    0x04,
    0x24,
    0x89,
    0x83,
    0x64,
    0x04,
    0x00,
    0x00,
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02,
    0x48,
    0x89,
    0x83,
    0x68,
    0x04,
    0x00,
    0x00,
    // IDTR
    0x0F,
    0x01,
    0x0C,
    0x24,
    0x0F,
    0xB7,
    0x04,
    0x24,
    0x89,
    0x83,
    0x84,
    0x04,
    0x00,
    0x00,
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02,
    0x48,
    0x89,
    0x83,
    0x88,
    0x04,
    0x00,
    0x00,
    0x48,
    0x83,
    0xC4,
    0x10,
    // Segment selectors
    0x8C,
    0xC8,
    0x66,
    0x89,
    0x83,
    0x10,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xD0,
    0x66,
    0x89,
    0x83,
    0x20,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xD8,
    0x66,
    0x89,
    0x83,
    0x30,
    0x04,
    0x00,
    0x00,
    0x8C,
    0xC0,
    0x66,
    0x89,
    0x83,
    0x00,
    0x04,
    0x00,
    0x00,
    // Segment limits
    0xB8,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0x89,
    0x83,
    0x04,
    0x04,
    0x00,
    0x00,
    0x89,
    0x83,
    0x14,
    0x04,
    0x00,
    0x00,
    0x89,
    0x83,
    0x24,
    0x04,
    0x00,
    0x00,
    0x89,
    0x83,
    0x34,
    0x04,
    0x00,
    0x00,
    // Segment attributes
    0x66,
    0xC7,
    0x83,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02,
    0x66,
    0xC7,
    0x83,
    0x22,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    0x66,
    0xC7,
    0x83,
    0x32,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    0x66,
    0xC7,
    0x83,
    0x02,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00,
    // RFLAGS
    0x9C,
    0x58,
    0x48,
    0x89,
    0x83,
    0x70,
    0x05,
    0x00,
    0x00,
    // RSP
    0x48,
    0x89,
    0xE0,
    0x48,
    0x89,
    0x83,
    0xD8,
    0x05,
    0x00,
    0x00,

    // ===== Set ASID = 1 =====
    0xC7,
    0x43,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Set intercepts (CPUID + VMRUN) =====
    0xC7,
    0x43,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x00, // CPUID intercept
    0xC7,
    0x43,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00, // VMRUN intercept

    // ===== Set guest RIP = address of guest CPUID =====
    0x48,
    0x8D,
    0x05,
    0x00,
    0x00,
    0x00,
    0x00, // lea rax, [rip+XX] @LEA_DISP
    0x48,
    0x89,
    0x83,
    0x78,
    0x05,
    0x00,
    0x00, // mov [rbx+0x578], rax

    // ===== Set guest RAX = 1 (CPUID leaf 1) =====
    0x48,
    0xC7,
    0x83,
    0xF8,
    0x05,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00, // mov qword [rbx+0x5F8], 1

    // ===== Load VMCB_PA into RAX for vmrun =====
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, vmcb_pa @VMCB_PA2

    // ===== VMRUN =====
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload rax
    0x0F,
    0x01,
    0xD8, // vmrun rax
    // ===== VMEXIT returns here =====
    0x0F,
    0x01,
    0xDB, // vmsave rax
    0x0F,
    0x01,
    0xDC, // stgi
    0xFB, // sti

    // ===== Read exit code into ESI =====
    0x8B,
    0x73,
    0x70, // mov esi, [rbx+0x70]

    // ===== Read guest RAX from VMCB into EDI =====
    0x8B,
    0xBB,
    0xF8,
    0x05,
    0x00,
    0x00, // mov edi, [rbx+0x5F8]

    // ===== Advance guest RIP by 2 =====
    0x48,
    0x8B,
    0x83,
    0x78,
    0x05,
    0x00,
    0x00, // mov rax, [rbx+0x578]
    0x48,
    0x83,
    0xC0,
    0x02, // add rax, 2
    0x48,
    0x89,
    0x83,
    0x78,
    0x05,
    0x00,
    0x00, // mov [rbx+0x578], rax

    // ===== Return: EAX = (exit_code << 16) | guest_rax =====
    0x89,
    0xF0, // mov eax, esi  ; exit code
    0xC1,
    0xE0,
    0x10, // shl eax, 16
    0x09,
    0xF8, // or eax, edi   ; guest RAX (should be 1)

    // ===== Epilogue =====
    0x41,
    0x5B, // pop r11
    0x41,
    0x5A, // pop r10
    0x41,
    0x59, // pop r9
    0x41,
    0x58, // pop r8
    0x5F, // pop rdi
    0x5E, // pop rsi
    0x5B, // pop rbx
    0x5A, // pop rdx
    0x59, // pop rcx
    0x48,
    0x83,
    0xC4,
    0x08, // add rsp, 8
    0x5D, // pop rbp
    0xC3, // ret

    // ===== Guest code: CPUID =====
    0x0F,
    0xA2, // cpuid (guest will execute this with RAX=1)
};

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V5.9 SAFE - CPUID Intercept Only         \n");
  printf("    Intercept CPUID, read guest RAX, NO emulation              \n");
  printf(
      "================================================================\n\n");

  // Calculate offsets dynamically
  printf("[*] Calculating shellcode offsets...\n");

  size_t OFF_HSAVE_LOW = 0, OFF_HSAVE_HIGH = 0;
  size_t OFF_VMCB_PA1 = 0, OFF_VMCB_VA = 0, OFF_VMCB_PA2 = 0;
  size_t OFF_LEA_DISP = 0;
  size_t LOC_GUEST_CODE = 0;

  // Find HSAVE patches (B8 followed by BA)
  for (size_t i = 0; i < sizeof(v5_9Shellcode) - 10; i++) {
    if (v5_9Shellcode[i] == 0xB8 && v5_9Shellcode[i + 5] == 0xBA &&
        OFF_HSAVE_LOW == 0) {
      OFF_HSAVE_LOW = i + 1;
      OFF_HSAVE_HIGH = i + 6;
      break;
    }
  }

  // Find mov rax, imm64 (48 B8)
  int movRaxCount = 0;
  for (size_t i = 0; i < sizeof(v5_9Shellcode) - 10; i++) {
    if (v5_9Shellcode[i] == 0x48 && v5_9Shellcode[i + 1] == 0xB8) {
      movRaxCount++;
      if (movRaxCount == 1)
        OFF_VMCB_PA1 = i + 2;
      if (movRaxCount == 2)
        OFF_VMCB_PA2 = i + 2;
    }
  }

  // Find mov rbx, imm64 (48 BB)
  for (size_t i = 0; i < sizeof(v5_9Shellcode) - 10; i++) {
    if (v5_9Shellcode[i] == 0x48 && v5_9Shellcode[i + 1] == 0xBB) {
      OFF_VMCB_VA = i + 2;
      break;
    }
  }

  // Find LEA (48 8D 05)
  for (size_t i = 0; i < sizeof(v5_9Shellcode) - 10; i++) {
    if (v5_9Shellcode[i] == 0x48 && v5_9Shellcode[i + 1] == 0x8D &&
        v5_9Shellcode[i + 2] == 0x05) {
      OFF_LEA_DISP = i + 3;
      break;
    }
  }

  // Guest code is at the very end (1 CPUID = 2 bytes)
  LOC_GUEST_CODE = sizeof(v5_9Shellcode) - 2;

  printf("    HSAVE: LOW=%zu, HIGH=%zu\n", OFF_HSAVE_LOW, OFF_HSAVE_HIGH);
  printf("    VMCB_PA1=%zu, VMCB_VA=%zu, VMCB_PA2=%zu\n", OFF_VMCB_PA1,
         OFF_VMCB_VA, OFF_VMCB_PA2);
  printf("    LEA_DISP=%zu, GUEST_CODE=%zu\n", OFF_LEA_DISP, LOC_GUEST_CODE);
  printf("    Total shellcode: %zu bytes\n\n", sizeof(v5_9Shellcode));

  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Intel driver not running!\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  uint64_t kernelExAllocatePool =
      GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");

  // Allocate memory
  uint64_t allocatedAddr = 0;
  CallKernelFunction<uint64_t>(&allocatedAddr, kernelExAllocatePool, 0, 0x2000,
                               0x484D5653);
  if (!allocatedAddr) {
    printf("[-] Allocation failed!\n");
    return 1;
  }

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  uint64_t vmcbPa = 0, hsavePa = 0;
  GetPhysicalAddress(vmcbVa, &vmcbPa);
  GetPhysicalAddress(hsaveVa, &hsavePa);
  printf("[+] VMCB VA: 0x%llX PA: 0x%llX\n", vmcbVa, vmcbPa);
  printf("[+] HSAVE VA: 0x%llX PA: 0x%llX\n", hsaveVa, hsavePa);

  // Zero memory
  uint8_t zeros[0x1000] = {0};
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);

  // Patch shellcode
  uint8_t patched[sizeof(v5_9Shellcode)];
  memcpy(patched, v5_9Shellcode, sizeof(patched));

  *(uint32_t *)&patched[OFF_HSAVE_LOW] = (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patched[OFF_HSAVE_HIGH] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patched[OFF_VMCB_PA1] = vmcbPa;
  *(uint64_t *)&patched[OFF_VMCB_VA] = vmcbVa;
  *(uint64_t *)&patched[OFF_VMCB_PA2] = vmcbPa;

  // Calculate LEA displacement to guest code
  int32_t leaDisp = (int32_t)(LOC_GUEST_CODE - (OFF_LEA_DISP + 4));
  *(int32_t *)&patched[OFF_LEA_DISP] = leaDisp;

  printf("[+] LEA displacement: %d\n", leaDisp);
  printf("[+] Shellcode patched (%zu bytes)\n\n", sizeof(patched));

  printf("Press ENTER to execute CPUID intercept...\n");
  getchar();

  // Execute
  uint8_t backup[512];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patched));
  WriteToReadOnlyMemory(kernelNtAddAtom, patched, sizeof(patched));

  printf("[*] Executing V5.9 SAFE (CPUID Intercept)...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patched));
  printf("[+] NtAddAtom restored\n\n");

  // Decode result
  uint32_t ret = (uint32_t)result;
  uint32_t exitCode = (ret >> 16) & 0xFFFF;
  uint32_t guestRax = ret & 0xFFFF;

  printf("=== CPUID Intercept Results ===\n");
  printf("[*] VMEXIT code: 0x%X\n", exitCode);
  printf("[*] Guest RAX (CPUID leaf): %d\n", guestRax);

  if (exitCode == 0x72 && guestRax == 1) {
    printf("\n");
    printf("========================================\n");
    printf("  [+] SUCCESS! CPUID Intercept Works!  \n");
    printf("  [+] Exit code = 0x72 (CPUID)         \n");
    printf("  [+] Guest RAX = 1 (CPUID leaf 1)     \n");
    printf("  [+] Ready for host context frame!    \n");
    printf("========================================\n");
  } else {
    printf("\n[!] Unexpected results - check VMCB\n");
  }

  CloseHandle(hDevice);
  return 0;
}
% *cascade08%**cascade08*2 *cascade082A*cascade08AM *cascade08MN*cascade08NW *cascade08WX*cascade08XY *cascade08Y]*cascade08]^ *cascade08^b*cascade08bc *cascade08ch*cascade08hi *cascade08im*cascade08m† *cascade08†‡*cascade08‡ *cascade08’*cascade08’“ *cascade08“•*cascade08•– *cascade08–™*cascade08™š *cascade08š*cascade08  *cascade08 ¥*cascade08¥« *cascade08«¬*cascade08¬­ *cascade08­®*cascade08®¯ *cascade08¯±*cascade08±² *cascade08²´*cascade08´¸ *cascade08¸»*cascade08»¼ *cascade08¼½*cascade08½¾ *cascade08¾À*cascade08ÀÁ *cascade08ÁÇ*cascade08ÇÈ *cascade08ÈÊ*cascade08ÊÌ *cascade08ÌÍ*cascade08ÍÑ *cascade08ÑÓ*cascade08ÓØ *cascade08ØÚ*cascade08Úæ *cascade08æë*cascade08ëğ *cascade08ğò*cascade08òù *cascade08ù‰*cascade08‰’ *cascade08’š*cascade08š› *cascade08›*cascade08 *cascade08¤*cascade08¤§ *cascade08§©*cascade08©« *cascade08«­*cascade08­® *cascade08®°*cascade08°± *cascade08±²*cascade08²³ *cascade08³´*cascade08´¶ *cascade08¶¼*cascade08¼½ *cascade08½À*cascade08ÀÁ *cascade08ÁÆ*cascade08ÆÇ *cascade08ÇÉ*cascade08ÉÎ *cascade08ÎĞ*cascade08ĞÒ *cascade08ÒÔ*cascade08ÔÕ *cascade08ÕØ*cascade08ØÙ *cascade08Ùã*cascade08ãä *cascade08äò*cascade08òéM *cascade08éMîM*cascade08îM–N *cascade08–N«N*cascade08«N³N *cascade08³N´N*cascade08´NµN *cascade08µNÀN*cascade08ÀNÁN *cascade08ÁNÅN*cascade08ÅN¼O *cascade08¼O½O*cascade08½O¿O *cascade08¿OÀO*cascade08ÀOÁO *cascade08ÁOÃO*cascade08ÃOÄO *cascade08ÄOÅO*cascade08ÅOÇO *cascade08ÇOÉO*cascade08ÉOËO *cascade08ËOÌO*cascade08ÌOÎO *cascade08ÎOÏO*cascade08ÏOÙO *cascade08ÙOÚO*cascade08ÚOñO *cascade08ñOòO*cascade08òOıO *cascade08ıOşO*cascade08şO€P *cascade08€PP*cascade08PƒP *cascade08ƒP„P*cascade08„P†P *cascade08†PˆP*cascade08ˆP‰P *cascade08‰P‹P*cascade08‹PP *cascade08PP*cascade08P”P *cascade08”P•P*cascade08•PÄx *cascade08ÄxÊx*cascade08ÊxØy *cascade08Øyôy*cascade08ôyŠ| *cascade08Š|Œ|*cascade08Œ|| *cascade08||*cascade08|“| *cascade08“|•|*cascade08•|–| *cascade08–|—|*cascade08—|˜| *cascade08˜|›|*cascade08›|´| *cascade08´|µ|*cascade08µ|¿| *cascade08¿|À|*cascade08À|Ê| *cascade08Ê|Í|*cascade08Í|Ö| *cascade08Ö|Ø|*cascade08Ø|ê| *cascade08ê|ë|*cascade08ë|í| *cascade08í|î|*cascade08î|ï| *cascade08ï|ğ|*cascade08ğ|õ| *cascade08õ|ö|*cascade08ö|„} *cascade08„}…}*cascade08…}‡} *cascade08‡}‹}*cascade08‹}š} *cascade08š}›}*cascade08›}Û} *cascade08Û}à}*cascade08à}~ *cascade08~~*cascade08~‘~ *cascade08‘~’~*cascade08’~³€ *cascade08³€´€*cascade08´€¶€ *cascade08¶€·€*cascade08·€¸€ *cascade08¸€º€*cascade08º€¼€ *cascade08¼€¾€*cascade08¾€À€ *cascade08À€Å€*cascade08Å€Æ€ *cascade08Æ€È€*cascade08È€Ê€ *cascade08Ê€Ì€*cascade08Ì€Í€ *cascade08Í€Ñ€*cascade08Ñ€Ò€ *cascade08Ò€Ó€*cascade08Ó€Ô€ *cascade08Ô€Ø€*cascade08Ø€ò€ *cascade08ò€ó€*cascade08ó€‚ *cascade08‚ä*cascade08äæ *cascade08æ‚‚*cascade08‚‚º… *cascade08º…ß…*cascade08ß…ë† *cascade08ë†ğ†*cascade08ğ†ø† *cascade08ø†ú†*cascade08ú†ü† *cascade08ü†‡*cascade08‡‚‡ *cascade08‚‡†‡*cascade08†‡¤‡ *cascade08¤‡§‡*cascade08§‡¨‡ *cascade08¨‡©‡*cascade08©‡ª‡ *cascade08ª‡¬‡*cascade08¬‡µ‡ *cascade08µ‡¼‡*cascade08¼‡½‡ *cascade08½‡¾‡*cascade08¾‡À‡ *cascade08À‡Â‡*cascade08Â‡Ã‡ *cascade08Ã‡Ä‡*cascade08Ä‡Å‡ *cascade08Å‡Ç‡*cascade08Ç‡É‡ *cascade08É‡Î‡*cascade08Î‡Ğ‡ *cascade08Ğ‡Õ‡*cascade08Õ‡±¦ *cascade08±¦¸¦*cascade08¸¦•¨ *cascade08•¨š¨*cascade08š¨¡¨ *cascade08¡¨©¨*cascade08©¨›« *cascade08›«œ«*cascade08œ«« *cascade08««*cascade08«Ÿ« *cascade08Ÿ«¡«*cascade08¡«£« *cascade08£«¨«*cascade08¨«°« *cascade08°«²«*cascade08²«µ« *cascade08µ«¶«*cascade08¶«¹« *cascade08¹«º«*cascade08º«¼« *cascade08¼«½«*cascade08½«À« *cascade08À«Ã«*cascade08Ã«Å« *cascade08Å«Ë«*cascade08Ë«Ô« *cascade08Ô«Ö«*cascade08Ö«å« *cascade08å«ç«*cascade08ç«è« *cascade08è«í«*cascade08í«î« *cascade08î«ï«*cascade08ï«ñ« *cascade08ñ«ò«*cascade08ò«ô« *cascade08ô«ø«*cascade08ø«¬ *cascade08¬ƒ¬*cascade08ƒ¬‘¬ *cascade08‘¬“¬*cascade08“¬–¬ *cascade08–¬—¬*cascade08—¬š¬ *cascade08š¬¬*cascade08¬¶¬ *cascade08¶¬¾¬*cascade08¾¬­ *cascade08­’­*cascade08’­“­ *cascade08“­”­*cascade08”­–­ *cascade08–­˜­*cascade08˜­›­ *cascade08›­ ­*cascade08 ­¡­ *cascade08¡­¢­*cascade08¢­£­ *cascade08£­¤­*cascade08¤­©­ *cascade08©­ª­*cascade08ª­×­ *cascade08×­Ù­*cascade08Ù­Ú­ *cascade08Ú­Ş­*cascade08Ş­Ø® *cascade08Ø®Ù®*cascade08Ù®Ú® *cascade08Ú®á®*cascade08á®„¯ *cascade08„¯…¯*cascade08…¯ˆ¯ *cascade08ˆ¯Œ¯*cascade08Œ¯¯ *cascade08¯“¯*cascade08“¯”¯ *cascade08”¯›¯*cascade08›¯¤¯ *cascade08¤¯«¯*cascade08«¯¯¯ *cascade08¯¯Ù¯*cascade08Ù¯ø¯ *cascade08ø¯ü¯*cascade08ü¯ı¯ *cascade08ı¯€°*cascade08€°° *cascade08°…°*cascade08…°†° *cascade08†°°*cascade08°° *cascade08°”°*cascade08”°ø° *cascade08ø°ı°*cascade08ı°ÿ° *cascade08ÿ°‚±*cascade08‚±± *cascade08±±*cascade08±± *cascade08±’±*cascade08’±“± *cascade08“±—±*cascade08—±Î± *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV5_9.cpp
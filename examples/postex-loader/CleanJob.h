#pragma once
#include "LoaderTypes.h"
#include <intrin.h>

void CleanJob(DLLMAIN entryPoint, ULONG_PTR loadedDllBaseAddress, void* loaderStart, NT_CREATETHREADEX NtCreateThreadEx, NT_GETCONTEXTTHREAD NtGetContextThread, RTL_EXITUSERTHREAD RtlExitUserThread, NT_SETCONTEXTTHREAD NtSetContextThread, NT_RESUMETHREAD NtResumeThread, WAITFORSINGLEOBJECTS WaitForSingleObject, VIRTUALFREE VirtualFree, RTL_CAPTURECONTEXT RtlCaptureContext, NT_CONTINUE NtContinue, VIRTUALQUERY VirtualQuery, PVOID TpReleaseCleanupGroupMembers, UNMAPVIEWOFFILE UnmapViewOfFile);
PVOID GetCleanData(PDWORD Length);
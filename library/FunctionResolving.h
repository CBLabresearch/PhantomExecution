#pragma once
#include <windows.h>

#include "LoaderTypes.h"
#include "Hash.h"

// Calculate hashes for base set of loader APIs
constexpr DWORD KERNEL32DLL_HASH = CompileTimeHash("kernel32.dll");
constexpr DWORD NTDLLDLL_HASH = CompileTimeHash("ntdll.dll");
constexpr DWORD LOADLIBRARYA_HASH = CompileTimeHash("LoadLibraryA");
constexpr DWORD GETPROCADDRESS_HASH = CompileTimeHash("GetProcAddress");
constexpr DWORD VIRTUALALLOC_HASH = CompileTimeHash("VirtualAlloc");
constexpr DWORD VIRTUALPROTECT_HASH = CompileTimeHash("VirtualProtect");
constexpr DWORD NTFLUSHINSTRUCTIONCACHE_HASH = CompileTimeHash("NtFlushInstructionCache");

constexpr DWORD NTCreateThreadEx_HASH = CompileTimeHash("NtCreateThreadEx");
constexpr DWORD NTGetContextThread_HASH = CompileTimeHash("NtGetContextThread");
constexpr DWORD NTSetContextThread_HASH = CompileTimeHash("NtSetContextThread");
constexpr DWORD NTResumeThread_HASH = CompileTimeHash("NtResumeThread");
constexpr DWORD RtlCaptureContext_HASH = CompileTimeHash("RtlCaptureContext");
constexpr DWORD VirtualFree_HASH = CompileTimeHash("VirtualFree");
constexpr DWORD NtContinue_HASH = CompileTimeHash("NtContinue");
constexpr DWORD RtlExitUserThread_HASH = CompileTimeHash("RtlExitUserThread");
constexpr DWORD TpReleaseCleanupGroupMembers_HASH = CompileTimeHash("TpReleaseCleanupGroupMembers");
constexpr DWORD WAITFORSINGLEOBJECTS_HASH = CompileTimeHash("WaitForSingleObject");
constexpr DWORD UNMAPVIEWOFFILE_HASH = CompileTimeHash("UnmapViewOfFile");
constexpr DWORD VIRTUALQUERY_HASH = CompileTimeHash("VirtualQuery");

constexpr DWORD ExitThread_HASH = CompileTimeHash("ExitThread");




ULONG_PTR GetProcAddressByHash(_PPEB pebAddress, DWORD moduleHash, DWORD functionHash);
BOOL ResolveBaseLoaderFunctions(_PPEB pebAddress, PWINDOWSAPIS winApi, PNTSAPIS ntApi, POTHERSAPIS otherApi);


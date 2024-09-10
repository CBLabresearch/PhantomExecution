#pragma once
#include <windows.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD(NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);


typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


typedef NTSTATUS(NTAPI* NT_CREATETHREADEX)(
    PHANDLE     hThread,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    HANDLE      ProcessHandle,
    PVOID       lpStartAddress,
    PVOID       lpParameter,
    ULONG       Flags,
    SIZE_T      StackZeroBits,
    SIZE_T      SizeOfStackCommit,
    SIZE_T      SizeOfStackReserve,
    PVOID       lpBytesBuffer
    );


#define NtCurrentProcess() ((HANDLE)-1)

typedef BOOL(WINAPI* VIRTUALFREE)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
    );

typedef NTSTATUS(NTAPI* NT_GETCONTEXTTHREAD)(HANDLE, PCONTEXT);

typedef NTSTATUS(NTAPI* NT_SETCONTEXTTHREAD)
(
    IN HANDLE ThreadHandle,
    IN PCONTEXT ThreadContext
);


typedef NTSTATUS(NTAPI* NT_RESUMETHREAD)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
    );

typedef VOID(NTAPI* RTL_CAPTURECONTEXT)(
    PCONTEXT ContextRecord
    );

typedef NTSTATUS(NTAPI* NT_CONTINUE)(
    PCONTEXT ContextRecord,
    BOOLEAN TestAlert
    );


typedef VOID(NTAPI* RTL_EXITUSERTHREAD)(
    NTSTATUS ExitStatus
    );

typedef DWORD(WINAPI* WAITFORSINGLEOBJECTS)(
    HANDLE hHandle,
    DWORD  dwMilliseconds
    );

typedef DWORD(WINAPI* QUENEUSERAPC)(
    PAPCFUNC  pfnAPC,
    HANDLE    hThread,
    ULONG_PTR dwData
);

typedef SIZE_T(WINAPI* VIRTUALQUERY)(
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T                    dwLength
);

typedef BOOL(WINAPI* UNMAPVIEWOFFILE)(
    LPCVOID lpBaseAddress
);


typedef BOOL(WINAPI * CREATETIMERQUENETIMER)(
    PHANDLE             phNewTimer,
    HANDLE              TimerQueue,
    WAITORTIMERCALLBACK Callback,
    PVOID               Parameter,
    DWORD               DueTime,
    DWORD               Period,
    ULONG               Flags
);

typedef struct _WINDOWSAPIS {
    LOADLIBRARYA LoadLibraryA;
    GETPROCADDRESS GetProcAddress;
    VIRTUALALLOC VirtualAlloc;
    VIRTUALPROTECT VirtualProtect;
    NTFLUSHINSTRUCTIONCACHE NtFlushInstructionCache;
    VIRTUALFREE VirtualFree;
    PVOID TpReleaseCleanupGroupMembers;

} WINDOWSAPIS, * PWINDOWSAPIS;

typedef struct _NTSAPIS {

    NT_CREATETHREADEX NtCreateThreadEx;
    NT_GETCONTEXTTHREAD NtGetContextThread;
    NT_SETCONTEXTTHREAD NtSetContextThread;
    NT_RESUMETHREAD NtResumeThread;
    RTL_CAPTURECONTEXT RtlCaptureContext;
    NT_CONTINUE NtContinue;
    RTL_EXITUSERTHREAD RtlExitUserThread;
} NTSAPIS, * PNTSAPIS;

typedef struct _OTHERSAPIS {

    WAITFORSINGLEOBJECTS WaitForSingleObject;
    VIRTUALQUERY VirtualQuery;
    UNMAPVIEWOFFILE UnmapViewOfFile;

} OTHERSAPIS, * POTHERSAPIS;

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY {
    //LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA {
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK {
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

/**
 * struct _PEB is defined in Winternl.h but it is incomplete
 * WinDbg> dt -v ntdll!_PEB
 */
typedef struct __PEB {
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct {
    WORD    offset : 12;
    WORD    type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

typedef struct {
    char* start;
    DWORD length;
    DWORD offset;
} RDATA_SECTION, *PRDATA_SECTION;

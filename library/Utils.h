#pragma once
#include <windows.h>
#include "LoaderTypes.h"

/**
 * PIC String Macros
 * https://gist.github.com/EvanMcBroom/d7f6a8fe3b4d8f511b132518b9cf80d7
*/
#define PIC_STRING(NAME, STRING) constexpr char NAME[]{ STRING }
#define PIC_WSTRING(NAME, STRING) constexpr wchar_t NAME[]{ STRING }

void* GetLocation();
_PPEB GetPEBAddress();
ULONG_PTR FindBufferBaseAddress();
ULONG_PTR FindBufferBaseAddressStephenFewer();
BOOL CopyPEHeader(ULONG_PTR srcImage, ULONG_PTR dstAddress);
BOOL CopyPESections(ULONG_PTR srcImage, ULONG_PTR dstAddress);
void ResolveImports(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, PWINDOWSAPIS winApi);
void ProcessRelocations(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress);
BOOL ResolveRdataSection(ULONG_PTR srcImage, ULONG_PTR dstAddress, PRDATA_SECTION rdata);

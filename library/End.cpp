#include <intrin.h>
#include "Utils.h"


#ifdef _DEBUG
// Position the contents of DebugDLL.h (debug_dll[]) at the end of the loader to replicate Release mode
#pragma code_seg(".text$z")
__declspec(allocate(".text$z"))
    #ifdef _WIN64
        #include "DebugDLL.x64.h"
    #elif _WIN32
        #include "DebugDLL.x86.h"
    #endif

#elif _WIN64
// An empty function to determine the end of the .text section in x64 (&LdrEnd + 1)
#pragma code_seg(".text$z")
void LdrEnd() {}

#elif _WIN32
#pragma optimize( "", off )
#pragma code_seg(".text$z")
// A function to determine the end of the .text section in x86
void* LdrEnd() {
    return GetLocation();
}
#pragma optimize( "", on )
#endif

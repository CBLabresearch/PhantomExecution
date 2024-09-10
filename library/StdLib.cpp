#include <windows.h>
#include "StdLib.h"
#include "Hash.h"

/*******************************************************************
 * To avoid problems with function positioning, do not add any new
 * functions above this pragma directive.
********************************************************************/
#pragma code_seg(".text$e")

/**
 * A function to copy memory from one location to another
 *
 * @param dest A pointer to the destination buffer.
 * @param src A pointer to the source buffer.
 * @param size The size of the memory to copy.
 * @return A Boolean value to indicate success
*/
BOOL _memcpy(void* dest, void* src, size_t size) {
    if (dest == NULL || src == NULL) {
        return FALSE;
    }
    char* csrc = (char*)src;
    char* cdest = (char*)dest;
    for (size_t i = 0; i < size; i++) {
        cdest[i] = csrc[i];
    }
    return TRUE;
}

/**
 * A function to compare two memory blocks
 *
 * @param ptr1 A pointer to the destination buffer.
 * @param ptr2 A pointer to the source buffer.
 * @param size Number of bytes to compare.
 * @return A negative value if ptr1 is less than ptr2, a positive value if ptr1 is greater
 *         than ptr2, or 0 if both memory blocks are equal.
*/
int _memcmp(const void* ptr1, const void* ptr2, size_t size) {
	const unsigned char* p1 = (const unsigned char*)ptr1;
	const unsigned char* p2 = (const unsigned char*)ptr2;

	for (size_t i = 0; i < size; ++i) {
		if (p1[i] < p2[i]) {
			return -1;
		}
		else if (p1[i] > p2[i]) {
			return 1;
		}
	}

	return 0;
}

/**
 * A function to fill a block of memory
 *
 * @param dest A pointer to the memory block to be filled.
 * @param ch The byte value to fill the memory block with.
 * @param count Number of bytes to fill.
 * @return A pointer to the memory block dest.
*/
#pragma optimize( "", off )
void* _memset(void* dest, int ch, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    unsigned char value = (unsigned char)ch;

    for (size_t i = 0; i < count; i++) {
        p[i] = value;
    }

    return dest;
}
#pragma optimize( "", on)


int _strcmp(const char* src, const char* dst)
{
    int ret = 0;

    while (!(ret = *(unsigned char*)src - *(unsigned char*)dst) && *dst)
        ++src, ++dst;

    if (ret < 0)
        ret = -1;
    else if (ret > 0)
        ret = 1;

    return ret;
}


#ifdef _DEBUG
#include "FunctionResolving.h"
/**
 * Print the specified string to the console
 *
 * Note: We resolve the Windows APIs each time we call the function to make it 
 * position independent and to avoid passing a DEBUGAPI structure around. 
 * This means the current implementation can be used in Release mode (for debugging) as well.
 * To support Release mode, modify the macro in StdLib.h.
 * 
 * @param format The string to be printed.
 * @param ... Optional number of arguments to facilitate printing format specifiers.
*/
void _printf(const char* format, ...) {
    va_list arglist;
    va_start(arglist, format);
    char buff[1024];

    typedef int (WINAPI* VSPRINTF_S)(char*, size_t, const char*, va_list);
    typedef BOOL(WINAPI* WRITECONSOLEA)(HANDLE, const void*, DWORD, LPDWORD, LPVOID);
    typedef HANDLE(WINAPI* GETSTDHANDLE)(DWORD);

    constexpr DWORD NTDLL_HASH = CompileTimeHash("ntdll.dll");
    constexpr DWORD KERNEL32_HASH = CompileTimeHash("kernel32.dll");
    
    constexpr DWORD vsprintf_s_hash = CompileTimeHash("vsprintf_s");
    constexpr DWORD WriteConsoleA_hash = CompileTimeHash("WriteConsoleA");
    constexpr DWORD GetStdHandle_hash = CompileTimeHash("GetStdHandle");

    // Get the Process Enviroment Block
#ifdef _WIN64
    _PPEB pebAddress = (_PPEB)__readgsqword(0x60);
#elif _WIN32
    _PPEB pebAddress = (_PPEB)__readfsdword(0x30);
#endif
    VSPRINTF_S fnVsprintf_s = (VSPRINTF_S)GetProcAddressByHash(pebAddress, NTDLL_HASH, vsprintf_s_hash);

    int len = fnVsprintf_s(buff, 1024, format, arglist);
    if (len > 0) {
        WRITECONSOLEA fnWriteConsoleA = (WRITECONSOLEA)GetProcAddressByHash(pebAddress, KERNEL32_HASH, WriteConsoleA_hash);
        GETSTDHANDLE fnGetStdHandle = (GETSTDHANDLE)GetProcAddressByHash(pebAddress, KERNEL32_HASH, GetStdHandle_hash);

        fnWriteConsoleA(fnGetStdHandle(STD_OUTPUT_HANDLE), buff, len, NULL, NULL);
    }
    va_end(arglist);
}
#endif _DEBUG

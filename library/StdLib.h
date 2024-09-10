#pragma once
#include <windows.h>

#ifdef _DEBUG
#define PRINT(message, ...) _printf(message, __VA_ARGS__)
void _printf(const char* format, ...);
#else
#define PRINT(message, ...) 
#endif

BOOL _memcpy(void* dest, void* src, size_t size);
int _memcmp(const void* ptr1, const void* ptr2, size_t size);
void* _memset(void* dest, int ch, size_t count);
int _strcmp(const char* src, const char* dst);
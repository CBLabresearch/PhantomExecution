#pragma once

#ifdef _DEBUG
unsigned char debug_dll[];

#elif _WIN64
void LdrEnd();

#elif _WIN32
void* LdrEnd();
#endif

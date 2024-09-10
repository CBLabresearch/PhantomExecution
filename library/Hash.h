#pragma once
#include <Windows.h> 


#define HASH_KEY  0x19
#pragma intrinsic( _rotr )

/**
 * Hash a string at run time.
 *
 * @param str A pointer to the string that should be hashed.
 * @return A hash of the string.
*/
__forceinline DWORD RunTimeHash(const char* str) {
    DWORD hash = 0;
    do {
        hash = _rotr(hash, HASH_KEY);
        if (*str >= 'a') {
            hash += *str - ('a' - 'A');
        }
        else {
            hash += *str;
        }
    } while (*++str);

    return hash;
}

/**
 * Hash data at run time.
 *
 * @param data A pointer to data that should be hashed.
 * @param length A size of the data buffer
 * @return A hash of data.
*/
__forceinline DWORD RunTimeHash(const char* data, size_t length) {
    DWORD hash = 0;
    while (length--) {
        hash = _rotr(hash, HASH_KEY);
        if (*data >= 'a') {
            hash += *data - ('a' - 'A');
        }
        else {
            hash += *data;
        }
        ++data;
    }

    return hash;
}

/**
 * Hash a string at compile time.
 *
 * @param str A pointer to the string that should be hashed.
 * @return A hash of the string.
*/
constexpr DWORD CompileTimeHash(const char* str) {
    DWORD hash = 0;
    do {
        hash = (hash >> HASH_KEY) | (hash << (sizeof(DWORD) * 8 - HASH_KEY));
        if (*str >= 'a') {
            hash += *str - ('a' - 'A');
        }
        else {
            hash += *str;
        }
    } while (*++str);

    return hash;
}

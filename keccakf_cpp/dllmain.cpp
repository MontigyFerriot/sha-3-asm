// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

static uint64_t rol64(uint64_t a, unsigned offset)
{
    return (a << offset) ^ (a >> (64 - offset));
}

void keccakf(uint64_t* state)
{
        constexpr uint64_t keccakf_rndc[24] = {
                0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
                0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
                0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
                0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
                0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
                0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
                0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        };

        constexpr unsigned keccakf_rotc[24] = {
                1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
        };

        constexpr unsigned keccakf_piln[24] = {
                10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6, 1
        };

        uint64_t bc[5];

        for (int round = 0; round < 24; round++) {
            for (int x = 0; x < 5; x++)
                bc[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

            for (int x = 0; x < 5; x++) {
                uint64_t t = bc[(x + 4) % 5] ^ rol64(bc[(x + 1) % 5], 1);

                for (int y = 0; y < 5; y++)
                    state[x + 5 * y] ^= t;
            }

            bc[0] = state[1];

            for (int i = 0; i < 24; i++) {
            int j = keccakf_piln[i];

            bc[1] = state[j];
            state[j] = rol64(bc[0], keccakf_rotc[i]);
            bc[0] = bc[1];
        }

            for (int y = 0; y < 25; y += 5) {
            for (int x = 0; x < 5; x++)
                bc[x] = state[y + x];

            for (int x = 0; x < 5; x++)
                state[y + x] ^= (~bc[(x + 1) % 5]) & bc[(x + 2) % 5];
        }

            state[0] ^= keccakf_rndc[round];
        }
 }

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


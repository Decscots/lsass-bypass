#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "Hello!", "Hi!", MB_OK);
    }
    return TRUE;
}


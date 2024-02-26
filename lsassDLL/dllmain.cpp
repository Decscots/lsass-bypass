#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <format>
#include <iostream>
#include <fstream>
#include <process.hpp>

#pragma comment (lib, "Injector.lib")

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        /* Example of injecting into another process using an lsass handle */
        DisableThreadLibraryCalls(hModule);
        auto process = Process(xorstr_("explorer.exe"), FALSE);
        auto address = process.ManualMap(xorstr_("C:\\helloworld.dll"));
        process.ManualFree(xorstr_("C:\\helloworld.dll"), address);
    }
    return TRUE;
}


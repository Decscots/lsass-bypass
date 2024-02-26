/* 
 * Huge thanks to: 
 * https://github.com/Apxaey/Handle-Hijacking-Anti-Cheat-Bypass/blob/main/Hijack%20Handle.cpp
 * https://github.com/JustasMasiulis/xorstr
 * https://www.unknowncheats.me/forum/anti-cheat-bypass/252728-lsass-exe-bypass-battleye-eac-vac.html
 * https://github.com/TheCruZ/Simple-Manual-Map-Injector/
 */
#if !defined(INJECTOR_LIB)
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <process.hpp>

int main(int argc, char** argv) {
	auto currentProc = Process();
	currentProc.ChangePrivilege(SE_DEBUG_NAME, true);

	auto proc = Process(xorstr_("lsass.exe"));
	auto address = proc.ManualMap(xorstr_("C:\\lsassDLL.dll"));
	proc.ManualFree(xorstr_("C:\\lsassDLL.dll"), address);
	return 0;
}
#endif
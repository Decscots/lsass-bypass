#pragma once
#include <iostream>

#if !defined(INJECTOR_LIB) && !defined(_USRDLL)

#define Log(...) std::cout << __VA_ARGS__ << std::endl \

#else

#define Log(...) \

#endif

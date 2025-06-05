#define UNICODE
#define _UNICODE

#include <windows.h>

#include <array>
#include <cstdio>
#include <cstdlib>

#include "LeakDetector.hpp"
#include "Hooker.hpp"

static inline int Log(unsigned int event, std::array<ULONG_PTR, 15> retval_and_args)
{
    // char dbgStr[1024] = {0};
    // sprintf(dbgStr, "%s retval = %p $0 = %p\n", DebugEventToString(event), retval_and_args[0], retval_and_args[1]);
    // OutputDebugStringA(dbgStr);

    // 发送调试信息，第一个参数为返回值，后面为传入参数
    RaiseException(event, 0, retval_and_args.size(), retval_and_args.data());
    return 0;
}

typedef void*(*malloc_t)(size_t);
IATHooker mallocHooker;
extern "C" void* log_malloc(size_t _Size)
{
    malloc_t originMalloc = reinterpret_cast<malloc_t>(mallocHooker.get_origin_func());
    void* retval = originMalloc(_Size);
    Log(LEAK_DETECTOR_MALLOC_CALL_EVENT, {(ULONG_PTR)retval, (ULONG_PTR)_Size});

    return retval;
}

typedef void*(*calloc_t)(size_t, size_t);
IATHooker callocHooker;
extern "C" void* log_calloc(size_t _NumOfElements,size_t _SizeOfElements)
{
    calloc_t originCalloc = reinterpret_cast<calloc_t>(callocHooker.get_origin_func());
    void* retval = originCalloc(_NumOfElements, _SizeOfElements);
    Log(LEAK_DETECTOR_CALLOC_CALL_EVENT, {(ULONG_PTR)retval, (ULONG_PTR)_NumOfElements, (ULONG_PTR)_SizeOfElements});

    return retval;
}

typedef void(*free_t)(void*);
IATHooker freeHooker;
extern "C" void log_free(void* _Memory)
{
    free_t originFree = reinterpret_cast<free_t>(freeHooker.get_origin_func());
    originFree(_Memory);
    Log(LEAK_DETECTOR_FREE_CALL_EVENT, {(ULONG_PTR)nullptr, (ULONG_PTR)_Memory});
}

typedef void*(*realloc_t)(void *, size_t);
IATHooker reallocHooker;
extern "C" void* log_realloc(void *_Memory, size_t _NewSize)
{
    realloc_t originRealloc = reinterpret_cast<realloc_t>(reallocHooker.get_origin_func());
    void* retval = originRealloc(_Memory, _NewSize);
    Log(LEAK_DETECTOR_REALLOC_CALL_EVENT, {(ULONG_PTR)retval, (ULONG_PTR)_Memory, (ULONG_PTR)_NewSize});

    return retval;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH && !mallocHooker.is_init()) {
        mallocHooker = IATHooker((void*)log_malloc, "malloc");
        callocHooker = IATHooker((void*)log_calloc, "calloc");
        reallocHooker = IATHooker((void*)log_realloc, "realloc");
        freeHooker = IATHooker((void*)log_free, "free");

        mallocHooker.hook();
        callocHooker.hook();
        reallocHooker.hook();
        freeHooker.hook();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        mallocHooker.unhook();
        callocHooker.unhook();
        freeHooker.unhook();
        reallocHooker.unhook();
    }
    return TRUE;
}
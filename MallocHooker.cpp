#define UNICODE
#define _UNICODE

#include <windows.h>

#include <array>
#include <cstdio>
#include <cstdlib>

#include "LeakDetector.hpp"
#include "Hooker.hpp"

static inline int Log(unsigned int event, std::array<void*, 15> retval_and_args)
{
    // char dbgStr[1024] = {0};
    // sprintf(dbgStr, "%s retval = %p $0 = %p\n", DebugEventToString(event), retval_and_args[0], retval_and_args[1]);
    // OutputDebugStringA(dbgStr);

    // 发送调试信息，第一个参数为返回值，后面为传入参数
    RaiseException(event, 0, retval_and_args.size(), reinterpret_cast<ULONG_PTR*>(retval_and_args.data()));
    return 0;
}

typedef void*(*malloc_t)(size_t);
InlineHooker mallocHooker;
extern "C" void* log_malloc(size_t _Size)
{
    mallocHooker.unhook();

    malloc_t originMalloc = reinterpret_cast<malloc_t>(mallocHooker.get_origin_func());
    void* retval = originMalloc(_Size);
    Log(LEAK_DETECTOR_MALLOC_CALL_EVENT, {retval, (void*)_Size});

    mallocHooker.hook();
    return retval;
}

typedef void*(*calloc_t)(size_t, size_t);
InlineHooker callocHooker;
extern "C" void* log_calloc(size_t _NumOfElements,size_t _SizeOfElements)
{
    callocHooker.unhook();

    calloc_t originCalloc = reinterpret_cast<calloc_t>(callocHooker.get_origin_func());
    void* retval = originCalloc(_NumOfElements, _SizeOfElements);
    Log(LEAK_DETECTOR_CALLOC_CALL_EVENT, {retval, (void*)_NumOfElements, (void*)_SizeOfElements});

    callocHooker.hook();
    return retval;
}

typedef void(*free_t)(void*);
InlineHooker freeHooker;
extern "C" void log_free(void* _Memory)
{
    freeHooker.unhook();

    free_t originFree = reinterpret_cast<free_t>(freeHooker.get_origin_func());
    originFree(_Memory);
    Log(LEAK_DETECTOR_FREE_CALL_EVENT, {nullptr, _Memory});

    freeHooker.hook();
}

// IAT 地址
extern "C" void* __imp_malloc;
extern "C" void* __imp_calloc;
extern "C" void* __imp_free;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        mallocHooker = InlineHooker(*(void**)&__imp_malloc, (void*)log_malloc);
        mallocHooker.hook();

        callocHooker = InlineHooker(*(void**)&__imp_calloc, (void*)log_calloc);
        callocHooker.hook();

        freeHooker = InlineHooker(*(void**)&__imp_free, (void*)log_free);
        freeHooker.hook();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        mallocHooker.unhook();
        callocHooker.unhook();
        freeHooker.unhook();
    }
    return TRUE;
}
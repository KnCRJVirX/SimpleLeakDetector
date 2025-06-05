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
MultiHooker mallocHooker;
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
MultiHooker callocHooker;
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
MultiHooker freeHooker;
extern "C" void log_free(void* _Memory)
{
    freeHooker.unhook();

    free_t originFree = reinterpret_cast<free_t>(freeHooker.get_origin_func());
    originFree(_Memory);
    Log(LEAK_DETECTOR_FREE_CALL_EVENT, {nullptr, _Memory});

    freeHooker.hook();
}

typedef void*(*realloc_t)(void *, size_t);
MultiHooker reallocHooker;
extern "C" void* log_realloc(void *_Memory, size_t _NewSize)
{
    reallocHooker.unhook();

    realloc_t originRealloc = reinterpret_cast<realloc_t>(reallocHooker.get_origin_func());
    void* retval = originRealloc(_Memory, _NewSize);
    Log(LEAK_DETECTOR_REALLOC_CALL_EVENT, {retval, _Memory, (void*)_NewSize});

    reallocHooker.hook();
    return retval;
}

bool HookFunc(MultiHooker& hooker, const std::vector<LPWSTR>& moduleList, LPCSTR funcName, PVOID hookFunc)
{
    HMODULE hModule = nullptr;
    void* originFunc = nullptr;
    for (auto& moduleName : moduleList)
    {
        if (hModule = GetModuleHandleW(moduleName)) {
            void* funcAddr = nullptr;
            if (funcAddr = reinterpret_cast<void*>(GetProcAddress(hModule, funcName))) {
                if (originFunc == nullptr) {
                    originFunc = funcAddr;
                }
                hooker.hookers.push_back(std::make_unique<InlineHooker>(funcAddr, hookFunc, GetCurrentProcessId()));
            }
        }
    }
    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        std::vector<LPWSTR> moduleList = {TEXT("ucrtbase.dll"), TEXT("msvcrt.dll")};
        
        HookFunc(mallocHooker, moduleList, "malloc", (void*)log_malloc);
        HookFunc(callocHooker, moduleList, "calloc", (void*)log_calloc);
        HookFunc(reallocHooker, moduleList, "realloc", (void*)log_realloc);
        HookFunc(freeHooker, moduleList, "free", (void*)log_free);

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
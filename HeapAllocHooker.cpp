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

typedef LPVOID(*HeapAlloc_t)(HANDLE, DWORD, SIZE_T);
InlineHooker HeapAllocHooker;
extern "C" LPVOID WINAPI log_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    HeapAllocHooker.unhook();

    HeapAlloc_t originHeapAlloc = reinterpret_cast<HeapAlloc_t>(HeapAllocHooker.get_origin_func());
    LPVOID retval = originHeapAlloc(hHeap, dwFlags, dwBytes);

    Log(LEAK_DETECTOR_HEAPALLOC_CALL_EVENT, {retval, hHeap, (void*)dwFlags, (void*)dwBytes});

    HeapAllocHooker.hook();
    return retval;
}

typedef LPVOID(*HeapReAlloc_t)(HANDLE, DWORD, LPVOID, SIZE_T);
InlineHooker HeapReAllocHooker;
extern "C" LPVOID WINAPI log_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    HeapReAllocHooker.unhook();

    HeapReAlloc_t originHeapReAlloc = reinterpret_cast<HeapReAlloc_t>(HeapReAllocHooker.get_origin_func());
    LPVOID retval = originHeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);

    Log(LEAK_DETECTOR_HEAPREALLOC_CALL_EVENT, {retval, hHeap, (void*)dwFlags, lpMem, (void*)dwBytes});

    HeapReAllocHooker.hook();
    return retval;
}

typedef BOOL(*HeapFree_t)(HANDLE, DWORD, LPVOID);
InlineHooker HeapFreeHooker;
extern "C" BOOL WINAPI log_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    HeapFreeHooker.unhook();

    HeapFree_t originHeapFree = reinterpret_cast<HeapFree_t>(HeapFreeHooker.get_origin_func());
    BOOL retval = originHeapFree(hHeap, dwFlags, lpMem);

    Log(LEAK_DETECTOR_HEAPFREE_CALL_EVENT, {(void*)retval, hHeap, (void*)dwFlags, lpMem});

    HeapFreeHooker.hook();
    return retval;
}

// IAT 地址
extern "C" void* __imp_HeapAlloc;
extern "C" void* __imp_HeapReAlloc;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HeapAllocHooker = InlineHooker(*(void**)&__imp_HeapAlloc, (void*)log_HeapAlloc);
        HeapAllocHooker.hook();

        HeapReAllocHooker = InlineHooker(*(void**)&__imp_HeapReAlloc, (void*)log_HeapReAlloc);
        HeapReAllocHooker.hook();

        HeapFreeHooker = InlineHooker((void*)GetProcAddress(GetModuleHandleW(TEXT("ntdll.dll")), "RtlFreeHeap"), (void*)log_HeapFree);
        HeapFreeHooker.hook();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        HeapAllocHooker.unhook();
        HeapReAllocHooker.unhook();
        HeapFreeHooker.unhook();
    }
    return TRUE;
}
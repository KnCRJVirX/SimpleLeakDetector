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
    RaiseException(event, 0, static_cast<DWORD>(retval_and_args.size()), retval_and_args.data());
    return 0;
}

typedef LPVOID(*HeapAlloc_t)(HANDLE, DWORD, SIZE_T);
IATHooker HeapAllocHooker;
extern "C" LPVOID WINAPI log_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    HeapAlloc_t originHeapAlloc = reinterpret_cast<HeapAlloc_t>(HeapAllocHooker.get_origin_func());
    LPVOID retval = originHeapAlloc(hHeap, dwFlags, dwBytes);

    Log(LEAK_DETECTOR_HEAPALLOC_CALL_EVENT, {(ULONG_PTR)retval, (ULONG_PTR)hHeap, (ULONG_PTR)dwFlags, (ULONG_PTR)dwBytes});

    return retval;
}

typedef LPVOID(*HeapReAlloc_t)(HANDLE, DWORD, LPVOID, SIZE_T);
IATHooker HeapReAllocHooker;
extern "C" LPVOID WINAPI log_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    HeapReAlloc_t originHeapReAlloc = reinterpret_cast<HeapReAlloc_t>(HeapReAllocHooker.get_origin_func());
    LPVOID retval = originHeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);

    Log(LEAK_DETECTOR_HEAPREALLOC_CALL_EVENT, {(ULONG_PTR)retval, (ULONG_PTR)hHeap, (ULONG_PTR)dwFlags, (ULONG_PTR)lpMem, (ULONG_PTR)dwBytes});

    return retval;
}

typedef BOOL(*HeapFree_t)(HANDLE, DWORD, LPVOID);
IATHooker HeapFreeHooker;
extern "C" BOOL WINAPI log_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    HeapFree_t originHeapFree = reinterpret_cast<HeapFree_t>(HeapFreeHooker.get_origin_func());
    BOOL retval = originHeapFree(hHeap, dwFlags, lpMem);

    Log(LEAK_DETECTOR_HEAPFREE_CALL_EVENT, {(ULONG_PTR)retval, (ULONG_PTR)hHeap, (ULONG_PTR)dwFlags, (ULONG_PTR)lpMem});

    return retval;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH && !HeapAllocHooker.is_init()) {
        HeapAllocHooker = IATHooker((void*)log_HeapAlloc, "HeapAlloc");
        HeapReAllocHooker = IATHooker((void*)log_HeapReAlloc, "HeapReAlloc");
        HeapFreeHooker = IATHooker((void*)log_HeapFree, "HeapFree");

        HeapAllocHooker.hook();
        HeapReAllocHooker.hook();
        HeapFreeHooker.hook();

        HeapAllocHooker.set_origin_func((void*)GetProcAddress(GetModuleHandleW(TEXT("ntdll.dll")), "RtlAllocateHeap"));
        HeapReAllocHooker.set_origin_func((void*)GetProcAddress(GetModuleHandleW(TEXT("ntdll.dll")), "RtlReAllocateHeap"));
        HeapFreeHooker.set_origin_func((void*)GetProcAddress(GetModuleHandleW(TEXT("ntdll.dll")), "RtlFreeHeap"));
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        HeapAllocHooker.unhook();
        HeapReAllocHooker.unhook();
        HeapFreeHooker.unhook();
    }
    return TRUE;
}
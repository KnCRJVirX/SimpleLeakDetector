#include "Injector.h"

// BOOL InjectThreadWork(PVOID injectArgs)
// {
//     InjectArgs* _args = (InjectArgs*)injectArgs;
//     return InjectModuleToProcessByRemoteThread(_args->hProcess, _args->pLoadLibraryW, _args->moduleName);
// }

BOOL InjectModuleToProcessByRemoteThread(DWORD processId, PVOID pLoadLibraryW, LPCWSTR moduleName)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    HANDLE hRemoteThread = NULL;
    size_t moduleNameSize = 0;
    LPVOID hRemoteMem = NULL;

    // 分配空间用于写入dll路径
    moduleNameSize = (wcslen(moduleName) + 2) * 2;
    hRemoteMem = VirtualAllocEx(hProcess, NULL, moduleNameSize, MEM_COMMIT, PAGE_READWRITE);
    if (hRemoteMem == NULL) goto err;

    // 写入dll路径
    if (!WriteProcessMemory(hProcess, hRemoteMem, moduleName, moduleNameSize, NULL)) goto err;

    // 创建远程线程
    hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, hRemoteMem, 0, NULL);
    if (hRemoteThread == NULL) goto err;

    // 等待远程线程
    WaitForSingleObject(hRemoteThread, INFINITE);

    // 释放内存，关闭句柄
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;

    err:
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
}
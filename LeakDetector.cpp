#define UNICODE
#define _UNICODE

#include <windows.h>

#include <vector>
#include <cstdio>
#include <cstdlib>

#include "Utils.h"
#include "LeakDetector.hpp"
#include "Injector.h"

int main(int argc, char const *argv[])
{
    UNICODE_INIT();

    char processPath[MAX_PATH] = {0};
    WCHAR processPathW[MAX_PATH];
    char dllPath[MAX_PATH] = {0};
    WCHAR dllPathW[MAX_PATH];
    char logFilePath[MAX_PATH] = {0};

    for (size_t i = 0; i < argc; i++)
    {
        if (!strcmp(argv[i], "-exe")) {
            strcpy(processPath, argv[++i]);
        } else if (!strcmp(argv[i], "-hooker")) {
            strcpy(dllPath, argv[++i]);
        } else if (!strcmp(argv[i], "-log")) {
            strcpy(logFilePath, argv[++i]);
        }
    }

    // 初始化可执行文件路径
    if (processPath[0] == '\0') {
        std::cout << "Exe file path: ";
        fgets(processPath, MAX_PATH, stdin);
    }
    utf8toutf16(processPath, processPathW, MAX_PATH);

    // 初始化Hooker模块路径
    if (dllPath[0] == '\0') {
        GetFullPathNameA("MallocHooker.dll", MAX_PATH, dllPath, NULL);
    }
    utf8toutf16(dllPath, dllPathW, MAX_PATH);

    // 日志文件
    if (logFilePath[0] != '\0')
    {
        LOG.setLogFile(std::string(logFilePath));
    }

    // 运行可执行文件，挂起，注入Hooker，继续运行
    STARTUPINFOW si = {0};
    si.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pi;
    CreateProcessW(processPathW,
                    NULL,
                    NULL, NULL, FALSE,
                    CREATE_SUSPENDED | DEBUG_PROCESS,
                    NULL, NULL, &si, &pi);
    PVOID pLoadLibraryW = (PVOID)GetProcAddress(GetModuleHandleW(TEXT("KERNEL32.dll")), "LoadLibraryW");
    InjectArgs injectArgs{pi.hProcess, pLoadLibraryW, dllPathW};
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InjectThreadWork, (LPVOID)&injectArgs, 0, NULL);
    ResumeThread(pi.hThread);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    MemoryLogger logger{hProcess};
    Debugger debugger{hProcess};
    DEBUG_EVENT dbgEvent = {0};
    while (1)
    {
        WaitForDebugEvent(&dbgEvent, INFINITE);

        // printf("Thread %-5d Debug event: %s\n", dbgEvent.dwThreadId, DebugEventToString(dbgEvent.dwDebugEventCode));
        // LOG << "Thread " << dbgEvent.dwThreadId << " Debug event: " << DebugEventToString(dbgEvent.dwDebugEventCode) << std::endl;

        switch (dbgEvent.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            if (logger.dispatch(&dbgEvent) != DBG_CONTINUE){
                debugger.OnExceptionDebugEvent(&dbgEvent);
            } else {
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
            }
            break;
        case LOAD_DLL_DEBUG_EVENT:
            debugger.OnLoadDllDebugEvent(&dbgEvent);
            break;
        // case OUTPUT_DEBUG_STRING_EVENT:
        //     OnOutputDebugStringEvent(&dbgEvent);
        //     break;
        case CREATE_PROCESS_DEBUG_EVENT:
            debugger.OnCreatePorcessDebugExent(&dbgEvent);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            if (debugger.OnExitProcessDebugEvent(&dbgEvent, logger) == 0) {
                goto out;
            }
            break;
        default:
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
            break;
        }
    }
    out:
    LOG << "All process exited, debug over." << std::endl;
    return 0;
}
#define UNICODE
#define _UNICODE

#include <windows.h>

#include <vector>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "Utils.h"
#include "LeakDetector.hpp"

int main(int argc, char const *argv[])
{
    UNICODE_INIT();

    char processPath[MAX_PATH] = {0};
    WCHAR processPathW[MAX_PATH];
    char dllPath[MAX_PATH] = "MallocHooker.dll";
    // char dllPath[MAX_PATH] = "HeapAllocHooker.dll";
    WCHAR dllPathW[MAX_PATH];
    char logFilePath[MAX_PATH] = "MemoryLeakDetect.log";

    for (size_t i = 0; i < argc; i++)
    {
        if (!strcmp(argv[i], "-exe")) {
            gbktoutf8(argv[++i], processPath, MAX_PATH);
        } else if (!strcmp(argv[i], "-hooker")) {
            gbktoutf8(argv[++i], dllPath, MAX_PATH);
        } else if (!strcmp(argv[i], "-log")) {
            strcpy(logFilePath, argv[++i]);
        }
    }

    // 初始化可执行文件路径
    if (processPath[0] == '\0') {
        std::cout << "Exe file path: ";
        fgets(processPath, MAX_PATH, stdin);
        if (strchr(processPath, '\n')) *(strchr(processPath, '\n')) = 0;
    }
    utf8toutf16(processPath, utf16_buffer, MAX_PATH);
    GetFullPathNameW(utf16_buffer, MAX_PATH, processPathW, NULL);

    // 初始化Hooker模块路径
    utf8toutf16(dllPath, utf16_buffer, M_BUF_SIZ);
    GetFullPathNameW(utf16_buffer, MAX_PATH, dllPathW, NULL);

    // 日志文件
    if (logFilePath[0] != '\0') {
        LOG.setLogFile(std::string(logFilePath));
    }

    // 运行可执行文件，挂起，注入Hooker，继续运行
    STARTUPINFOW si = {0};
    si.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pi;
    CreateProcessW(processPathW,
                    NULL,
                    NULL, NULL, FALSE,
                    DEBUG_PROCESS,
                    NULL, NULL, &si, &pi);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    MemoryLeakDebugger debugger{hProcess, dllPathW};
    DEBUG_EVENT dbgEvent = {0};
    while (1) {
        WaitForDebugEvent(&dbgEvent, INFINITE);

        // LOG << "Thread " << dbgEvent.dwThreadId << " Debug event: " << DebugEventToString(dbgEvent.dwDebugEventCode) << std::endl;

        debugger.dispatch(&dbgEvent);
        if (debugger.isDebugOver()) goto out;
    }
    out:
    
    return 0;
}
#ifndef LEAK_DETECTOR
#define LEAK_DETECTOR

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define LEAK_DETECTOR_MALLOC_CALL_EVENT 0xE00000F1
#define LEAK_DETECTOR_CALLOC_CALL_EVENT 0xE00000F2
#define LEAK_DETECTOR_FREE_CALL_EVENT 0xE00000F3

#include <iostream>
#include <string>
#include <vector>
#include <map>

#include <windows.h>
#include <dbghelp.h>

#include "Utils.h"

// 调试事件代码转换
static inline const char* DebugEventToString(DWORD dbgEventCode)
{
    switch (dbgEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:    return "CREATE_PROCESS_DEBUG_EVENT";
    case CREATE_THREAD_DEBUG_EVENT:     return "CREATE_THREAD_DEBUG_EVENT";
    case EXCEPTION_DEBUG_EVENT:         return "EXCEPTION_DEBUG_EVENT";
    case EXIT_PROCESS_DEBUG_EVENT:      return "EXIT_PROCESS_DEBUG_EVENT";
    case EXIT_THREAD_DEBUG_EVENT:       return "EXIT_THREAD_DEBUG_EVENT";
    case LOAD_DLL_DEBUG_EVENT:          return "LOAD_DLL_DEBUG_EVENT";
    case OUTPUT_DEBUG_STRING_EVENT:     return "OUTPUT_DEBUG_STRING_EVENT";
    case UNLOAD_DLL_DEBUG_EVENT:        return "UNLOAD_DLL_DEBUG_EVENT";
    case RIP_EVENT:                     return "RIP_EVENT";
    case LEAK_DETECTOR_MALLOC_CALL_EVENT:   return "LEAK_DETECTOR_MALLOC_CALL_EVENT";
    case LEAK_DETECTOR_CALLOC_CALL_EVENT:   return "LEAK_DETECTOR_CALLOC_CALL_EVENT";
    case LEAK_DETECTOR_FREE_CALL_EVENT:   return "LEAK_DETECTOR_FREE_CALL_EVENT";
    default:
        return "UNKNOWN_EVENT";
    }
    return NULL;
}

// 栈帧信息
struct StackFrameInfo
{
    void* funcAddr;
    std::string funcName;
    StackFrameInfo(): funcAddr(nullptr), funcName(""){}
    StackFrameInfo(void* _Addr = nullptr, std::string _Name = ""): funcAddr(_Addr), funcName(_Name){}
};

// 内存块被获取的方法（用什么函数获取的堆内存）
enum class MemoryAllocMethod
{
    ByMalloc = 0,
    ByCalloc = 1
};

// 内存块信息
struct MemoryBlockInfo
{
    MemoryAllocMethod allocMethod;
    void* memoryAddr;
    union
    {
        struct ByMalloc
        {
            size_t size;
        } byMalloc;
        struct ByCalloc
        {
            size_t num_of_element;
            size_t size_of_element;
        } byCalloc;
    } sizeInfo;
    bool is_free = false;
    std::vector<StackFrameInfo> stackTrace;

    MemoryBlockInfo(){}
    MemoryBlockInfo(void* addr, size_t _size)
    {
        allocMethod = MemoryAllocMethod::ByMalloc;
        memoryAddr = addr;
        sizeInfo.byMalloc.size = _size; 
    }
    MemoryBlockInfo(void* addr, size_t _NumOfElem, size_t _SizeOfElem)
    {
        allocMethod = MemoryAllocMethod::ByCalloc;
        memoryAddr = addr;
        sizeInfo.byCalloc.num_of_element = _NumOfElem;
        sizeInfo.byCalloc.size_of_element = _SizeOfElem;
    }

    // 获取内存块大小
    size_t size() const
    {
        switch (allocMethod)
        {
        case MemoryAllocMethod::ByMalloc:   return sizeInfo.byMalloc.size;
        case MemoryAllocMethod::ByCalloc:   return sizeInfo.byCalloc.num_of_element * sizeInfo.byCalloc.size_of_element;
        default:
            break;
        }
        return 0;
    }
};

// 堆内存记录器
class MemoryLogger
{
private:
    HANDLE hProcess;
    std::map<void*, MemoryBlockInfo> log;
    std::string get_func_name(DWORD64 funcAddr)
    {
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(hProcess, funcAddr, &displacement, pSymbol)) {
            return std::string(pSymbol->Name);
        }
        return "";
    }
    std::vector<StackFrameInfo> get_stack_trace(DWORD threadId)
    {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (hThread == NULL) return {};

        CONTEXT context = {};
        context.ContextFlags = CONTEXT_FULL;

        SuspendThread(hThread);
        if (!GetThreadContext(hThread, &context)) {
            ResumeThread(hThread);
            return {};
        }

        // 利用StackWalk64遍历栈，获取Stack trace
        STACKFRAME64 frame = {};
        DWORD machineType = IMAGE_FILE_MACHINE_AMD64;

        frame.AddrPC.Offset    = context.Rip;  // 当前指令地址
        frame.AddrPC.Mode      = AddrModeFlat;
        frame.AddrFrame.Offset = context.Rbp;
        frame.AddrFrame.Mode   = AddrModeFlat;
        frame.AddrStack.Offset = context.Rsp;
        frame.AddrStack.Mode   = AddrModeFlat;

        std::vector<StackFrameInfo> stackTrace;
        for (int i = 0; i < 20; ++i) {
            if (!StackWalk64(machineType, hProcess, hThread, &frame, &context,
                NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
                break;

            if (frame.AddrPC.Offset == 0) break;
            // 跳过RaiseException
            if (i < 2) continue;

            stackTrace.push_back(StackFrameInfo((void*)frame.AddrPC.Offset, get_func_name(frame.AddrPC.Offset)));
            // std::cout << "Address: " << std::hex << frame.AddrPC.Offset << std::dec << " Name: " << get_func_name(frame.AddrPC.Offset) << std::endl;
        }

        ResumeThread(hThread);
        CloseHandle(hThread);
        return stackTrace;
    }
public:
    MemoryLogger(HANDLE _hProcess): hProcess(_hProcess){}
    ~MemoryLogger()
    {
        CloseHandle(hProcess);
    }
    int on_malloc_call_event(DEBUG_EVENT* dbgEvent)
    {
        // 解析返回值和参数
        void* ret_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[0];
        size_t alloc_size = (size_t)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];

        MemoryBlockInfo info{ret_memory, alloc_size};
        info.stackTrace = get_stack_trace(dbgEvent->dwThreadId);

        log.insert({ret_memory, info});
        // std::cout << "malloc(" << alloc_size << "), retval = " << std::hex << ret_memory << std::dec << std::endl;
        return DBG_CONTINUE;
    }
    int on_calloc_call_event(DEBUG_EVENT* dbgEvent)
    {
        // 解析返回值和参数
        void* ret_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[0];
        size_t num_of_elem = (size_t)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
        size_t siz_of_elem = (size_t)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[2];

        MemoryBlockInfo info{ret_memory, num_of_elem, siz_of_elem};
        info.stackTrace = get_stack_trace(dbgEvent->dwThreadId);

        log.insert({ret_memory, info});
        // std::cout << "calloc(" << num_of_elem << ", " << siz_of_elem << "), retval = " << std::hex << ret_memory << std::dec << std::endl;
        return DBG_CONTINUE;
    }
    int on_free_call_event(DEBUG_EVENT* dbgEvent)
    {
        // 参数
        void* free_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
        if (log.find(free_memory) != log.end())
        {
            log[free_memory].is_free = true;
        }
        // std::cout << "free(" << std::hex << free_memory << std::dec << ")" << std::endl;
        return DBG_CONTINUE;
    }
    // 根据ExceptionCode分发到handler
    int dispatch(DEBUG_EVENT* dbgEvent)
    {
        if (dbgEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            switch (dbgEvent->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case LEAK_DETECTOR_MALLOC_CALL_EVENT:   return on_malloc_call_event(dbgEvent);
            case LEAK_DETECTOR_CALLOC_CALL_EVENT:   return on_calloc_call_event(dbgEvent);
            case LEAK_DETECTOR_FREE_CALL_EVENT:     return on_free_call_event(dbgEvent);
            default:
                break;
            }
        }
        return 0;
    }
    // 获取泄露的内存信息
    std::vector<MemoryBlockInfo> get_leak_info()
    {
        std::vector<MemoryBlockInfo> res;
        for (auto& [addr, info] : log)
        {
            // 记录未被free的内存块信息
            if (!info.is_free)
            {
                res.push_back(info);
            }
        }
        return res;
    }
};

class Debugger
{
private:
    DWORD processId;
    HANDLE hProcess;
    void init()
    {
        if (hProcess == NULL) {
            return;
        }
        BOOL retval = SymInitializeW(hProcess, TEXT("srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols"), FALSE);
        DWORD err = GetLastError();
    }
public:
    Debugger(){}
    Debugger(HANDLE _hProcess): processId(0), hProcess(_hProcess)
    { init(); }
    ~Debugger()
    {
        SymCleanup(hProcess);
        CloseHandle(hProcess);
    }
    static BOOL PrintSymbol(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
    {
        std::cout << std::hex << pSymInfo->Address << std::dec << pSymInfo->Name << std::endl;
        return TRUE;
    }
    BOOL OnExceptionDebugEvent(DEBUG_EVENT* pDbgEvent)
    {
        printf("Exception code: %x\n", pDbgEvent->u.Exception.ExceptionRecord.ExceptionCode);
        if (pDbgEvent->u.Exception.ExceptionRecord.ExceptionCode == 0x80000003)
        {
            return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
        }
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
    }
    BOOL OnLoadDllDebugEvent(DEBUG_EVENT* pDbgEvent)
    {
        GetFinalPathNameByHandleW(pDbgEvent->u.LoadDll.hFile, utf16_buffer, M_BUF_SIZ, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        printf("Load dll: %s\n", utf16toutf8(utf16_buffer, utf8_buffer, M_BUF_SIZ));

        DWORD64 retval = SymLoadModuleExW(hProcess, pDbgEvent->u.LoadDll.hFile, utf16_buffer, NULL, (DWORD64)pDbgEvent->u.LoadDll.lpBaseOfDll, 0, NULL, 0);
        DWORD err = GetLastError();

        // SymEnumSymbols(hProcess, 0, "*!*", PrintSymbol, NULL);

        CloseHandle(pDbgEvent->u.LoadDll.hFile);
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
    }
    BOOL OnOutputDebugStringEvent(DEBUG_EVENT* pDbgEvent)
    {
        char* stringBuf = (char*)calloc((pDbgEvent->u.DebugString.nDebugStringLength + 2) * 2, 1);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDbgEvent->dwProcessId);
        if (pDbgEvent->u.DebugString.fUnicode)
        {
            ReadProcessMemory(hProcess, pDbgEvent->u.DebugString.lpDebugStringData, stringBuf, pDbgEvent->u.DebugString.nDebugStringLength * 2, NULL);
            printf("Output debug string: %s\n", utf16toutf8((WCHAR*)stringBuf, utf8_buffer, M_BUF_SIZ));
        }
        else
        {
            ReadProcessMemory(hProcess, pDbgEvent->u.DebugString.lpDebugStringData, stringBuf, pDbgEvent->u.DebugString.nDebugStringLength, NULL);
            printf("Output debug string: %s\n", gbktoutf8(stringBuf, utf8_buffer, M_BUF_SIZ));
        }
        CloseHandle(hProcess);
        free(stringBuf);
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
    }
    BOOL OnExitProcessDebugEvent(DEBUG_EVENT* pDbgEvent, MemoryLogger& logger)
    {
        std::cout << std::endl;
        auto leak_memories = logger.get_leak_info();
        for (auto& info : leak_memories)
        {
            std::cout << "Possible leak " << info.size() << " bytes." << std::endl;
            std::cout << "Address: " << info.memoryAddr << std::endl;
            std::cout << "Alloc method: ";
            switch (info.allocMethod)
            {
            case MemoryAllocMethod::ByMalloc:
                std::cout << "malloc(" << info.sizeInfo.byMalloc.size << ")";
                break;
            case MemoryAllocMethod::ByCalloc:
                std::cout << "calloc(" << info.sizeInfo.byCalloc.num_of_element << ", " << info.sizeInfo.byCalloc.size_of_element << ")";
                break;
            default:
                break;
            }
            std::cout << std::endl;

            std::cout << "Stack trace: " << std::endl;
            for (auto& stackFrame : info.stackTrace)
            {
                std::cout << std::hex << stackFrame.funcAddr << std::dec << "\t" << stackFrame.funcName << std::endl;
            }
            std::cout << std::endl;
        }

        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
    }
};

#endif
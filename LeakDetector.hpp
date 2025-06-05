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
#define LEAK_DETECTOR_REALLOC_CALL_EVENT 0xE00000F4
#define LEAK_DETECTOR_HEAPALLOC_CALL_EVENT 0xE00000F5
#define LEAK_DETECTOR_HEAPREALLOC_CALL_EVENT 0xE00000F7
#define LEAK_DETECTOR_HEAPFREE_CALL_EVENT 0xE00000F8

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <algorithm>
#include <thread>

#include <windows.h>
#include <dbghelp.h>

#include "Utils.h"
#include "Injector.h"

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
    default:
        return "UNKNOWN_EVENT";
    }
    return NULL;
}

// 全局单例
class Log {
private:
    std::ofstream logFile;

    Log() {
        logFile.open("MemoryLeakDetect.log");
    }

    ~Log() {
        if (logFile.is_open())
            logFile.close();
    }

public:
    static Log& getInstance() {
        static Log instance;  // C++11 后线程安全，初始化顺序明确
        return instance;
    }
    void setLogFile(const std::string& logFileName) {
        logFile.close();
        logFile.open(logFileName);
    }
    std::ofstream& fileOnly()
    { return logFile; }

    std::ostream& showOnly()
    { return std::cout; }

    template<typename T>
    Log& operator<<(const T& val) {
        std::cout << val;
        if (logFile.is_open())
            logFile << val;
        return *this;
    }
    Log& operator<<(std::ostream& (*manip)(std::ostream&)) {
        manip(std::cout);
        if (logFile.is_open())
            manip(logFile);
        return *this;
    }

    // 禁止复制
    Log(const Log&) = delete;
    Log& operator=(const Log&) = delete;
};
#define LOG Log::getInstance()

// 栈帧信息
struct StackFrameInfo
{
    void* funcAddr;
    std::string funcName;
    std::string moduleName;
    StackFrameInfo(): funcAddr(nullptr), funcName(""){}
    StackFrameInfo(void* _Addr = nullptr, std::string _Name = "", std::string _Module = ""): funcAddr(_Addr), funcName(_Name), moduleName(_Module){}
};

// 内存块被获取的方法（用什么函数获取的堆内存）
enum class MemoryAllocMethod
{
    ByMalloc = 0,
    ByCalloc = 1, 
    ByRealloc = 2,
    ByHeapAlloc = 3,
    ByHeapReAlloc = 4
};

// 内存块信息
struct MemoryBlockInfo
{
    MemoryAllocMethod allocMethod;
    void* memoryAddr;
    union
    {
        struct
        {
            size_t size;
        } byMalloc;
        struct
        {
            size_t num_of_element;
            size_t size_of_element;
        } byCalloc;
        struct
        {
            void* old_addr;
            size_t new_size;
        } byRealloc;
        struct
        {
            HANDLE hHeap;
            DWORD dwFlag;
            SIZE_T dwBytes;
        } byHeapAlloc;
        struct
        {
            HANDLE hHeap;
            DWORD dwFlag;
            LPVOID oldAddress;
            SIZE_T dwBytes;
        } byHeapReAlloc;
    } sizeInfo;
    bool isFree = false;
    std::chrono::time_point<std::chrono::steady_clock> allocTime;
    std::vector<StackFrameInfo> stackTrace;

    MemoryBlockInfo(){}
    MemoryBlockInfo(void* addr, size_t _size)
    {
        allocTime = std::chrono::steady_clock::now();
        allocMethod = MemoryAllocMethod::ByMalloc;
        memoryAddr = addr;
        sizeInfo.byMalloc.size = _size;
    }
    MemoryBlockInfo(void* addr, size_t _NumOfElem, size_t _SizeOfElem)
    {
        allocTime = std::chrono::steady_clock::now();
        allocMethod = MemoryAllocMethod::ByCalloc;
        memoryAddr = addr;
        sizeInfo.byCalloc.num_of_element = _NumOfElem;
        sizeInfo.byCalloc.size_of_element = _SizeOfElem;
    }
    MemoryBlockInfo(void* addr, void* _OldMemory, size_t _NewSize)
    {
        allocTime = std::chrono::steady_clock::now();
        allocMethod = MemoryAllocMethod::ByRealloc;
        memoryAddr = addr;
        sizeInfo.byRealloc.old_addr = _OldMemory;
        sizeInfo.byRealloc.new_size = _NewSize;
    }
    MemoryBlockInfo(LPVOID addr, HANDLE _hHeap, DWORD _dwFlags, SIZE_T _dwBytes)
    {
        allocTime = std::chrono::steady_clock::now();
        allocMethod = MemoryAllocMethod::ByHeapAlloc;
        memoryAddr = addr;
        sizeInfo.byHeapAlloc.hHeap = _hHeap;
        sizeInfo.byHeapAlloc.dwFlag = _dwFlags;
        sizeInfo.byHeapAlloc.dwBytes = _dwBytes;
    }
    MemoryBlockInfo(LPVOID addr, HANDLE _hHeap, DWORD _dwFlags, LPVOID _lpMem, SIZE_T _dwBytes)
    {
        allocTime = std::chrono::steady_clock::now();
        allocMethod = MemoryAllocMethod::ByHeapReAlloc;
        memoryAddr = addr;
        sizeInfo.byHeapReAlloc.hHeap = _hHeap;
        sizeInfo.byHeapReAlloc.dwFlag = _dwFlags;
        sizeInfo.byHeapReAlloc.oldAddress = _lpMem;
        sizeInfo.byHeapReAlloc.dwBytes = _dwBytes;
    }

    // 获取内存块大小
    size_t size() const
    {
        switch (allocMethod)
        {
        case MemoryAllocMethod::ByMalloc:       return sizeInfo.byMalloc.size;
        case MemoryAllocMethod::ByCalloc:       return sizeInfo.byCalloc.num_of_element * sizeInfo.byCalloc.size_of_element;
        case MemoryAllocMethod::ByRealloc:      return sizeInfo.byRealloc.new_size;
        case MemoryAllocMethod::ByHeapAlloc:    return sizeInfo.byHeapAlloc.dwBytes;
        case MemoryAllocMethod::ByHeapReAlloc:  return sizeInfo.byHeapReAlloc.dwBytes;
        default:
            break;
        }
        return 0;
    }
};

class MemoryLeakDebugger;
// 堆内存记录器
class MemoryLogger
{
private:
    friend class MemoryLeakDebugger;
    HANDLE hProcess;
    std::unordered_map<void*, MemoryBlockInfo> log;
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
    std::string get_module_name(DWORD64 funcAddr)
    {
        DWORD64 moduleBaseAddr = SymGetModuleBase64(hProcess, funcAddr);
        if (moduleBaseAddr == (DWORD64)NULL) return "";

        IMAGEHLP_MODULE64 moduleInfo = {0};
        moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
        if (SymGetModuleInfo64(hProcess, moduleBaseAddr, &moduleInfo)) {
            return std::string(moduleInfo.ModuleName);
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
        for (int i = 0; i < 2048; ++i) {
            if (!StackWalk64(machineType, hProcess, hThread, &frame, &context,
                NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
                break;

            if (frame.AddrPC.Offset == 0) break;
            // 跳过RaiseException
            if (i < 2) continue;

            stackTrace.push_back(StackFrameInfo((void*)frame.AddrPC.Offset, get_func_name(frame.AddrPC.Offset), get_module_name(frame.AddrPC.Offset)));
            // LOG << "Address: " << std::hex << frame.AddrPC.Offset << std::dec << " Name: " << get_func_name(frame.AddrPC.Offset) << std::endl;
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

        log[ret_memory] = info;
        // LOG << "malloc(" << alloc_size << "), retval = " << std::hex << ret_memory << std::dec << std::endl;
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

        log[ret_memory] = info;
        // LOG << "calloc(" << num_of_elem << ", " << siz_of_elem << "), retval = " << std::hex << ret_memory << std::dec << std::endl;
        return DBG_CONTINUE;
    }
    int on_free_call_event(DEBUG_EVENT* dbgEvent)
    {
        // 参数
        void* free_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
        if (log.find(free_memory) != log.end())
        {
            log[free_memory].isFree = true;
        }
        // LOG << "free(" << std::hex << free_memory << std::dec << ")" << std::endl;
        return DBG_CONTINUE;
    }
    int on_realloc_call_event(DEBUG_EVENT* dbgEvent)
    {
        // 解析返回值和参数
        void* ret_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[0];
        void* old_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
        size_t new_size = (size_t)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[2];

        // LOG << "realloc(" << std::hex << old_memory << std::dec << ", " << new_size << ")" << std::endl;

        if (log.find(old_memory) != log.end()) {
            log[old_memory].isFree = true;
        }

        if (new_size != 0)
        {
            MemoryBlockInfo info{ret_memory, old_memory, new_size};
            info.stackTrace = get_stack_trace(dbgEvent->dwThreadId);
            log[ret_memory] = info;
        }
        
        return DBG_CONTINUE;
    }
    int on_HeapAlloc_call_event(DEBUG_EVENT* dbgEvent)
    {
        // 解析返回值和参数
        void* ret_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[0];
        HANDLE hHeap = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
        DWORD dwFlags = (DWORD32)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[2];
        SIZE_T dwBytes = (SIZE_T)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[3];

        MemoryBlockInfo info{ret_memory, hHeap, dwFlags, dwBytes};
        info.stackTrace = get_stack_trace(dbgEvent->dwThreadId);

        // LOG << "HeapAlloc(" 
        //     << std::hex << hHeap << std::dec 
        //     << ", " << std::hex << dwFlags << std::dec
        //     << ", " << dwBytes 
        //     << "), retval = " 
        //     << std::hex << ret_memory << std::dec 
        //     << std::endl;

        log[ret_memory] = info;
        return DBG_CONTINUE;
    }
    int on_HeapReAlloc_call_event(DEBUG_EVENT* dbgEvent)
    {
        // 解析返回值和参数
        void* ret_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[0];
        HANDLE hHeap = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
        DWORD dwFlags = (DWORD32)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[2];
        LPVOID oldAddr = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[3];
        SIZE_T dwBytes = (SIZE_T)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[4];

        if (log.find(oldAddr) != log.end()) {
            log[oldAddr].isFree = true;
        }

        if (dwBytes != 0)
        {
            MemoryBlockInfo info{ret_memory, hHeap, dwFlags, oldAddr, dwBytes};
            info.stackTrace = get_stack_trace(dbgEvent->dwThreadId);
            log[ret_memory] = info;
        }

        // LOG << "HeapReAlloc(" 
        //     << std::hex << hHeap << std::dec 
        //     << ", " << std::hex << dwFlags << std::dec
        //     << ", " << std::hex << oldAddr << std::dec 
        //     << ", " << dwBytes 
        //     << "), retval = " 
        //     << std::hex << ret_memory << std::dec 
        //     << std::endl;
        
        return DBG_CONTINUE;
    }
    int on_HeapFree_call_event(DEBUG_EVENT* dbgEvent)
    {
        // 解析返回值和参数
        BOOL retval = (BOOL)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[0];
        HANDLE hHeap = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
        DWORD dwFlags = (DWORD32)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[2];
        LPVOID free_memory = (void*)dbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[3];
        if (log.find(free_memory) != log.end())
        {
            log[free_memory].isFree = true;
        }

        // LOG << "HeapFree(" 
        //     << std::hex << hHeap << std::dec 
        //     << ", " << std::hex << dwFlags << std::dec
        //     << ", " << std::hex << free_memory << std::dec 
        //     << "), retval = " 
        //     << retval
        //     << std::endl;

        return DBG_CONTINUE;
    }
    // 根据ExceptionCode分发到handler
    int dispatch(DEBUG_EVENT* dbgEvent)
    {
        if (dbgEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            switch (dbgEvent->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case LEAK_DETECTOR_MALLOC_CALL_EVENT:       return on_malloc_call_event(dbgEvent);
            case LEAK_DETECTOR_CALLOC_CALL_EVENT:       return on_calloc_call_event(dbgEvent);
            case LEAK_DETECTOR_FREE_CALL_EVENT:         return on_free_call_event(dbgEvent);
            case LEAK_DETECTOR_REALLOC_CALL_EVENT:      return on_realloc_call_event(dbgEvent);
            case LEAK_DETECTOR_HEAPALLOC_CALL_EVENT:    return on_HeapAlloc_call_event(dbgEvent);
            case LEAK_DETECTOR_HEAPREALLOC_CALL_EVENT:  return on_HeapReAlloc_call_event(dbgEvent);
            case LEAK_DETECTOR_HEAPFREE_CALL_EVENT:     return on_HeapFree_call_event(dbgEvent);
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
            if (!info.isFree)
            {
                res.push_back(info);
            }
        }
        return res;
    }
};

class BasicDebugger
{
public:
    virtual BOOL dispatch(DEBUG_EVENT* pDbgEvent)
    {
        switch (pDbgEvent->dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:    return OnCreateProcessDebugExent(pDbgEvent);
        case CREATE_THREAD_DEBUG_EVENT:     return OnCreateThreadDebugExent(pDbgEvent);
        case EXCEPTION_DEBUG_EVENT:         return OnExceptionDebugEvent(pDbgEvent);
        case EXIT_PROCESS_DEBUG_EVENT:      return OnExitProcessDebugEvent(pDbgEvent);
        case EXIT_THREAD_DEBUG_EVENT:       return OnExitThreadDebugEvent(pDbgEvent);
        case LOAD_DLL_DEBUG_EVENT:          return OnLoadDllDebugEvent(pDbgEvent);
        case OUTPUT_DEBUG_STRING_EVENT:     return OnOutputDebugStringEvent(pDbgEvent);
        case UNLOAD_DLL_DEBUG_EVENT:        return OnUnLoadDllDebugEvent(pDbgEvent);
        case RIP_EVENT:                     return OnRipEvent(pDbgEvent);
        default:
            break;
        }
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
    }
    virtual BOOL OnExceptionDebugEvent(DEBUG_EVENT* pDbgEvent)
    {  
        if (pDbgEvent->u.Exception.ExceptionRecord.ExceptionCode == 0x80000003) {
            return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
        }
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
    }
    virtual BOOL OnOutputDebugStringEvent(DEBUG_EVENT* pDbgEvent)
    { return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE); }
    virtual BOOL OnCreateProcessDebugExent(DEBUG_EVENT* pDbgEvent)
    { return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE); }
    virtual BOOL OnCreateThreadDebugExent(DEBUG_EVENT* pDbgEvent)
    { return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE); }
    virtual BOOL OnExitProcessDebugEvent(DEBUG_EVENT* pDbgEvent)
    { return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE); }
    virtual BOOL OnExitThreadDebugEvent(DEBUG_EVENT* pDbgEvent)
    { return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE); }
    virtual BOOL OnLoadDllDebugEvent(DEBUG_EVENT* pDbgEvent)
    { return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE); }
    virtual BOOL OnUnLoadDllDebugEvent(DEBUG_EVENT* pDbgEvent)
    { return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE); }
    virtual BOOL OnRipEvent(DEBUG_EVENT* pDbgEvent)
    { return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE); }
};

class MemoryLeakDebugger : public BasicDebugger
{
private:
    DWORD processId;
    HANDLE hProcess;
    std::unordered_set<DWORD> allProcess;
    MemoryLogger logger;
    std::wstring hookerPath;
    std::chrono::time_point<std::chrono::steady_clock> startTime;
    void init()
    {
        startTime = std::chrono::steady_clock::now();
        if (hProcess == NULL) {
            return;
        }
        BOOL retval = SymInitializeW(hProcess, TEXT("srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols"), FALSE);
        DWORD err = GetLastError();
    }
public:
    MemoryLeakDebugger(HANDLE _hProcess, LPCWSTR _hookerPath): processId(0), hProcess(_hProcess), logger(_hProcess), hookerPath(_hookerPath)
    { init(); }
    ~MemoryLeakDebugger()
    {
        SymCleanup(hProcess);
        CloseHandle(hProcess);
    }
    bool is_debug_over()
    { return allProcess.empty(); }
    BOOL OnExceptionDebugEvent(DEBUG_EVENT* pDbgEvent)
    {
        // 优先给内存记录器处理，若已处理则继续
        if (logger.dispatch(pDbgEvent) == DBG_CONTINUE) {
            return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
        }

        // 若未处理则为其他普通异常
        LOG << "Exception code: " << std::hex << pDbgEvent->u.Exception.ExceptionRecord.ExceptionCode << std::dec << std::endl;

        // 入口断点时注入
        if (pDbgEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT) {
            PVOID pLoadLibraryW = (PVOID)GetProcAddress(GetModuleHandleW(TEXT("Kernel32.dll")), "LoadLibraryW");
            std::thread injectWork{InjectModuleToProcessByRemoteThread, pDbgEvent->dwProcessId, pLoadLibraryW, hookerPath.data()};
            injectWork.detach();
            return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
        } 
        // 栈错误时打印栈回溯
        else if (pDbgEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_STACK_OVERFLOW || 
                pDbgEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_STACK_BUFFER_OVERRUN ||
                pDbgEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_INVALID_HANDLE) {
            auto stackTrace = logger.get_stack_trace(pDbgEvent->dwThreadId);
            for (auto& frame : stackTrace) {
                LOG << frame.funcAddr << "\t" << frame.moduleName << "!" << frame.funcName << std::endl;
            }
        }
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
    }
    BOOL OnLoadDllDebugEvent(DEBUG_EVENT* pDbgEvent)
    {
        // 获取模块路径
        GetFinalPathNameByHandleW(pDbgEvent->u.LoadDll.hFile, utf16_buffer, M_BUF_SIZ, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        LOG << "Load dll: " << utf16toutf8(utf16_buffer, utf8_buffer, M_BUF_SIZ) << std::endl;

        // 加载模块符号
        DWORD64 retval = SymLoadModuleExW(hProcess, pDbgEvent->u.LoadDll.hFile, utf16_buffer, NULL, (DWORD64)pDbgEvent->u.LoadDll.lpBaseOfDll, 0, NULL, 0);
        DWORD err = GetLastError();

        CloseHandle(pDbgEvent->u.LoadDll.hFile);
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
    }
    // BOOL OnOutputDebugStringEvent(DEBUG_EVENT* pDbgEvent)
    // {
    //     char* stringBuf = (char*)calloc((pDbgEvent->u.DebugString.nDebugStringLength + 2) * 2, 1);
    //     HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pDbgEvent->dwProcessId);
    //     if (pDbgEvent->u.DebugString.fUnicode)
    //     {
    //         ReadProcessMemory(hProcess, pDbgEvent->u.DebugString.lpDebugStringData, stringBuf, pDbgEvent->u.DebugString.nDebugStringLength * 2, NULL);
    //         printf("Output debug string: %s\n", utf16toutf8((WCHAR*)stringBuf, utf8_buffer, M_BUF_SIZ));
    //     }
    //     else
    //     {
    //         ReadProcessMemory(hProcess, pDbgEvent->u.DebugString.lpDebugStringData, stringBuf, pDbgEvent->u.DebugString.nDebugStringLength, NULL);
    //         printf("Output debug string: %s\n", gbktoutf8(stringBuf, utf8_buffer, M_BUF_SIZ));
    //     }
    //     CloseHandle(hProcess);
    //     free(stringBuf);
    //     return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
    // }
    BOOL OnCreateProcessDebugExent(DEBUG_EVENT* pDbgEvent)
    {
        LOG << "Create process: " << pDbgEvent->dwProcessId << std::endl;
        allProcess.insert(pDbgEvent->dwProcessId);
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
    }
    BOOL OnExitProcessDebugEvent(DEBUG_EVENT* pDbgEvent)
    {
        LOG << "Exit process: " << pDbgEvent->dwProcessId << std::endl;
        if (allProcess.find(pDbgEvent->dwProcessId) != allProcess.end()) {
            allProcess.erase(pDbgEvent->dwProcessId);
        }
        if (is_debug_over()) {
            LOG << "All process exited, debug over." << std::endl;
            PrintLeakMemoryInfo(logger);
            return 0;
        }
        return ContinueDebugEvent(pDbgEvent->dwProcessId, pDbgEvent->dwThreadId, DBG_CONTINUE);
    }
    void PrintLeakMemoryInfo(MemoryLogger& logger)
    {
        using namespace std::chrono;

        auto leak_memories = logger.get_leak_info();
        std::sort(leak_memories.begin(),
                    leak_memories.end(),
                    [](const MemoryBlockInfo& l, const MemoryBlockInfo& r){ return l.allocTime < r.allocTime; });

        LOG << std::endl;
        LOG << "----- Leak Memory Info Start -----" << std::endl;
        LOG << std::endl;
        size_t totalLeakSize = 0, memoryBlockCnt = 0;
        for (auto& info : leak_memories)
        {
            LOG << "Possible leak " << info.size() << " bytes." << std::endl;
            totalLeakSize += info.size();
            ++memoryBlockCnt;

            LOG << "Address: " << info.memoryAddr << std::endl;

            auto offsetTime = duration_cast<milliseconds>(info.allocTime - this->startTime);
            LOG << "Alloc time: " << "+ " << offsetTime.count() << " ms" << std::endl;

            LOG << "Alloc method: ";
            switch (info.allocMethod)
            {
            case MemoryAllocMethod::ByMalloc:
                LOG << "malloc(" << info.sizeInfo.byMalloc.size << ")";
                break;
            case MemoryAllocMethod::ByCalloc:
                LOG << "calloc(" 
                    << info.sizeInfo.byCalloc.num_of_element 
                    << ", " << info.sizeInfo.byCalloc.size_of_element 
                    << ")";
                break;
            case MemoryAllocMethod::ByRealloc:
                LOG << "realloc(" 
                    << std::hex << info.sizeInfo.byRealloc.old_addr << std::dec 
                    << ", " << info.sizeInfo.byRealloc.new_size 
                    << ")";
                break;
            case MemoryAllocMethod::ByHeapAlloc:
                LOG << "HeapAlloc(" 
                    << std::hex << info.sizeInfo.byHeapAlloc.hHeap << std::dec 
                    << ", " << std::hex << info.sizeInfo.byHeapReAlloc.dwFlag << std::dec
                    << ", " << info.sizeInfo.byHeapAlloc.dwBytes 
                    << ")";
                break;
            case MemoryAllocMethod::ByHeapReAlloc:
                LOG << "HeapReAlloc(" 
                    << std::hex << info.sizeInfo.byHeapReAlloc.hHeap << std::dec 
                    << ", " << std::hex << info.sizeInfo.byHeapReAlloc.dwFlag << std::dec
                    << ", " << std::hex << info.sizeInfo.byHeapReAlloc.oldAddress << std::dec 
                    << ", " << info.sizeInfo.byHeapReAlloc.dwBytes 
                    << ")";
                break;
            default:
                break;
            }
            LOG << std::endl;

            LOG << "Stack trace: " << std::endl;
            for (auto& stackFrame : info.stackTrace)
            {
                LOG << std::hex << stackFrame.funcAddr << std::dec << "\t" << stackFrame.moduleName << "!" << stackFrame.funcName << std::endl;
            }
            LOG << std::endl;
        }
        LOG << std::endl;
        LOG << "Total alloc memory block count: " << logger.log.size() << std::endl;
        LOG << "Leak memory block count: " << memoryBlockCnt << " block(s)" << std::endl;
        LOG << "Total leak size: " << totalLeakSize << std::endl;
        LOG << std::endl;
        LOG << "----- Leak Memory Info End -----" << std::endl;
    }
};

#endif
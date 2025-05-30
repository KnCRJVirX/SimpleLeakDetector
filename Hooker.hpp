#ifndef HOOKER
#define HOOKER

#include <string>
#include <array>

#include <windows.h>

class Hooker
{
public:
    virtual bool hook() = 0;
    virtual bool unhook() = 0;
    virtual void* get_origin_func() const = 0;
};

class InlineHooker : public Hooker
{
private:
    DWORD processId;
    HANDLE hProcess;
    void* targetFuncAddr;
    void* hookFuncAddr;
    std::array<unsigned char, 13> backupData;
    bool backuped;
    bool hooked;
    bool is_init()
    { return targetFuncAddr && hookFuncAddr && hProcess; }
public:
    InlineHooker(): hProcess(nullptr), targetFuncAddr(nullptr), hookFuncAddr(), hooked(false), backuped(false){}
    InlineHooker(void* targetFunc, void* hookFunc, DWORD processId = 0): hProcess(nullptr), targetFuncAddr(targetFunc), hookFuncAddr(hookFunc), hooked(false), backuped(false)
    {
        if (processId){
            this->processId = processId;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        } else {
            hProcess = GetCurrentProcess();
        }
    };
    ~InlineHooker()
    {
        CloseHandle(hProcess);
        this->unhook();
    }
    bool hook()
    {
        if (!is_init() || hooked) return false;

        // 备份目标函数开头13字节
        if (!backuped)
        {
            ReadProcessMemory(hProcess, targetFuncAddr, backupData.data(), 13, NULL);
            backuped = true;
        }

        // 构造shellcode
        unsigned char shellcode[13] = {0};
        // mov r11, addr
        shellcode[0] = 0x49;
        shellcode[1] = 0xBB;
        // 目标地址
        memcpy(&shellcode[2], &hookFuncAddr, 8);
        // jmp r11
        shellcode[10] = 0x41;
        shellcode[11] = 0xFF;
        shellcode[12] = 0xE3;
        
        // 写入
        DWORD oldProt = 0;
        VirtualProtectEx(hProcess, targetFuncAddr, 13, PAGE_EXECUTE_READWRITE, &oldProt);
        WriteProcessMemory(hProcess, targetFuncAddr, shellcode, 13, NULL);
        VirtualProtectEx(hProcess, targetFuncAddr, 13, oldProt, nullptr);

        hooked = true;
        return true;
    }
    bool unhook()
    {
        if (!is_init() || !hooked) return false;

        // 写回备份数据
        DWORD oldProt = 0;
        VirtualProtectEx(hProcess, targetFuncAddr, 13, PAGE_EXECUTE_READWRITE, &oldProt);
        WriteProcessMemory(hProcess, targetFuncAddr, backupData.data(), 13, NULL);
        VirtualProtectEx(hProcess, targetFuncAddr, 13, oldProt, nullptr);

        hooked = false;
        return true;
    }
    void* get_origin_func() const
    { return targetFuncAddr; }
};

class IATHooker : public Hooker
{
private:
    void** IATRowPtr;
    void* originFuncAddr;
    void* hookFuncAddr;
    bool hooked;
    bool is_init()
    { return IATRowPtr && hookFuncAddr; }
public:
    IATHooker(): IATRowPtr(nullptr), originFuncAddr(nullptr), hookFuncAddr(nullptr), hooked(false){}
    IATHooker(void** IATRowPtr, void* hookFuncAddr)
    {
        this->IATRowPtr = IATRowPtr;
        this->hookFuncAddr = hookFuncAddr;
        this->hooked = false;
    }
    bool hook()
    {
        if (!is_init() || hooked) return false;

        DWORD oldProt = 0;
        VirtualProtect(IATRowPtr, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);
        originFuncAddr = *IATRowPtr;
        *IATRowPtr = hookFuncAddr;
        VirtualProtect(IATRowPtr, sizeof(void*), oldProt, NULL);

        hooked = true;
        return true;
    }
    bool unhook()
    {
        if (!is_init() || !hooked) return false;

        DWORD oldProt = 0;
        VirtualProtect(IATRowPtr, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);
        *IATRowPtr = originFuncAddr;
        VirtualProtect(IATRowPtr, sizeof(void*), oldProt, NULL);
        
        hooked = false;
        return true;
    }
    void* get_origin_func() const
    { return originFuncAddr; }
};

#endif
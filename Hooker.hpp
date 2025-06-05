#ifndef HOOKER
#define HOOKER

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <string>
#include <array>
#include <vector>
#include <memory>

#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>

typedef PVOID (WINAPI *ImageDirectoryEntryToData_t)(
    PVOID Base,
    BOOLEAN MappedAsImage,
    USHORT DirectoryEntry,
    PULONG Size
);

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
    InlineHooker(void* targetFunc, void* hookFunc, DWORD processId): hProcess(nullptr), targetFuncAddr(targetFunc), hookFuncAddr(hookFunc), hooked(false), backuped(false)
    {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
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
    HANDLE hProcess;
    std::string funcName;
    void* originFuncAddr;
    void* hookFuncAddr;
    bool hooked;
    void* enumModules(void* writeData)
    {
        HANDLE hAllModules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
        if (hAllModules == INVALID_HANDLE_VALUE) return nullptr;

        MODULEENTRY32W me = {0};
        void* retval = nullptr;
        me.dwSize = sizeof(me);
        if (Module32FirstW(hAllModules, &me)) {
            do {
                if (wcsstr(me.szModule, TEXT("ntdll.dll"))) {
                    continue;
                }
                void* ret = writeIAT(&me, writeData);
                if (retval == nullptr) {
                    retval = ret;
                }
            } while (Module32NextW(hAllModules, &me));
        }
        
        CloseHandle(hAllModules);
        return retval;
    }
    void* writeIAT(PMODULEENTRY32W moduleEntry, void* writeData)
    {
        HMODULE hModule = moduleEntry->hModule;

        HMODULE hDbghelp = LoadLibraryW(TEXT("dbghelp.dll"));
        ImageDirectoryEntryToData_t pImageDirectoryEntryToData = (ImageDirectoryEntryToData_t)GetProcAddress(hDbghelp, "ImageDirectoryEntryToData");

        void* retval = nullptr;
        ULONG tableSize = 0;
        PIMAGE_IMPORT_DESCRIPTOR pImportTable = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &tableSize));
        for (size_t i = 0; pImportTable[i].Name; i++)
        {
            // std::cout << "Import DLL: " << (char*)((BYTE*)hModule + pImportTable[i].Name) << std::endl;

            // 导入名称表INT
            PIMAGE_THUNK_DATA64 pINT = reinterpret_cast<PIMAGE_THUNK_DATA64>((BYTE*)hModule + pImportTable[i].OriginalFirstThunk);
            // 导入地址表IAT
            PIMAGE_THUNK_DATA64 pIAT = reinterpret_cast<PIMAGE_THUNK_DATA64>((BYTE*)hModule + pImportTable[i].FirstThunk);

            for (size_t j = 0; pIAT[j].u1.AddressOfData; j++) {
                if (pINT[j].u1.AddressOfData > moduleEntry->modBaseSize) {
                    continue;
                }
                
                PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((BYTE*)hModule + pINT[j].u1.AddressOfData);
                // std::cout << "  Imported Function: " << pImport->Name << std::endl;
                
                if (!strcmp(pImport->Name, this->funcName.data())) {
                    // 保存原函数地址
                    if (retval == nullptr) {
                        retval = (void*)pIAT[j].u1.Function;
                    }
                    
                    // 写入IAT
                    DWORD oldProt = 0;
                    VirtualProtect(&pIAT[j].u1.Function, sizeof(ULONGLONG), PAGE_EXECUTE_READWRITE, &oldProt);
                    pIAT[j].u1.Function = (ULONGLONG)writeData;
                    VirtualProtect(&pIAT[j].u1.Function, sizeof(ULONGLONG), oldProt, NULL);
                    break;
                }
            }
        }
        
        return retval;
    }
public:
    bool is_init()
    { return hookFuncAddr && hProcess; }
    IATHooker(): originFuncAddr(nullptr), hookFuncAddr(nullptr), hooked(false){}
    IATHooker(void* hookFuncAddr, LPCSTR targetFuncName, DWORD processId = 0)
    {
        if (processId) {
            this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        } else {
            this->hProcess = GetCurrentProcess();
        }
        
        this->funcName = std::string(targetFuncName);
        this->hookFuncAddr = hookFuncAddr;
        this->hooked = false;
    }
    ~IATHooker()
    {
        if (this->hProcess != GetCurrentProcess()) {
            CloseHandle(hProcess);
        }
    }
    bool hook()
    {
        if (!is_init() || hooked) return false;

        this->originFuncAddr = enumModules(this->hookFuncAddr);

        hooked = true;
        return true;
    }
    bool unhook()
    {
        if (!is_init() || !hooked) return false;

        enumModules(this->originFuncAddr);
        
        hooked = false;
        return true;
    }
    void set_origin_func(void* originFunc)
    {
        this->originFuncAddr = originFunc;
    }
    void* get_origin_func() const
    { return originFuncAddr; }
};

class EATHooker : public Hooker
{
private:
    HMODULE hModule;
    DWORD* EATRowPtr;
    DWORD originRowData;
    void* hookFuncAddr;
    bool is_init()
    { return hModule && EATRowPtr && originRowData && hookFuncAddr; }
public:
    EATHooker(): hModule(nullptr), EATRowPtr(nullptr), originRowData(0), hookFuncAddr(nullptr){}
    EATHooker(LPCWSTR moduleName, LPCSTR targetFuncName, void* hookFunc)
    {
        hModule = nullptr;
        EATRowPtr = nullptr;
        originRowData = 0;
        hookFuncAddr = hookFunc;

        HMODULE hDbghelp = LoadLibraryW(TEXT("dbghelp.dll"));
        ImageDirectoryEntryToData_t pImageDirectoryEntryToData = (ImageDirectoryEntryToData_t)GetProcAddress(hDbghelp, "ImageDirectoryEntryToData");

        HMODULE hModule = LoadLibraryW(moduleName);
        if (hModule) {
            this->hModule = hModule;
            ULONG tableSize = 0;
            PIMAGE_EXPORT_DIRECTORY pExportTable = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &tableSize));
            if (pExportTable) {
                // 导出符号名表
                DWORD* funcNamesTable = (DWORD*)((BYTE*)hModule + pExportTable->AddressOfNames);
                // RVA表
                DWORD* RVATable = (DWORD*)((BYTE*)hModule + pExportTable->AddressOfFunctions);
                // 索引表
                WORD* ordinalsTable = (WORD*)((BYTE*)hModule + pExportTable->AddressOfNameOrdinals);
                /* RVA表的索引是ordinals表中存储的索引 */

                for (size_t i = 0; i < pExportTable->NumberOfNames; i++) {
                    LPCSTR funcName = (LPCSTR)((BYTE*)hModule + funcNamesTable[i]);
                    if (!strcmp(funcName, targetFuncName)) {
                        DWORD ord = ordinalsTable[i];
                        EATRowPtr = &RVATable[ord];
                        originRowData = *EATRowPtr;
                        break;
                    }
                }
            }
        }
    }
    bool hook()
    {
        if (!is_init()) return false;

        DWORD oldProt = 0;
        BOOL retval = VirtualProtect(this->EATRowPtr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProt);
        *EATRowPtr = (DWORD)((BYTE*)hookFuncAddr - (BYTE*)hModule);
        VirtualProtect(this->EATRowPtr, sizeof(DWORD), oldProt, NULL);
        return true;
    }
    bool unhook()
    {
        if (!is_init()) return false;

        DWORD oldProt = 0;
        VirtualProtect(this->EATRowPtr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProt);
        *EATRowPtr = this->originRowData;
        VirtualProtect(this->EATRowPtr, sizeof(DWORD), oldProt, NULL);
        return true;
    }
    void* get_origin_func() const
    { return (void*)(hModule + originRowData); }
};

class MultiHooker : public Hooker
{
private:
    void* origin_func;
public:
    std::vector<std::unique_ptr<Hooker>> hookers;
    bool hook()
    {
        bool retval = false;
        for (auto& hooker : hookers) {
            if (hooker->hook()) {
                retval = true;
            }
        }
        return retval;
    }
    bool unhook()
    {
        bool retval = false;
        for (auto& hooker : hookers) {
            if (hooker->unhook()) {
                retval = true;
            }
        }
        return retval;
    }
    bool set_origin_func(void* origin_func)
    {
        this->origin_func = origin_func;
        return true;
    }
    void* get_origin_func() const
    {
        if (origin_func) return origin_func;
        void* ret = nullptr;
        for (auto& hooker : hookers)
        {
            if (ret = hooker->get_origin_func()) {
                return ret;
            }
        }
        return ret;
    }
    
};

#endif
#ifndef INJECTOR
#define INJECTOR

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include "Utils.h"

typedef struct InjectArgs
{
    HANDLE hProcess;
    PVOID pLoadLibraryW;
    LPCWSTR moduleName;
    #ifdef __cplusplus
    InjectArgs(HANDLE _hProcess, PVOID _pLoadLibraryW, LPCWSTR _moduleName): hProcess(_hProcess), pLoadLibraryW(_pLoadLibraryW), moduleName(_moduleName){}
    #endif
}InjectArgs;


#ifdef __cplusplus
extern "C" {
#endif

BOOL InjectThreadWork(PVOID injectArgs);
BOOL InjectModuleToProcessByRemoteThread(HANDLE hProcess, PVOID pLoadLibraryW, LPCWSTR moduleName);

#ifdef __cplusplus
}
#endif

#endif
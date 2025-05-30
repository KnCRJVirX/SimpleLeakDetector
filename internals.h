#ifndef INTERNALS
#define INTERNALS

#include <stdint.h>
#include <winternl.h>

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME   /* Size=0x18 */
{
    /* 0x0000 */ struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    /* 0x0008 */ void* ActivationContext;
    /* 0x0010 */ uint32_t Flags;
}RTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK   /* Size=0x28 */
{
    /* 0x0000 */ RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    /* 0x0008 */ LIST_ENTRY FrameListCache;
    /* 0x0018 */ uint32_t Flags;
    /* 0x001c */ uint32_t NextCookieSequenceNumber;
    /* 0x0020 */ uint32_t StackId;
    uint32_t Padding;
}ACTIVATION_CONTEXT_STACK;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT   /* Size=0x10 */
{
    /* 0x0000 */ uint32_t Flags;
    /* 0x0008 */ char* FrameName;
}TEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME   /* Size=0x18 */
{
    /* 0x0000 */ uint32_t Flags;
    uint32_t Padding;
    /* 0x0008 */ struct _TEB_ACTIVE_FRAME* Previous;
    /* 0x0010 */ TEB_ACTIVE_FRAME_CONTEXT* Context;
}TEB_ACTIVE_FRAME;

typedef struct _GDI_TEB_BATCH   /* Size=0x4e8 */
{
    /* 0x0000 */ uint32_t Offset;
    uint32_t Padding;
    /* 0x0008 */ uint64_t HDC;
    /* 0x0010 */ uint32_t Buffer[310];
}GDI_TEB_BATCH;

typedef struct _TEB_FULL   /* Size=0x1838 */
{
    /* 0x0000 */ NT_TIB NtTib;
    /* 0x0038 */ void* EnvironmentPointer;
    /* 0x0040 */ CLIENT_ID ClientId;
    /* 0x0050 */ void* ActiveRpcHandle;
    /* 0x0058 */ void* ThreadLocalStoragePointer;
    /* 0x0060 */ PEB* ProcessEnvironmentBlock;
    /* 0x0068 */ uint32_t LastErrorValue;
    /* 0x006c */ uint32_t CountOfOwnedCriticalSections;
    /* 0x0070 */ void* CsrClientThread;
    /* 0x0078 */ void* Win32ThreadInfo;
    /* 0x0080 */ uint32_t User32Reserved[26];
    /* 0x00e8 */ uint32_t UserReserved[5];
    uint32_t Padding;
    /* 0x0100 */ void* WOW32Reserved;
    /* 0x0108 */ uint32_t CurrentLocale;
    /* 0x010c */ uint32_t FpSoftwareStatusRegister;
    /* 0x0110 */ void* ReservedForDebuggerInstrumentation[16];
    /* 0x0190 */ void* SystemReserved1[30];
    /* 0x0280 */ char PlaceholderCompatibilityMode;
    /* 0x0281 */ unsigned char PlaceholderHydrationAlwaysExplicit;
    /* 0x0282 */ char PlaceholderReserved[10];
    /* 0x028c */ uint32_t ProxiedProcessId;
    /* 0x0290 */ ACTIVATION_CONTEXT_STACK _ActivationStack;
    /* 0x02b8 */ unsigned char WorkingOnBehalfTicket[8];
    /* 0x02c0 */ int32_t ExceptionCode;
    /* 0x02c4 */ unsigned char Padding0[4];
    /* 0x02c8 */ ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    /* 0x02d0 */ uint64_t InstrumentationCallbackSp;
    /* 0x02d8 */ uint64_t InstrumentationCallbackPreviousPc;
    /* 0x02e0 */ uint64_t InstrumentationCallbackPreviousSp;
    /* 0x02e8 */ uint32_t TxFsContext;
    /* 0x02ec */ unsigned char InstrumentationCallbackDisabled;
    /* 0x02ed */ unsigned char UnalignedLoadStoreExceptions;
    /* 0x02ee */ unsigned char Padding1[2];
    /* 0x02f0 */ GDI_TEB_BATCH GdiTebBatch;
    /* 0x07d8 */ CLIENT_ID RealClientId;
    /* 0x07e8 */ void* GdiCachedProcessHandle;
    /* 0x07f0 */ uint32_t GdiClientPID;
    /* 0x07f4 */ uint32_t GdiClientTID;
    /* 0x07f8 */ void* GdiThreadLocalInfo;
    /* 0x0800 */ uint64_t Win32ClientInfo[62];
    /* 0x09f0 */ void* glDispatchTable[233];
    /* 0x1138 */ uint64_t glReserved1[29];
    /* 0x1220 */ void* glReserved2;
    /* 0x1228 */ void* glSectionInfo;
    /* 0x1230 */ void* glSection;
    /* 0x1238 */ void* glTable;
    /* 0x1240 */ void* glCurrentRC;
    /* 0x1248 */ void* glContext;
    /* 0x1250 */ uint32_t LastStatusValue;
    /* 0x1254 */ unsigned char Padding2[4];
    /* 0x1258 */ UNICODE_STRING StaticUnicodeString;
    /* 0x1268 */ wchar_t StaticUnicodeBuffer[261];
    /* 0x1472 */ unsigned char Padding3[6];
    /* 0x1478 */ void* DeallocationStack;
    /* 0x1480 */ void* TlsSlots[64];
    /* 0x1680 */ LIST_ENTRY TlsLinks;
    /* 0x1690 */ void* Vdm;
    /* 0x1698 */ void* ReservedForNtRpc;
    /* 0x16a0 */ void* DbgSsReserved[2];
    /* 0x16b0 */ uint32_t HardErrorMode;
    /* 0x16b4 */ unsigned char Padding4[4];
    /* 0x16b8 */ void* Instrumentation[11];
    /* 0x1710 */ GUID ActivityId;
    /* 0x1720 */ void* SubProcessTag;
    /* 0x1728 */ void* PerflibData;
    /* 0x1730 */ void* EtwTraceData;
    /* 0x1738 */ void* WinSockData;
    /* 0x1740 */ uint32_t GdiBatchCount;
    /* 0x1744 */ PROCESSOR_NUMBER CurrentIdealProcessor;
    /* 0x1748 */ uint32_t GuaranteedStackBytes;
    /* 0x174c */ unsigned char Padding5[4];
    /* 0x1750 */ void* ReservedForPerf;
    /* 0x1758 */ void* ReservedForOle;
    /* 0x1760 */ uint32_t WaitingOnLoaderLock;
    /* 0x1764 */ unsigned char Padding6[4];
    /* 0x1768 */ void* SavedPriorityState;
    /* 0x1770 */ uint64_t ReservedForCodeCoverage;
    /* 0x1778 */ void* ThreadPoolData;
    /* 0x1780 */ void** TlsExpansionSlots;
    /* 0x1788 */ void* DeallocationBStore;
    /* 0x1790 */ void* BStoreLimit;
    /* 0x1798 */ uint32_t MuiGeneration;
    /* 0x179c */ uint32_t IsImpersonating;
    /* 0x17a0 */ void* NlsCache;
    /* 0x17a8 */ void* pShimData;
    /* 0x17b0 */ uint32_t HeapData;
    /* 0x17b4 */ unsigned char Padding7[4];
    /* 0x17b8 */ void* CurrentTransactionHandle;
    /* 0x17c0 */ TEB_ACTIVE_FRAME* ActiveFrame;
    /* 0x17c8 */ void* FlsData;
    /* 0x17d0 */ void* PreferredLanguages;
    /* 0x17d8 */ void* UserPrefLanguages;
    /* 0x17e0 */ void* MergedPrefLanguages;
    /* 0x17e8 */ uint32_t MuiImpersonation;
    /* 0x17ec */ uint16_t CrossTebFlags;
    /* 0x17ee */ uint16_t SameTebFlags;
    /* 0x17f0 */ void* TxnScopeEnterCallback;
    /* 0x17f8 */ void* TxnScopeExitCallback;
    /* 0x1800 */ void* TxnScopeContext;
    /* 0x1808 */ uint32_t LockCount;
    /* 0x180c */ int32_t WowTebOffset;
    /* 0x1810 */ void* ResourceRetValue;
    /* 0x1818 */ void* ReservedForWdf;
    /* 0x1820 */ uint64_t ReservedForCrt;
    /* 0x1828 */ GUID EffectiveContainerId;
}TEB_FULL;


#endif
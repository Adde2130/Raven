#ifndef RAVEN_WINDOWS_STRUCT
#define RAVEN_WINDOWS_STRUCT

#include <windows.h>
#include <subauth.h>
#include <stdint.h>


/* ----------------- LDR DDAG NODE ----------------- */
// LDR_DDAG_NODE REFERENCE: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_ddag_node.htm
#define LDR_DDAG_NODE RAVEN_LDR_DDAG_NODE
#define PLDR_DDAG_NODE PRAVEN_LDR_DDAG_NODE
typedef struct {
    LIST_ENTRY Modules;
    void* ServiceTagList; // Type LDR_SERVICE_TAG_RECORD, see reference

    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;

    SINGLE_LIST_ENTRY* Dependencies;
    SINGLE_LIST_ENTRY* IncomingDependencies;

    void* State; // Type LDR_DDAG_STATE, see reference

    SINGLE_LIST_ENTRY* CondenseLink;

    ULONG PreorderNumber;
} RAVEN_LDR_DDAG_NODE, *PRAVEN_LDR_DDAG_NODE;

/* -------------- LDR DATA TABLE ENTRY --------------*/
// PEB_LOADER REFERENCE: 1. http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html
//                       2. https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry/index.htm
#define LDR_DATA_TABLE_ENTRY RAVEN_LDR_DATA_TABLE_ENTRY
#define PLDR_DATA_TABLE_ENTRY PRAVEN_LDR_DATA_TABLE_ENTRY
typedef struct {
    // List to the other modules
    LIST_ENTRY InLoadOrder;
    LIST_ENTRY InMemOrder;
    LIST_ENTRY InInitOrder;

    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;

    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;

    union {
        // see reference 2
        UCHAR FlagGroup[4]; 
        ULONG Flags;
    };

    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;

    LIST_ENTRY HashLinks;

    ULONG TimeDateStamp;

    void* EntryPointActivationContext;
    void* Lock;

    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;

    void* LoadContext; // LDRP_LOAD_CONTEXT, see reference 2
    void* ParentDllBase;
    void* SwitchBackContext;
} RAVEN_LDR_DATA_TABLE_ENTRY, *PRAVEN_LDR_DATA_TABLE_ENTRY;


/* ------------------ PEB LDR DATA ------------------*/
// PEB_LOADER REFERENCE: http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html
#define PEB_LDR_DATA RAVEN_PEB_LDR_DATA
#define PPEB_LDR_DATA PRAVEN_PEB_LDR_DATA
typedef struct {
    uint32_t Length;
    uint8_t Initialized[4];
    uint32_t SsHandle;

    // Linked lists to modules loaded
    LIST_ENTRY InLoadOrder; 
    LIST_ENTRY InMemoryOrder;
    LIST_ENTRY InInitOrder;

    uint8_t EntryInProgrss;
} RAVEN_PEB_LDR_DATA, *PRAVEN_PEB_LDR_DATA;


/* ---------------------- PEB ----------------------*/
// PEB REFERENCE: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
#define PEB RAVEN_PEB
#define PPEB PRAVEN_PEB
typedef struct {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;

    UCHAR BitField; // See reference

#ifdef _WIN64
    UCHAR  Padding0 [4];
#endif

    HANDLE Mutant;
    void* ImageBaseAddress;
    PRAVEN_PEB_LDR_DATA Ldr;
    void* ProcessParameters; // RTL_USER_PROCESS_PARAMETERS struct, see reference
    void* SubSystemData;
    void* ProcessHeap;
    RTL_CRITICAL_SECTION* FastPebLock;
    void* AtlThunkSListPtr;
    void* IFEOKey;

    ULONG CrossProcessFlags; // Bitfield, see reference

#ifdef _WIN64
    UCHAR  Padding1 [4];
#endif

    union {
        void* KernelCallbackTable;
        void* UserSharedInfoPtr;
    };

    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    void* ApiSetMap;
    ULONG TlsExpansionCounter;

#ifdef _WIN64
    UCHAR Padding2[4];
#endif

    void*  TlsBitmap;
    ULONG  TlsBitmapBits[2];
    void** ReadOnlySharedMemoryBase;
    void*  SharedData;
    void*  ReadOnlyStaticServerData;
    void*  AnsiCodePageData;
    void*  OemCodePageData;
    void*  UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;

#ifdef _WIN64
    BYTE Unknown[512];
#else
    BYTE Unknown[352];
#endif

} RAVEN_PEB, *PRAVEN_PEB;


#endif
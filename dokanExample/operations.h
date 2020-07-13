#pragma once
#include "dokan/dokan.h"
#include "spdlog/spdlog.h"

#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG


NTSTATUS DOKAN_CALLBACK
MirrorCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
    ACCESS_MASK DesiredAccess, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo);



void DOKAN_CALLBACK MirrorCloseFile(LPCWSTR FileName,
    PDOKAN_FILE_INFO DokanFileInfo);


 void DOKAN_CALLBACK MirrorCleanup(LPCWSTR FileName,
    PDOKAN_FILE_INFO DokanFileInfo);



NTSTATUS DOKAN_CALLBACK MirrorReadFile(LPCWSTR FileName, LPVOID Buffer,
    DWORD BufferLength,
    LPDWORD ReadLength,
    LONGLONG Offset,
    PDOKAN_FILE_INFO DokanFileInfo);

NTSTATUS DOKAN_CALLBACK MirrorWriteFile(LPCWSTR FileName, LPCVOID Buffer,
    DWORD NumberOfBytesToWrite,
    LPDWORD NumberOfBytesWritten,
    LONGLONG Offset,
    PDOKAN_FILE_INFO DokanFileInfo);


NTSTATUS DOKAN_CALLBACK
MirrorFlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);


NTSTATUS DOKAN_CALLBACK MirrorGetFileInformation(
    LPCWSTR FileName, LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
    PDOKAN_FILE_INFO DokanFileInfo);




NTSTATUS DOKAN_CALLBACK
MirrorFindFiles(LPCWSTR FileName,
    PFillFindData FillFindData, // function pointer
    PDOKAN_FILE_INFO DokanFileInfo);
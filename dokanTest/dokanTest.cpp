// dokanTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "dokan/dokan.h"
#include "spdlog/spdlog.h"
#include "operations.h"
#include <iostream>

static WCHAR RootDirectory[DOKAN_MAX_PATH] = L"C:";
static WCHAR MountPoint[DOKAN_MAX_PATH] = L"M:\\";
static WCHAR UNCName[DOKAN_MAX_PATH] = L"";
int main(int argc, char* argv[])
{
    DOKAN_OPERATIONS dokanOperations;
    ZeroMemory(&dokanOperations, sizeof(DOKAN_OPERATIONS));
    dokanOperations.ZwCreateFile = MirrorCreateFile;
    dokanOperations.Cleanup = MirrorCleanup;
    dokanOperations.CloseFile = MirrorCloseFile;
    dokanOperations.ReadFile = MirrorReadFile;
    dokanOperations.WriteFile = MirrorWriteFile;
    dokanOperations.FlushFileBuffers = MirrorFlushFileBuffers;
    dokanOperations.GetFileInformation = MirrorGetFileInformation;
    dokanOperations.FindFiles = MirrorFindFiles;
    dokanOperations.FindFilesWithPattern = NULL;
    dokanOperations.SetFileAttributes = NULL;
    dokanOperations.SetFileTime = NULL;
    dokanOperations.DeleteFile = NULL;
    dokanOperations.DeleteDirectory = NULL;
    dokanOperations.MoveFile = NULL;
    dokanOperations.SetEndOfFile = NULL;
    dokanOperations.SetAllocationSize = NULL;
    dokanOperations.LockFile = NULL;
    dokanOperations.UnlockFile = NULL;
    dokanOperations.GetFileSecurity = NULL;
    dokanOperations.SetFileSecurity = NULL;
    dokanOperations.GetDiskFreeSpace = NULL;
    dokanOperations.GetVolumeInformation = NULL;
    dokanOperations.Unmounted = NULL;
    dokanOperations.FindStreams = NULL;
    dokanOperations.Mounted = NULL;

    DOKAN_OPTIONS dokanOptions;

    wcscpy_s(MountPoint, sizeof(MountPoint) / sizeof(WCHAR), L"T:\\");
    dokanOptions.MountPoint = MountPoint;
    dokanOptions.Version = DOKAN_VERSION;
    dokanOptions.ThreadCount = 0;
    //dokanOptions.UNCName;
    //dokanOptions.Timeout;
    //dokanOptions.AllocationUnitSize;
    dokanOptions.SectorSize;
    dokanOptions.Options = 0;

    int status = DokanMain(&dokanOptions, &dokanOperations);
    return status;
}



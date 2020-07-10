#include "dokan/dokan.h"
#include "spdlog/spdlog.h"
#include "operations.h"


BOOL DebugMode = true;
static void myprint(LPCWSTR format, ...) {
	if (DebugMode) {
		va_list args;
		int len;
		wchar_t* buffer;
		va_start(args, format);
		len = _vscwprintf(format, args) + 1;
		buffer = (wchar_t*)_malloca(len * sizeof(WCHAR));
		vswprintf_s(buffer, len, format, args);
		wprintf(buffer);
		_freea(buffer);
	}
}




#define MirrorCheckFlag(val, flag)                                             \
  if (val & flag) {                                                            \
    myprint(L"\t" L#flag L"\n");                                              \
  }

#define MirrorCheckVarEqual(val, flag)                                             \
  if (val == flag) {                                                            \
    myprint(L"\t" L#flag L"\n");                                              \
  }
/*
\foo
\foo\a
\b
*/

#define WCSMATCH(x, y) ((wcslen(x) == wcslen(y)) && wcscmp(x,y)==0)
#define IS_ROOT(var) WCSMATCH(var, L"\\")
#define IS_FOLDER_FOO(var) WCSMATCH(var, L"\\foo")
#define IS_FILE_A(var) WCSMATCH(var, L"\\foo\\a")
#define IS_FILE_B(var) WCSMATCH(var, L"\\b")



NTSTATUS DOKAN_CALLBACK
MirrorCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo) {
	NTSTATUS status = STATUS_SUCCESS;
	DWORD creationDisposition;
	DWORD fileAttributesAndFlags;
	ACCESS_MASK genericDesiredAccess;

	DokanMapKernelToUserCreateFileFlags(
		DesiredAccess, FileAttributes, CreateOptions, CreateDisposition,
		&genericDesiredAccess, &fileAttributesAndFlags, &creationDisposition);

	myprint(L"CreateFile : %s\n", FileName);



	myprint(L"\tShareMode = 0x%x\n", ShareAccess);

	MirrorCheckFlag(ShareAccess, FILE_SHARE_READ);
	MirrorCheckFlag(ShareAccess, FILE_SHARE_WRITE);
	MirrorCheckFlag(ShareAccess, FILE_SHARE_DELETE);

	myprint(L"\tDesiredAccess = 0x%x\n", DesiredAccess);

	MirrorCheckFlag(DesiredAccess, GENERIC_READ);
	MirrorCheckFlag(DesiredAccess, GENERIC_WRITE);
	MirrorCheckFlag(DesiredAccess, GENERIC_EXECUTE);

	MirrorCheckFlag(DesiredAccess, DELETE);
	MirrorCheckFlag(DesiredAccess, FILE_READ_DATA);
	MirrorCheckFlag(DesiredAccess, FILE_READ_ATTRIBUTES);
	MirrorCheckFlag(DesiredAccess, FILE_READ_EA);
	MirrorCheckFlag(DesiredAccess, READ_CONTROL);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_DATA);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_EA);
	MirrorCheckFlag(DesiredAccess, FILE_APPEND_DATA);
	MirrorCheckFlag(DesiredAccess, WRITE_DAC);
	MirrorCheckFlag(DesiredAccess, WRITE_OWNER);
	MirrorCheckFlag(DesiredAccess, SYNCHRONIZE);
	MirrorCheckFlag(DesiredAccess, FILE_EXECUTE);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_READ);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_WRITE);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_EXECUTE);

	// When filePath is a directory, needs to change the flag so that the file can
	// be opened.
	bool isFolder;
	if (IS_FOLDER_FOO(FileName) || IS_ROOT(FileName)) {
		isFolder = TRUE;
		myprint(L"file is a folder\n");
	}
	else {
		isFolder = FALSE;
		myprint(L"file is a file\n");
	}

	if (isFolder) {
		if (CreateOptions & FILE_NON_DIRECTORY_FILE) {
			myprint(L"error: file is a directory\n");
			return STATUS_FILE_IS_A_DIRECTORY;
		}
		DokanFileInfo->IsDirectory = TRUE;
	}
	else {
		if (CreateOptions & FILE_DIRECTORY_FILE) {
			myprint(L"error: file is not a directory\n");
			return STATUS_NOT_A_DIRECTORY;
		}
	}

	myprint(L"\tFlagsAndAttributes = 0x%x\n", fileAttributesAndFlags);

	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_COMPRESSED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DEVICE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DIRECTORY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_INTEGRITY_STREAM);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NO_SCRUB_DATA);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_REPARSE_POINT);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SPARSE_FILE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_VIRTUAL);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_ANONYMOUS);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IMPERSONATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_DELEGATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);



	myprint(L"creationDisposition:\n");
	if (creationDisposition == CREATE_NEW) {
		myprint(L"\tCREATE_NEW\n");
	}
	else if (creationDisposition == OPEN_ALWAYS) {
		myprint(L"\tOPEN_ALWAYS\n");
	}
	else if (creationDisposition == CREATE_ALWAYS) {
		myprint(L"\tCREATE_ALWAYS\n");
	}
	else if (creationDisposition == OPEN_EXISTING) {
		myprint(L"\tOPEN_EXISTING\n");
	}
	else if (creationDisposition == TRUNCATE_EXISTING) {
		myprint(L"\tTRUNCATE_EXISTING\n");
	}
	else {
		myprint(L"\tUNKNOWN creationDisposition!\n");
	}



	if (IS_ROOT(FileName) ||
		IS_FOLDER_FOO(FileName) ||
		IS_FILE_A(FileName) ||
		IS_FILE_B(FileName)) {
		if (creationDisposition == OPEN_ALWAYS) {
			status = ERROR_ALREADY_EXISTS;
		}
		if (creationDisposition == OPEN_EXISTING) {
			status = STATUS_SUCCESS;
		}
		if (creationDisposition == CREATE_NEW) {
			status = ERROR_FILE_EXISTS;
		}
		if (creationDisposition == CREATE_ALWAYS) {
			status = STATUS_ACCESS_DENIED;
		}
		if (creationDisposition == TRUNCATE_EXISTING) {
			status = STATUS_ACCESS_DENIED;
		}
	}
	else {
		if (creationDisposition == CREATE_NEW ||
			creationDisposition == CREATE_ALWAYS ||
			creationDisposition == TRUNCATE_EXISTING ||
			creationDisposition == OPEN_ALWAYS) {
			status = STATUS_ACCESS_DENIED;
		}
		if (creationDisposition == OPEN_EXISTING) {
			status = ERROR_FILE_NOT_FOUND;
		}
	}
	myprint(L"status code:\n");
	MirrorCheckVarEqual(status, ERROR_ALREADY_EXISTS);
	MirrorCheckVarEqual(status, STATUS_SUCCESS);
	MirrorCheckVarEqual(status, ERROR_FILE_EXISTS);
	MirrorCheckVarEqual(status, STATUS_ACCESS_DENIED);
	MirrorCheckVarEqual(status, ERROR_FILE_NOT_FOUND);

	myprint(L"end of createFile function\n");
	return status;
}



void DOKAN_CALLBACK MirrorCloseFile(LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {
	myprint(L"CloseFile: %s\n", FileName);
}


void DOKAN_CALLBACK MirrorCleanup(LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo) {
	myprint(L"Cleanup: %s\n", FileName);
}



NTSTATUS DOKAN_CALLBACK MirrorReadFile(LPCWSTR FileName, LPVOID Buffer,
	DWORD BufferLength,
	LPDWORD ReadLength,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) {
	myprint(L"ReadFile: %s\n", FileName);
	int len = 10 - (int)Offset;
	if (len < 0) {
		len = 0;
	}
	*ReadLength = (DWORD)len;
	for (int i = 0; i < len; ++i) {
		if (IS_FILE_A(FileName)) {
			((char*)Buffer)[i] = 'a';
		}
		if (IS_FILE_B(FileName)) {
			((char*)Buffer)[i] = 'b';
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK MirrorWriteFile(LPCWSTR FileName, LPCVOID Buffer,
	DWORD NumberOfBytesToWrite,
	LPDWORD NumberOfBytesWritten,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) {
	myprint(L"WriteFile: %s\n", FileName);
	return ERROR_ACCESS_DENIED;
}


NTSTATUS DOKAN_CALLBACK
MirrorFlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
	myprint(L"FlushFileBuffers: %s\n", FileName);
	return STATUS_SUCCESS;
}



NTSTATUS DOKAN_CALLBACK MirrorGetFileInformation(
	LPCWSTR FileName, LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
	PDOKAN_FILE_INFO DokanFileInfo) {
	myprint(L"GetFileInfo: %s\n", FileName);
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	BOOL opened = FALSE;

	if (IS_FOLDER_FOO(FileName) || IS_ROOT(FileName)) {
		HandleFileInformation->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY;
	}
	else {
		HandleFileInformation->dwFileAttributes = FILE_ATTRIBUTE_READONLY;
	}
	HandleFileInformation->ftCreationTime.dwLowDateTime = 100;
	HandleFileInformation->ftCreationTime.dwHighDateTime = 100;
	HandleFileInformation->ftLastAccessTime.dwLowDateTime = 102;
	HandleFileInformation->ftLastAccessTime.dwHighDateTime = 100;
	HandleFileInformation->ftLastWriteTime = HandleFileInformation->ftLastAccessTime;
	HandleFileInformation->nFileSizeHigh = 0;
	HandleFileInformation->nFileSizeLow = 10;
	return STATUS_SUCCESS;
}


static void cpyFileData(LPWIN32_FIND_DATAW findData, LPBY_HANDLE_FILE_INFORMATION info) {
	findData->nFileSizeHigh = info->nFileSizeHigh;
	findData->nFileSizeLow = info->nFileSizeLow;
	findData->dwFileAttributes = info->dwFileAttributes;
	findData->ftCreationTime = info->ftCreationTime;
	findData->ftLastAccessTime = info->ftLastAccessTime;
	findData->ftLastWriteTime = info->ftLastWriteTime;
}


NTSTATUS DOKAN_CALLBACK
MirrorFindFiles(LPCWSTR FileName,
	PFillFindData FillFindData, // function pointer
	PDOKAN_FILE_INFO DokanFileInfo) {
	myprint(L"FindFiles: %s\n", FileName);
	WIN32_FIND_DATAW findData;
	if (IS_ROOT(FileName)) {
		BY_HANDLE_FILE_INFORMATION info;
		MirrorGetFileInformation(L"\\foo", &info, DokanFileInfo);
		wcscpy_s(findData.cFileName, DOKAN_MAX_PATH, L"foo");
		cpyFileData(&findData, &info);
		FillFindData(&findData, DokanFileInfo);

		MirrorGetFileInformation(L"\\b", &info, DokanFileInfo);
		wcscpy_s(findData.cFileName, DOKAN_MAX_PATH, L"b");
		cpyFileData(&findData, &info);
		FillFindData(&findData, DokanFileInfo);
	}
	if (IS_FOLDER_FOO(FileName)) {
		BY_HANDLE_FILE_INFORMATION info;
		MirrorGetFileInformation(L"\\foo\\a", &info, DokanFileInfo);
		wcscpy_s(findData.cFileName, DOKAN_MAX_PATH, L"a");
		cpyFileData(&findData, &info);
		FillFindData(&findData, DokanFileInfo);
	}
	return STATUS_SUCCESS;
}
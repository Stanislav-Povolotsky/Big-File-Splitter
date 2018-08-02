/*
  Big-File-Splitter
  https://github.com/Stanislav-Povolotsky/Big-File-Splitter/
  This tool makes virtual drive, which mirrors user folder and splits big files to smaller chunks (100Mb by default) just on-fly.
  Tool is useful to backup large files.
  Source code is based on "Mirror" sample from Dokan.

  Copyright (C) 2018 Stanislav Povolotsky <stas.dev[at]povolotsky.info>

  Dokan original license:

  Dokan : user-mode file system library for Windows

  Copyright (C) 2015 - 2018 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
  Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>

  http://dokan-dev.github.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/*
Command line examples:

Mirror C:\Users as RootDirectory in to a drive of letter M:\ and split big files to 100Mb parts

big-file-splitter /r C:\Users /l m /z 104857600

Mount as removable drive

big-file-splitter /m /r C:\Users /l m

Mount as network drive

big-file-splitter /n /r C:\Users /l m

Mount as read only drive

big-file-splitter /w /r C:\Users /l m

Enable debug output stderr

big-file-splitter /d /s /r C:\Users /l m

Note: To unmount the drive, just press CTRL + C in the console.
*/

#include <dokan/dokan.h>
#include <dokan/fileinfo.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include <atlbase.h>
#include "helpers.h"

#define WIN10_ENABLE_LONG_PATH
#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG

BOOL g_UseStdErr;
BOOL g_DebugMode;
BOOL g_HasSeSecurityPrivilege;
BOOL g_ImpersonateCallerUser;

static void DbgPrint(LPCWSTR format, ...) {
  if (g_DebugMode) {
    const WCHAR *outputString;
    WCHAR *buffer = NULL;
    size_t length;
    va_list argp;

    va_start(argp, format);
    length = _vscwprintf(format, argp) + 1;
    buffer = (WCHAR*)_malloca(length * sizeof(WCHAR));
    if (buffer) {
      vswprintf_s(buffer, length, format, argp);
      outputString = buffer;
    } else {
      outputString = format;
    }
    if (g_UseStdErr)
      fputws(outputString, stderr);
    else
      OutputDebugStringW(outputString);
    if (buffer)
      _freea(buffer);
    va_end(argp);
    if (g_UseStdErr)
      fflush(stderr);
  }
}

static WCHAR RootDirectory[DOKAN_MAX_PATH] = L"C:";
static WCHAR MountPoint[DOKAN_MAX_PATH] = L"M:\\";
static WCHAR UNCName[DOKAN_MAX_PATH] = L"";
static CSplittingHelper g_SplittingHelper;

static void GetFilePath(PWCHAR filePath, ULONG numberOfElements,
                        LPCWSTR FileName) {
  wcsncpy_s(filePath, numberOfElements, RootDirectory, wcslen(RootDirectory));
  size_t unclen = wcslen(UNCName);
  if (unclen > 0 && _wcsnicmp(FileName, UNCName, unclen) == 0) {
    if (_wcsnicmp(FileName + unclen, L".", 1) != 0) {
      wcsncat_s(filePath, numberOfElements, FileName + unclen,
                wcslen(FileName) - unclen);
    }
  } else {
    wcsncat_s(filePath, numberOfElements, FileName, wcslen(FileName));
  }
}

static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo) {
  HANDLE handle;
  UCHAR buffer[1024];
  DWORD returnLength;
  WCHAR accountName[256];
  WCHAR domainName[256];
  DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
  DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
  PTOKEN_USER tokenUser;
  SID_NAME_USE snu;

  if (!g_DebugMode)
    return;

  handle = DokanOpenRequestorToken(DokanFileInfo);
  if (handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"  DokanOpenRequestorToken failed\n");
    return;
  }

  if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
                           &returnLength)) {
    DbgPrint(L"  GetTokenInformaiton failed: %d\n", GetLastError());
    CloseHandle(handle);
    return;
  }

  CloseHandle(handle);

  tokenUser = (PTOKEN_USER)buffer;
  if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
                        domainName, &domainLength, &snu)) {
    DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
    return;
  }

  DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
}

static BOOL AddSeSecurityNamePrivilege() {
  HANDLE token = 0;
  DbgPrint(
           L"## Attempting to add SE_SECURITY_NAME privilege to process token ##\n");
  DWORD err;
  LUID luid;
  if (!LookupPrivilegeValue(0, SE_SECURITY_NAME, &luid)) {
    err = GetLastError();
    if (err != ERROR_SUCCESS) {
      DbgPrint(L"  failed: Unable to lookup privilege value. error = %u\n",
               err);
      return FALSE;
    }
  }

  LUID_AND_ATTRIBUTES attr;
  attr.Attributes = SE_PRIVILEGE_ENABLED;
  attr.Luid = luid;

  TOKEN_PRIVILEGES priv;
  priv.PrivilegeCount = 1;
  priv.Privileges[0] = attr;

  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    err = GetLastError();
    if (err != ERROR_SUCCESS) {
      DbgPrint(L"  failed: Unable obtain process token. error = %u\n", err);
      return FALSE;
    }
  }

  TOKEN_PRIVILEGES oldPriv;
  DWORD retSize;
  AdjustTokenPrivileges(token, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), &oldPriv,
                        &retSize);
  err = GetLastError();
  if (err != ERROR_SUCCESS) {
    DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
    CloseHandle(token);
    return FALSE;
  }

  BOOL privAlreadyPresent = FALSE;
  for (unsigned int i = 0; i < oldPriv.PrivilegeCount; i++) {
    if (oldPriv.Privileges[i].Luid.HighPart == luid.HighPart &&
        oldPriv.Privileges[i].Luid.LowPart == luid.LowPart) {
      privAlreadyPresent = TRUE;
      break;
    }
  }
  DbgPrint(privAlreadyPresent ? L"  success: privilege already present\n"
             : L"  success: privilege added\n");
  if (token)
    CloseHandle(token);
  return TRUE;
}

#define BFS_CheckFlag(val, flag)                                             \
  if (val & flag) {                                                            \
    DbgPrint(L"\t" L#flag L"\n");                                              \
  }

static NTSTATUS DOKAN_CALLBACK
BFS_CreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
                 ACCESS_MASK DesiredAccess, ULONG FileAttributes,
                 ULONG ShareAccess, ULONG CreateDisposition,
                 ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  HANDLE handle;
  DWORD fileAttr;
  NTSTATUS status = STATUS_SUCCESS;
  DWORD creationDisposition;
  DWORD fileAttributesAndFlags;
  DWORD error = 0;
  SECURITY_ATTRIBUTES securityAttrib;
  ACCESS_MASK genericDesiredAccess;
  // userTokenHandle is for Impersonate Caller User Option
  HANDLE userTokenHandle = INVALID_HANDLE_VALUE;

  std::wstring sFileNameWithoutSuffix;
  ULONGLONG ullBaseOfs;
  bool bChunked = g_SplittingHelper.HaveBigFileSuffix(FileName, sFileNameWithoutSuffix, ullBaseOfs);
  if (bChunked) {
      FileName = sFileNameWithoutSuffix.c_str();
  }

  securityAttrib.nLength = sizeof(securityAttrib);
  securityAttrib.lpSecurityDescriptor =
    SecurityContext->AccessState.SecurityDescriptor;
  securityAttrib.bInheritHandle = FALSE;

  DokanMapKernelToUserCreateFileFlags(
      DesiredAccess, FileAttributes, CreateOptions, CreateDisposition,
	  &genericDesiredAccess, &fileAttributesAndFlags, &creationDisposition);

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"CreateFile : %s\n", filePath);

  PrintUserName(DokanFileInfo);

  /*
  if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
          ShareMode = FILE_SHARE_WRITE;
  else if (ShareMode == 0)
          ShareMode = FILE_SHARE_READ;
  */

  DbgPrint(L"\tShareMode = 0x%x\n", ShareAccess);

  BFS_CheckFlag(ShareAccess, FILE_SHARE_READ);
  BFS_CheckFlag(ShareAccess, FILE_SHARE_WRITE);
  BFS_CheckFlag(ShareAccess, FILE_SHARE_DELETE);

  DbgPrint(L"\tDesiredAccess = 0x%x\n", DesiredAccess);

  BFS_CheckFlag(DesiredAccess, GENERIC_READ);
  BFS_CheckFlag(DesiredAccess, GENERIC_WRITE);
  BFS_CheckFlag(DesiredAccess, GENERIC_EXECUTE);

  BFS_CheckFlag(DesiredAccess, DELETE);
  BFS_CheckFlag(DesiredAccess, FILE_READ_DATA);
  BFS_CheckFlag(DesiredAccess, FILE_READ_ATTRIBUTES);
  BFS_CheckFlag(DesiredAccess, FILE_READ_EA);
  BFS_CheckFlag(DesiredAccess, READ_CONTROL);
  BFS_CheckFlag(DesiredAccess, FILE_WRITE_DATA);
  BFS_CheckFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES);
  BFS_CheckFlag(DesiredAccess, FILE_WRITE_EA);
  BFS_CheckFlag(DesiredAccess, FILE_APPEND_DATA);
  BFS_CheckFlag(DesiredAccess, WRITE_DAC);
  BFS_CheckFlag(DesiredAccess, WRITE_OWNER);
  BFS_CheckFlag(DesiredAccess, SYNCHRONIZE);
  BFS_CheckFlag(DesiredAccess, FILE_EXECUTE);
  BFS_CheckFlag(DesiredAccess, STANDARD_RIGHTS_READ);
  BFS_CheckFlag(DesiredAccess, STANDARD_RIGHTS_WRITE);
  BFS_CheckFlag(DesiredAccess, STANDARD_RIGHTS_EXECUTE);

  // When filePath is a directory, needs to change the flag so that the file can
  // be opened.
  fileAttr = GetFileAttributes(filePath);

  if (fileAttr != INVALID_FILE_ATTRIBUTES
    && fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
      if (!(CreateOptions & FILE_NON_DIRECTORY_FILE)) {
        DokanFileInfo->IsDirectory = TRUE;
        // Needed by FindFirstFile to list files in it
        // TODO: use ReOpenFile in BFS_FindFiles to set share read temporary
        ShareAccess |= FILE_SHARE_READ;
      } else { // FILE_NON_DIRECTORY_FILE - Cannot open a dir as a file
        DbgPrint(L"\tCannot open a dir as a file\n");
        return STATUS_FILE_IS_A_DIRECTORY;
      }
  }

  DbgPrint(L"\tFlagsAndAttributes = 0x%x\n", fileAttributesAndFlags);

  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_COMPRESSED);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DEVICE);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DIRECTORY);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_INTEGRITY_STREAM);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NO_SCRUB_DATA);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_REPARSE_POINT);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SPARSE_FILE);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_VIRTUAL);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
  BFS_CheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
  BFS_CheckFlag(fileAttributesAndFlags, SECURITY_ANONYMOUS);
  BFS_CheckFlag(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
  BFS_CheckFlag(fileAttributesAndFlags, SECURITY_IMPERSONATION);
  BFS_CheckFlag(fileAttributesAndFlags, SECURITY_DELEGATION);
  BFS_CheckFlag(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
  BFS_CheckFlag(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
  BFS_CheckFlag(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);

  if (creationDisposition == CREATE_NEW) {
    DbgPrint(L"\tCREATE_NEW\n");
  } else if (creationDisposition == OPEN_ALWAYS) {
    DbgPrint(L"\tOPEN_ALWAYS\n");
  } else if (creationDisposition == CREATE_ALWAYS) {
    DbgPrint(L"\tCREATE_ALWAYS\n");
  } else if (creationDisposition == OPEN_EXISTING) {
    DbgPrint(L"\tOPEN_EXISTING\n");
  } else if (creationDisposition == TRUNCATE_EXISTING) {
    DbgPrint(L"\tTRUNCATE_EXISTING\n");
  } else {
    DbgPrint(L"\tUNKNOWN creationDisposition!\n");
  }

  if (g_ImpersonateCallerUser) {
    userTokenHandle = DokanOpenRequestorToken(DokanFileInfo);

    if (userTokenHandle == INVALID_HANDLE_VALUE) {
      DbgPrint(L"  DokanOpenRequestorToken failed\n");
      // Should we return some error?
    }
  }

  if (DokanFileInfo->IsDirectory) {
    // It is a create directory request

    if (creationDisposition == CREATE_NEW ||
        creationDisposition == OPEN_ALWAYS) {

      if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
        // if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
        if (!ImpersonateLoggedOnUser(userTokenHandle)) {
          // handle the error if failed to impersonate
          DbgPrint(L"\tImpersonateLoggedOnUser failed.\n");
        }
      }

      //We create folder
      if (!CreateDirectory(filePath, &securityAttrib)) {
        error = GetLastError();
        // Fail to create folder for OPEN_ALWAYS is not an error
        if (error != ERROR_ALREADY_EXISTS ||
            creationDisposition == CREATE_NEW) {
          DbgPrint(L"\terror code = %d\n\n", error);
          status = DokanNtStatusFromWin32(error);
        }
      }

      if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
        // Clean Up operation for impersonate
        DWORD lastError = GetLastError();
        if (status != STATUS_SUCCESS) //Keep the handle open for CreateFile
          CloseHandle(userTokenHandle);
        RevertToSelf();
        SetLastError(lastError);
      }
    }

    if (status == STATUS_SUCCESS) {

      //Check first if we're trying to open a file as a directory.
      if (fileAttr != INVALID_FILE_ATTRIBUTES &&
          !(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
          (CreateOptions & FILE_DIRECTORY_FILE)) {
        return STATUS_NOT_A_DIRECTORY;
      }

      if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
        // if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
        if (!ImpersonateLoggedOnUser(userTokenHandle)) {
          // handle the error if failed to impersonate
          DbgPrint(L"\tImpersonateLoggedOnUser failed.\n");
        }
      }

      // FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
      handle =
        CreateFile(filePath, genericDesiredAccess, ShareAccess,
                   &securityAttrib, OPEN_EXISTING,
                   fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);

      if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
        // Clean Up operation for impersonate
        DWORD lastError = GetLastError();
        CloseHandle(userTokenHandle);
        RevertToSelf();
        SetLastError(lastError);
      }

      if (handle == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);

        status = DokanNtStatusFromWin32(error);
      } else {
        DokanFileInfo->Context = 
            NEW_CONTEXT(handle, bChunked, sFileNameWithoutSuffix, ullBaseOfs); // save the file handle in Context

        // Open succeed but we need to inform the driver
        // that the dir open and not created by returning STATUS_OBJECT_NAME_COLLISION
        if (creationDisposition == OPEN_ALWAYS &&
            fileAttr != INVALID_FILE_ATTRIBUTES)
          return STATUS_OBJECT_NAME_COLLISION;
      }
    }
  } else {
    // It is a create file request

    // Cannot overwrite a hidden or system file if flag not set
    if (fileAttr != INVALID_FILE_ATTRIBUTES &&
        ((!(fileAttributesAndFlags & FILE_ATTRIBUTE_HIDDEN) &&
          (fileAttr & FILE_ATTRIBUTE_HIDDEN)) ||
         (!(fileAttributesAndFlags & FILE_ATTRIBUTE_SYSTEM) &&
          (fileAttr & FILE_ATTRIBUTE_SYSTEM))) &&
        (creationDisposition == TRUNCATE_EXISTING ||
         creationDisposition == CREATE_ALWAYS))
      return STATUS_ACCESS_DENIED;

    // Cannot delete a read only file
    if ((fileAttr != INVALID_FILE_ATTRIBUTES &&
         (fileAttr & FILE_ATTRIBUTE_READONLY) ||
         (fileAttributesAndFlags & FILE_ATTRIBUTE_READONLY)) &&
        (fileAttributesAndFlags & FILE_FLAG_DELETE_ON_CLOSE))
      return STATUS_CANNOT_DELETE;

    // Truncate should always be used with write access
    if (creationDisposition == TRUNCATE_EXISTING)
      genericDesiredAccess |= GENERIC_WRITE;

    if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
      // if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
      if (!ImpersonateLoggedOnUser(userTokenHandle)) {
        // handle the error if failed to impersonate
        DbgPrint(L"\tImpersonateLoggedOnUser failed.\n");
      }
    }

    handle = CreateFile(
                        filePath,
        genericDesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
                        ShareAccess,
                        &securityAttrib, // security attribute
                        creationDisposition,
                        fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
                        NULL);                  // template file handle

    if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
      // Clean Up operation for impersonate
      DWORD lastError = GetLastError();
      CloseHandle(userTokenHandle);
      RevertToSelf();
      SetLastError(lastError);
    }

    if (handle == INVALID_HANDLE_VALUE) {
      error = GetLastError();
      DbgPrint(L"\terror code = %d\n\n", error);

      status = DokanNtStatusFromWin32(error);
    } else {

      //Need to update FileAttributes with previous when Overwrite file
      if (fileAttr != INVALID_FILE_ATTRIBUTES &&
          creationDisposition == TRUNCATE_EXISTING) {
        SetFileAttributes(filePath, fileAttributesAndFlags | fileAttr);
      }

      DokanFileInfo->Context =
          NEW_CONTEXT(handle, bChunked, sFileNameWithoutSuffix, ullBaseOfs); // save the file handle in Context

      if (creationDisposition == OPEN_ALWAYS ||
          creationDisposition == CREATE_ALWAYS) {
        error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS) {
          DbgPrint(L"\tOpen an already existing file\n");
          // Open succeed but we need to inform the driver
          // that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
          status = STATUS_OBJECT_NAME_COLLISION;
        }
      }
    }
  }

  DbgPrint(L"\n");
  return status;
}

#pragma warning(push)
#pragma warning(disable : 4305)

static void DOKAN_CALLBACK BFS_CloseFile(LPCWSTR FileName,
                                           PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  if (DokanFileInfo->Context) {
    DbgPrint(L"CloseFile: %s\n", filePath);
    DbgPrint(L"\terror : not cleanuped file\n\n");
    auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
    if(pCtx) delete pCtx;
    DokanFileInfo->Context = 0;
  } else {
    DbgPrint(L"Close: %s\n\n", filePath);
  }
}

static void DOKAN_CALLBACK BFS_Cleanup(LPCWSTR FileName,
                                         PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  if (pCtx) {
    DbgPrint(L"Cleanup: %s\n\n", filePath);
    pCtx->Close();
  } else {
    DbgPrint(L"Cleanup: %s\n\tinvalid handle\n\n", filePath);
  }

  if (DokanFileInfo->DeleteOnClose) {
    // Should already be deleted by CloseHandle
    // if open with FILE_FLAG_DELETE_ON_CLOSE
    DbgPrint(L"\tDeleteOnClose\n");
    if (DokanFileInfo->IsDirectory) {
      DbgPrint(L"  DeleteDirectory ");
      if (!RemoveDirectory(filePath)) {
        DbgPrint(L"error code = %d\n\n", GetLastError());
      } else {
        DbgPrint(L"success\n\n");
      }
    } else {
      DbgPrint(L"  DeleteFile ");
      if (DeleteFile(filePath) == 0) {
        DbgPrint(L" error code = %d\n\n", GetLastError());
      } else {
        DbgPrint(L"success\n\n");
      }
    }
  }
}

static NTSTATUS DOKAN_CALLBACK BFS_ReadFile(LPCWSTR FileName, LPVOID Buffer,
                                              DWORD BufferLength,
                                              LPDWORD ReadLength,
                                              LONGLONG Offset,
                                              PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  HANDLE handle = pCtx ? pCtx->handle : 0;
  LONGLONG OriginalOffset = max(0, Offset);
  if (pCtx) {
      Offset = pCtx->offset + OriginalOffset;
  }
  CHandle hFile;

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"ReadFile : %s\n", filePath);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      DbgPrint(L"\tCreateFile error : %d\n\n", error);
      return DokanNtStatusFromWin32(error);
    }
    hFile.Attach(handle);
  }

  LARGE_INTEGER distanceToMove;
  distanceToMove.QuadPart = Offset;
  if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
    DWORD error = GetLastError();
    DbgPrint(L"\tseek error, offset = %I64d\n\n", Offset);
    return DokanNtStatusFromWin32(error);
  }

  if (OriginalOffset > (LONGLONG)g_SplittingHelper.MaxChunkSize) {
      *ReadLength = 0;
      return NO_ERROR;
  }

  if (((ULONGLONG)OriginalOffset + BufferLength) > g_SplittingHelper.MaxChunkSize) {
      BufferLength = (DWORD)(g_SplittingHelper.MaxChunkSize - OriginalOffset);
  }

  if (!ReadFile(handle, Buffer, BufferLength, ReadLength, NULL)) {
    DWORD error = GetLastError();
    DbgPrint(L"\tread error = %u, buffer length = %d, read length = %d\n\n",
             error, BufferLength, *ReadLength);
    return DokanNtStatusFromWin32(error);

  } else {
    DbgPrint(L"\tByte to read: %d, Byte read %d, offset %I64d\n\n", BufferLength,
             *ReadLength, Offset);
  }

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_WriteFile(LPCWSTR FileName, LPCVOID Buffer,
                                               DWORD NumberOfBytesToWrite,
                                               LPDWORD NumberOfBytesWritten,
                                               LONGLONG Offset,
                                               PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  HANDLE handle = pCtx ? pCtx->handle : 0;
  CHandle hFile;
  if (pCtx) {
      Offset = max(Offset, 0) + (LONGLONG)pCtx->offset;
  }

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"WriteFile : %s, offset %I64d, length %d\n", filePath, Offset,
           NumberOfBytesToWrite);

  // reopen the file
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      DbgPrint(L"\tCreateFile error : %d\n\n", error);
      return DokanNtStatusFromWin32(error);
    }
    hFile.Attach(handle);
  }

  UINT64 fileSize = 0;
  DWORD fileSizeLow = 0;
  DWORD fileSizeHigh = 0;
  fileSizeLow = GetFileSize(handle, &fileSizeHigh);
  if (fileSizeLow == INVALID_FILE_SIZE) {
    DWORD error = GetLastError();
    DbgPrint(L"\tcan not get a file size error = %d\n", error);
    return DokanNtStatusFromWin32(error);
  }

  fileSize = ((UINT64)fileSizeHigh << 32) | fileSizeLow;

  LARGE_INTEGER distanceToMove;
  if (DokanFileInfo->WriteToEndOfFile) {
      if (pCtx && pCtx->chunk) {
          return DokanNtStatusFromWin32(STATUS_NOT_SUPPORTED);
      }
    LARGE_INTEGER z;
    z.QuadPart = 0;
    if (!SetFilePointerEx(handle, z, NULL, FILE_END)) {
      DWORD error = GetLastError();
      DbgPrint(L"\tseek error, offset = EOF, error = %d\n", error);
      return DokanNtStatusFromWin32(error);
    }
  } else {
    // Paging IO cannot write after allocate file size.
    if (DokanFileInfo->PagingIo) {
      if ((UINT64)Offset >= fileSize) {
        *NumberOfBytesWritten = 0;
        return STATUS_SUCCESS;
      }

      if (((UINT64)Offset + NumberOfBytesToWrite) > fileSize) {
        UINT64 bytes = fileSize - Offset;
        if (bytes >> 32) {
          NumberOfBytesToWrite = (DWORD)(bytes & 0xFFFFFFFFUL);
        } else {
          NumberOfBytesToWrite = (DWORD)bytes;
        }
      }
    }

    if ((UINT64)Offset > fileSize) {
      // In the BFS_ sample helperZeroFileData is not necessary. NTFS will
      // zero a hole.
      // But if user's file system is different from NTFS( or other Windows's
      // file systems ) then  users will have to zero the hole themselves.
    }

    distanceToMove.QuadPart = Offset;
    if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
      DWORD error = GetLastError();
      DbgPrint(L"\tseek error, offset = %I64d, error = %d\n", Offset, error);
      return DokanNtStatusFromWin32(error);
    }
  }

  if (pCtx && pCtx->chunk &&
      (ULONGLONG)Offset > (pCtx->offset + g_SplittingHelper.MaxChunkSize))
  {
      return DokanNtStatusFromWin32(ERROR_END_OF_MEDIA);
  }

  if (pCtx && pCtx->chunk &&
      ((ULONGLONG)Offset + NumberOfBytesToWrite) > (pCtx->offset + g_SplittingHelper.MaxChunkSize))
  {
      NumberOfBytesToWrite = (DWORD)((pCtx->offset + g_SplittingHelper.MaxChunkSize) - Offset);
  }

  if (!WriteFile(handle, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten,
                 NULL)) {
    DWORD error = GetLastError();
    DbgPrint(L"\twrite error = %u, buffer length = %d, write length = %d\n",
             error, NumberOfBytesToWrite, *NumberOfBytesWritten);
    return DokanNtStatusFromWin32(error);

  } else {
    DbgPrint(L"\twrite %d, offset %I64d\n\n", *NumberOfBytesWritten, Offset);
  }

  // close the file when it is reopened
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
BFS_FlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  HANDLE handle = pCtx ? pCtx->handle : 0;

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"FlushFileBuffers : %s\n", filePath);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_SUCCESS;
  }

  if (FlushFileBuffers(handle)) {
    return STATUS_SUCCESS;
  } else {
    DWORD error = GetLastError();
    DbgPrint(L"\tflush error code = %d\n", error);
    return DokanNtStatusFromWin32(error);
  }
}

static NTSTATUS DOKAN_CALLBACK BFS_GetFileInformation(
  LPCWSTR FileName, LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
  PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  HANDLE handle = pCtx ? pCtx->handle : 0;
  BOOL opened = FALSE;

  GetFilePath(filePath, DOKAN_MAX_PATH, pCtx ? pCtx->FileName.c_str() : FileName);

  DbgPrint(L"GetFileInfo : %s\n", filePath);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      DbgPrint(L"\tCreateFile error : %d\n\n", error);
      return DokanNtStatusFromWin32(error);
    }
    opened = TRUE;
  }

  if (!GetFileInformationByHandle(handle, HandleFileInformation)) {
    DbgPrint(L"\terror code = %d\n", GetLastError());

    // FileName is a root directory
    // in this case, FindFirstFile can't get directory information
    if (wcslen(FileName) == 1) {
      DbgPrint(L"  root dir\n");
      HandleFileInformation->dwFileAttributes = GetFileAttributes(filePath);

    } else {
      WIN32_FIND_DATAW find;
      ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
      HANDLE findHandle = FindFirstFile(filePath, &find);
      if (findHandle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        DbgPrint(L"\tFindFirstFile error code = %d\n\n", error);
        if (opened)
          CloseHandle(handle);
        return DokanNtStatusFromWin32(error);
      }
      HandleFileInformation->dwFileAttributes = find.dwFileAttributes;
      HandleFileInformation->ftCreationTime = find.ftCreationTime;
      HandleFileInformation->ftLastAccessTime = find.ftLastAccessTime;
      HandleFileInformation->ftLastWriteTime = find.ftLastWriteTime;
      HandleFileInformation->nFileSizeLow = find.nFileSizeLow;
      HandleFileInformation->nFileSizeHigh = find.nFileSizeHigh;
      DbgPrint(L"\tFindFiles OK, file size = %d\n", find.nFileSizeLow);
      FindClose(findHandle);
    }
  } else {
    DbgPrint(L"\tGetFileInformationByHandle success, file size = %d\n",
             HandleFileInformation->nFileSizeLow);
  }

  if (1)
  {
      ULONGLONG ullSize = (ULONGLONG)HandleFileInformation->nFileSizeLow |
          ((ULONGLONG)HandleFileInformation->nFileSizeHigh << 32);
      if (pCtx && pCtx->chunk) {
          ullSize -= pCtx->offset;
      }
      ullSize = min(g_SplittingHelper.MaxChunkSize, ullSize);
      HandleFileInformation->nFileSizeHigh = (DWORD)(ullSize >> 32);
      HandleFileInformation->nFileSizeLow = (DWORD)(ullSize);
      DbgPrint(L"\tGetFileInformation file size: %I64u\n",
          ullSize);
  }


  DbgPrint(L"FILE ATTRIBUTE  = %d\n", HandleFileInformation->dwFileAttributes);

  if (opened)
    CloseHandle(handle);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
BFS_FindFiles(LPCWSTR FileName,
                PFillFindData FillFindData, // function pointer
                PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  size_t fileLen;
  HANDLE hFind;
  WIN32_FIND_DATAW findData;
  DWORD error;
  int count = 0;

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"FindFiles : %s\n", filePath);

  fileLen = wcslen(filePath);
  if (filePath[fileLen - 1] != L'\\') {
    filePath[fileLen++] = L'\\';
  }
  filePath[fileLen] = L'*';
  filePath[fileLen + 1] = L'\0';

  hFind = FindFirstFile(filePath, &findData);

  if (hFind == INVALID_HANDLE_VALUE) {
    error = GetLastError();
    DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  // Root folder does not have . and .. folder - we remove them
  BOOLEAN rootFolder = (wcscmp(FileName, L"\\") == 0);
  do {
      if (!rootFolder || (wcscmp(findData.cFileName, L".") != 0 &&
          wcscmp(findData.cFileName, L"..") != 0))
      {
          g_SplittingHelper.FileEnum_Helper(FillFindData, DokanFileInfo, findData, count);
      }
  } while (FindNextFile(hFind, &findData) != 0);

  error = GetLastError();
  FindClose(hFind);

  if (error != ERROR_NO_MORE_FILES) {
    DbgPrint(L"\tFindNextFile error. Error is %u\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  DbgPrint(L"\tFindFiles return %d entries in %s\n\n", count, filePath);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
BFS_DeleteFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  HANDLE handle = pCtx ? pCtx->handle : 0;

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
  DbgPrint(L"DeleteFile %s - %d\n", filePath, DokanFileInfo->DeleteOnClose);

  DWORD dwAttrib = GetFileAttributes(filePath);

  if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
      (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
    return STATUS_ACCESS_DENIED;

  if (handle && handle != INVALID_HANDLE_VALUE) {
    FILE_DISPOSITION_INFO fdi;
    fdi.DeleteFile = DokanFileInfo->DeleteOnClose;
    if (!SetFileInformationByHandle(handle, FileDispositionInfo, &fdi,
                                    sizeof(FILE_DISPOSITION_INFO)))
      return DokanNtStatusFromWin32(GetLastError());
  }

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
BFS_DeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  // HANDLE	handle = (HANDLE)DokanFileInfo->Context;
  HANDLE hFind;
  WIN32_FIND_DATAW findData;
  size_t fileLen;

  ZeroMemory(filePath, sizeof(filePath));
  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"DeleteDirectory %s - %d\n", filePath,
           DokanFileInfo->DeleteOnClose);

  if (!DokanFileInfo->DeleteOnClose)
    //Dokan notify that the file is requested not to be deleted.
    return STATUS_SUCCESS;

  fileLen = wcslen(filePath);
  if (filePath[fileLen - 1] != L'\\') {
    filePath[fileLen++] = L'\\';
  }
  filePath[fileLen] = L'*';
  filePath[fileLen + 1] = L'\0';

  hFind = FindFirstFile(filePath, &findData);

  if (hFind == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  do {
    if (wcscmp(findData.cFileName, L"..") != 0 &&
        wcscmp(findData.cFileName, L".") != 0) {
      FindClose(hFind);
      DbgPrint(L"\tDirectory is not empty: %s\n", findData.cFileName);
      return STATUS_DIRECTORY_NOT_EMPTY;
    }
  } while (FindNextFile(hFind, &findData) != 0);

  DWORD error = GetLastError();

  FindClose(hFind);

  if (error != ERROR_NO_MORE_FILES) {
    DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
BFS_MoveFile(LPCWSTR FileName, // existing file name
               LPCWSTR NewFileName, BOOL ReplaceIfExisting,
               PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  WCHAR newFilePath[DOKAN_MAX_PATH];
  HANDLE handle;
  DWORD bufferSize;
  BOOL result;
  size_t newFilePathLen;
  std::wstring sNewNameWithoutSuffix;

  PFILE_RENAME_INFO renameInfo = NULL;
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  if (pCtx->chunk) 
  {
      ULONGLONG nNewBaseOfs;
      if (!g_SplittingHelper.HaveBigFileSuffix(NewFileName, sNewNameWithoutSuffix, nNewBaseOfs) ||
          nNewBaseOfs != pCtx->offset) 
      {
          DbgPrint(L"\tinvalid splitted file name\n\n");
          return STATUS_OBJECT_NAME_INVALID;
      }
      NewFileName = sNewNameWithoutSuffix.c_str();
  }

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
  GetFilePath(newFilePath, DOKAN_MAX_PATH, NewFileName);

  DbgPrint(L"MoveFile %s -> %s\n\n", filePath, newFilePath);
  handle = pCtx ? pCtx->handle : 0;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  newFilePathLen = wcslen(newFilePath);

  // the PFILE_RENAME_INFO struct has space for one WCHAR for the name at
  // the end, so that
  // accounts for the null terminator

  bufferSize = (DWORD)(sizeof(FILE_RENAME_INFO) +
                       newFilePathLen * sizeof(newFilePath[0]));

  renameInfo = (PFILE_RENAME_INFO)malloc(bufferSize);
  if (!renameInfo) {
    return STATUS_BUFFER_OVERFLOW;
  }
  ZeroMemory(renameInfo, bufferSize);

  renameInfo->ReplaceIfExists =
    ReplaceIfExisting
      ? TRUE
          : FALSE; // some warning about converting BOOL to BOOLEAN
  renameInfo->RootDirectory = NULL; // hope it is never needed, shouldn't be
  renameInfo->FileNameLength =
    (DWORD)newFilePathLen *
    sizeof(newFilePath[0]); // they want length in bytes

  wcscpy_s(renameInfo->FileName, newFilePathLen + 1, newFilePath);

  result = SetFileInformationByHandle(handle, FileRenameInfo, renameInfo,
                                      bufferSize);

  free(renameInfo);

  if (result) {
      if (pCtx) {
          pCtx->FileName = NewFileName;
      }
    return STATUS_SUCCESS;
  } else {
    DWORD error = GetLastError();
    DbgPrint(L"\tMoveFile error = %u\n", error);
    return DokanNtStatusFromWin32(error);
  }
}

static NTSTATUS DOKAN_CALLBACK BFS_LockFile(LPCWSTR FileName,
                                              LONGLONG ByteOffset,
                                              LONGLONG Length,
                                              PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  HANDLE handle;
  LARGE_INTEGER offset;
  LARGE_INTEGER length;

  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  handle = pCtx ? pCtx->handle : 0;
  if (pCtx && pCtx->chunk) {
      ByteOffset = max(0, ByteOffset) + pCtx->offset;
  }

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"LockFile %s\n", filePath);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  length.QuadPart = Length;
  offset.QuadPart = ByteOffset;

  if (!LockFile(handle, offset.LowPart, offset.HighPart, length.LowPart,
                length.HighPart)) {
    DWORD error = GetLastError();
    DbgPrint(L"\terror code = %d\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  DbgPrint(L"\tsuccess\n\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_SetEndOfFile(
  LPCWSTR FileName, LONGLONG ByteOffset, PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  HANDLE handle;
  LARGE_INTEGER offset;
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  handle = pCtx ? pCtx->handle : 0;

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"SetEndOfFile %s, %I64d\n", filePath, ByteOffset);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  if (pCtx && pCtx->chunk) {
      DWORD error = ERROR_NOT_SUPPORTED;
      DbgPrint(L"\tSetEndOfFile is not supported for chunks\n");
      return DokanNtStatusFromWin32(error);
  }

  offset.QuadPart = ByteOffset;
  if (!SetFilePointerEx(handle, offset, NULL, FILE_BEGIN)) {
    DWORD error = GetLastError();
    DbgPrint(L"\tSetFilePointer error: %d, offset = %I64d\n\n", error,
             ByteOffset);
    return DokanNtStatusFromWin32(error);
  }

  if (!SetEndOfFile(handle)) {
    DWORD error = GetLastError();
    DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_SetAllocationSize(
  LPCWSTR FileName, LONGLONG AllocSize, PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  HANDLE handle;
  LARGE_INTEGER fileSize;
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  handle = pCtx ? pCtx->handle : 0;

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"SetAllocationSize %s, %I64d\n", filePath, AllocSize);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  if (GetFileSizeEx(handle, &fileSize)) {
    if (AllocSize < fileSize.QuadPart) {
      fileSize.QuadPart = AllocSize;
      if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) {
        DWORD error = GetLastError();
        DbgPrint(L"\tSetAllocationSize: SetFilePointer eror: %d, "
                 L"offset = %I64d\n\n",
                 error, AllocSize);
        return DokanNtStatusFromWin32(error);
      }
      if (!SetEndOfFile(handle)) {
        DWORD error = GetLastError();
        DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
        return DokanNtStatusFromWin32(error);
      }
    }
  } else {
    DWORD error = GetLastError();
    DbgPrint(L"\terror code = %d\n\n", error);
    return DokanNtStatusFromWin32(error);
  }
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_SetFileAttributes(
  LPCWSTR FileName, DWORD FileAttributes, PDOKAN_FILE_INFO DokanFileInfo) 
{
  WCHAR filePath[DOKAN_MAX_PATH];
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"SetFileAttributes %s 0x%x\n", filePath, FileAttributes);

  if (FileAttributes != 0) {
    if (!SetFileAttributes(filePath, FileAttributes)) {
      DWORD error = GetLastError();
      DbgPrint(L"\terror code = %d\n\n", error);
      return DokanNtStatusFromWin32(error);
    }
  } else {
    // case FileAttributes == 0 :
    // MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
    // because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
    DbgPrint(L"Set 0 to FileAttributes means MUST NOT be changed. Didn't call "
             L"SetFileAttributes function. \n");
  }

  DbgPrint(L"\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
BFS_SetFileTime(LPCWSTR FileName, CONST FILETIME *CreationTime,
                  CONST FILETIME *LastAccessTime, CONST FILETIME *LastWriteTime,
                  PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  HANDLE handle;
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  handle = pCtx ? pCtx->handle : 0;

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"SetFileTime %s\n", filePath);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) {
    DWORD error = GetLastError();
    DbgPrint(L"\terror code = %d\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  DbgPrint(L"\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
BFS_UnlockFile(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length,
                 PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  HANDLE handle;
  LARGE_INTEGER length;
  LARGE_INTEGER offset;
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();
  handle = pCtx ? pCtx->handle : 0;
  if (pCtx && pCtx->chunk) {
      ByteOffset = max(0, ByteOffset) + pCtx->offset;
  }

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"UnlockFile %s\n", filePath);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  length.QuadPart = Length;
  offset.QuadPart = ByteOffset;

  if (!UnlockFile(handle, offset.LowPart, offset.HighPart, length.LowPart,
                  length.HighPart)) {
    DWORD error = GetLastError();
    DbgPrint(L"\terror code = %d\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  DbgPrint(L"\tsuccess\n\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_GetFileSecurity(
  LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
  PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
  PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  BOOLEAN requestingSaclInfo;

  UNREFERENCED_PARAMETER(DokanFileInfo);

  std::wstring sFileNameWithoutSuffix;
  ULONGLONG ullBaseOfs;
  bool bChunked = g_SplittingHelper.HaveBigFileSuffix(FileName, sFileNameWithoutSuffix, ullBaseOfs);
  if (bChunked) {
      FileName = sFileNameWithoutSuffix.c_str();
  }

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"GetFileSecurity %s\n", filePath);

  BFS_CheckFlag(*SecurityInformation, FILE_SHARE_READ);
  BFS_CheckFlag(*SecurityInformation, OWNER_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, GROUP_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, DACL_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, SACL_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, LABEL_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, ATTRIBUTE_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, SCOPE_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation,
    PROCESS_TRUST_LABEL_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, BACKUP_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, PROTECTED_DACL_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, PROTECTED_SACL_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, UNPROTECTED_DACL_SECURITY_INFORMATION);
  BFS_CheckFlag(*SecurityInformation, UNPROTECTED_SACL_SECURITY_INFORMATION);

  requestingSaclInfo = ((*SecurityInformation & SACL_SECURITY_INFORMATION) ||
                        (*SecurityInformation & BACKUP_SECURITY_INFORMATION));

  if (!g_HasSeSecurityPrivilege) {
    *SecurityInformation &= ~SACL_SECURITY_INFORMATION;
    *SecurityInformation &= ~BACKUP_SECURITY_INFORMATION;
  }

  DbgPrint(L"  Opening new handle with READ_CONTROL access\n");
  HANDLE handle = CreateFile(
      filePath,
      READ_CONTROL | ((requestingSaclInfo && g_HasSeSecurityPrivilege)
                          ? ACCESS_SYSTEM_SECURITY
                          : 0),
      FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
      NULL, // security attribute
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
      NULL);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    int error = GetLastError();
    return DokanNtStatusFromWin32(error);
  }

  if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
                             BufferLength, LengthNeeded)) {
    int error = GetLastError();
    if (error == ERROR_INSUFFICIENT_BUFFER) {
      DbgPrint(L"  GetUserObjectSecurity error: ERROR_INSUFFICIENT_BUFFER\n");
      CloseHandle(handle);
      return STATUS_BUFFER_OVERFLOW;
    } else {
      DbgPrint(L"  GetUserObjectSecurity error: %d\n", error);
      CloseHandle(handle);
      return DokanNtStatusFromWin32(error);
    }
  }

  // Ensure the Security Descriptor Length is set
  DWORD securityDescriptorLength =
    GetSecurityDescriptorLength(SecurityDescriptor);
  DbgPrint(L"  GetUserObjectSecurity return true,  *LengthNeeded = "
           L"securityDescriptorLength \n");
  *LengthNeeded = securityDescriptorLength;

  CloseHandle(handle);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_SetFileSecurity(
  LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
  PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength,
  PDOKAN_FILE_INFO DokanFileInfo) {
  HANDLE handle;
  WCHAR filePath[DOKAN_MAX_PATH];
  auto pCtx = GET_CONTEXT(DokanFileInfo->Context);
  if (pCtx) FileName = pCtx->FileName.c_str();

  UNREFERENCED_PARAMETER(SecurityDescriptorLength);

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"SetFileSecurity %s\n", filePath);

  handle = pCtx ? pCtx->handle : 0;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
    int error = GetLastError();
    DbgPrint(L"  SetUserObjectSecurity error: %d\n", error);
    return DokanNtStatusFromWin32(error);
  }
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_GetVolumeInformation(
  LPWSTR VolumeNameBuffer, DWORD VolumeNameSize, LPDWORD VolumeSerialNumber,
  LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags,
  LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize,
  PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  WCHAR volumeRoot[4];
  DWORD fsFlags = 0;

  wcscpy_s(VolumeNameBuffer, VolumeNameSize, L"BIG-FILE-SPLITTER");

  if (VolumeSerialNumber)
    *VolumeSerialNumber = 0x19831116;
  if (MaximumComponentLength)
    *MaximumComponentLength = 255;
  if (FileSystemFlags)
    *FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
                       FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
                       FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS;

  volumeRoot[0] = RootDirectory[0];
  volumeRoot[1] = ':';
  volumeRoot[2] = '\\';
  volumeRoot[3] = '\0';

  if (GetVolumeInformation(volumeRoot, NULL, 0, NULL, MaximumComponentLength,
                           &fsFlags, FileSystemNameBuffer,
                           FileSystemNameSize)) {

    if (FileSystemFlags)
      *FileSystemFlags &= fsFlags;

    if (MaximumComponentLength) {
      DbgPrint(L"GetVolumeInformation: max component length %u\n",
               *MaximumComponentLength);
    }
    if (FileSystemNameBuffer) {
      DbgPrint(L"GetVolumeInformation: file system name %s\n",
               FileSystemNameBuffer);
    }
    if (FileSystemFlags) {
      DbgPrint(L"GetVolumeInformation: got file system flags 0x%08x,"
               L" returning 0x%08x\n",
               fsFlags, *FileSystemFlags);
    }
  } else {

    DbgPrint(L"GetVolumeInformation: unable to query underlying fs,"
             L" using defaults.  Last error = %u\n",
             GetLastError());

    // File system name could be anything up to 10 characters.
    // But Windows check few feature availability based on file system name.
    // For this, it is recommended to set NTFS or FAT here.
    wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, L"NTFS");
  }

  return STATUS_SUCCESS;
}

/*
//Uncomment for personalize disk space
static NTSTATUS DOKAN_CALLBACK BFS_DokanGetDiskFreeSpace(
    PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes,
    PULONGLONG TotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  *FreeBytesAvailable = (ULONGLONG)(512 * 1024 * 1024);
  *TotalNumberOfBytes = 9223372036854775807;
  *TotalNumberOfFreeBytes = 9223372036854775807;

  return STATUS_SUCCESS;
}
*/

/**
 * Avoid #include <winternl.h> which as conflict with FILE_INFORMATION_CLASS
 * definition.
 * This only for BFS_FindStreams. Link with ntdll.lib still required.
 *
 * Not needed if you're not using NtQueryInformationFile!
 *
 * BEGIN
 */
#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;

  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#pragma warning(pop)

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationFile(
    _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass);
/**
 * END
 */

NTSTATUS DOKAN_CALLBACK
BFS_FindStreams(LPCWSTR FileName, PFillFindStreamData FillFindStreamData,
                  PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[DOKAN_MAX_PATH];
  HANDLE hFind;
  WIN32_FIND_STREAM_DATA findData;
  DWORD error;
  int count = 0;

  GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

  DbgPrint(L"FindStreams :%s\n", filePath);

  hFind = FindFirstStreamW(filePath, FindStreamInfoStandard, &findData, 0);

  if (hFind == INVALID_HANDLE_VALUE) {
    error = GetLastError();
    DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  FillFindStreamData(&findData, DokanFileInfo);
  count++;

  while (FindNextStreamW(hFind, &findData) != 0) {
    FillFindStreamData(&findData, DokanFileInfo);
    count++;
  }

  error = GetLastError();
  FindClose(hFind);

  if (error != ERROR_HANDLE_EOF) {
    DbgPrint(L"\tFindNextStreamW error. Error is %u\n\n", error);
    return DokanNtStatusFromWin32(error);
  }

  DbgPrint(L"\tFindStreams return %d entries in %s\n\n", count, filePath);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_Mounted(PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  DbgPrint(L"Mounted\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK BFS_Unmounted(PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  DbgPrint(L"Unmounted\n");
  return STATUS_SUCCESS;
}

#pragma warning(pop)

BOOL WINAPI CtrlHandler(DWORD dwCtrlType) {
  switch (dwCtrlType) {
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
  case CTRL_CLOSE_EVENT:
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    DokanRemoveMountPoint(MountPoint);
    return TRUE;
  default:
    return FALSE;
  }
}

void ShowUsage() {
  // clang-format off
  fprintf(stderr, "big-file-splitter.exe\n"
          "  /z FileSizeLimit (ex. /z 1048576)\t\t\t Limits one file chunk size.\n"
          "  /r RootDirectory (ex. /r c:\\test)\t\t Directory source to mirror.\n"
          "  /l MountPoint (ex. /l m)\t\t\t Mount point. Can be M:\\ (drive letter) or empty NTFS folder C:\\mount\\dokan .\n"
          "  /t ThreadCount (ex. /t 5)\t\t\t Number of threads to be used internally by Dokan library.\n\t\t\t\t\t\t More threads will handle more event at the same time.\n"
          "  /d (enable debug output)\t\t\t Enable debug output to an attached debugger.\n"
          "  /s (use stderr for output)\t\t\t Enable debug output to stderr.\n"
          "  /n (use network drive)\t\t\t Show device as network device.\n"
          "  /m (use removable drive)\t\t\t Show device as removable media.\n"
          "  /w (write-protect drive)\t\t\t Read only filesystem.\n"
          "  /o (use mount manager)\t\t\t Register device to Windows mount manager.\n\t\t\t\t\t\t This enables advanced Windows features like recycle bin and more...\n"
          "  /c (mount for current session only)\t\t Device only visible for current user session.\n"
          "  /u (UNC provider name ex. \\localhost\\myfs)\t UNC name used for network volume.\n"
          "  /p (Impersonate Caller User)\t\t\t Impersonate Caller User when getting the handle in CreateFile for operations.\n\t\t\t\t\t\t This option requires administrator right to work properly.\n"
          "  /a Allocation unit size (ex. /a 512)\t\t Allocation Unit Size of the volume. This will behave on the disk file size.\n"
          "  /k Sector size (ex. /k 512)\t\t\t Sector Size of the volume. This will behave on the disk file size.\n"
          "  /f User mode Lock\t\t\t\t Enable Lockfile/Unlockfile operations. Otherwise Dokan will take care of it.\n"
          "  /i (Timeout in Milliseconds ex. /i 30000)\t Timeout until a running operation is aborted and the device is unmounted.\n\n"
          "Examples:\n"
          "\tbig-file-splitter.exe /r C:\\Users /l M:\t\t\t# mirror C:\\Users as RootDirectory into a drive of letter M:\\.\n"
          "\tbig-file-splitter.exe /r C:\\Users /l C:\\mount\\dokan\t# mirror C:\\Users as RootDirectory into NTFS folder C:\\mount\\dokan.\n"
          "\tbig-file-splitter.exe /r C:\\Users /l M: /n /u \\myfs\\myfs1\t# mirror C:\\Users as RootDirectory into a network drive M:\\. with UNC \\\\myfs\\myfs1\n\n"
          "Unmount the drive with CTRL + C in the console or alternatively via \"dokanctl /u MountPoint\".\n");
  // clang-format on
}

int __cdecl wmain(ULONG argc, PWCHAR argv[]) {
  int status;
  ULONG command;
  PDOKAN_OPERATIONS dokanOperations =
    (PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
  if (dokanOperations == NULL) {
    return EXIT_FAILURE;
  }
  PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));
  if (dokanOptions == NULL) {
    free(dokanOperations);
    return EXIT_FAILURE;
  }

  if (argc < 3) {
    ShowUsage();
    free(dokanOperations);
    free(dokanOptions);
    return EXIT_FAILURE;
  }

  g_DebugMode = FALSE;
  g_UseStdErr = FALSE;

  ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
  dokanOptions->Version = DOKAN_VERSION;
  dokanOptions->ThreadCount = 0; // use default

  for (command = 1; command < argc; command++) {
    switch (towlower(argv[command][1])) {
    case L'z':
        command++;
        g_SplittingHelper.MaxChunkSize = _wcstoui64(argv[command], NULL, 10);
        g_SplittingHelper.MaxChunkSize = max(g_SplittingHelper.MaxChunkSize, 1);
        DbgPrint(L"MaxChunkSize: %I64u\n", g_SplittingHelper.MaxChunkSize);
        break;
    case L'r':
      command++;
      wcscpy_s(RootDirectory, sizeof(RootDirectory) / sizeof(WCHAR),
               argv[command]);
      DbgPrint(L"RootDirectory: %ls\n", RootDirectory);
      break;
    case L'l':
      command++;
      wcscpy_s(MountPoint, sizeof(MountPoint) / sizeof(WCHAR), argv[command]);
      dokanOptions->MountPoint = MountPoint;
      break;
    case L't':
      command++;
      dokanOptions->ThreadCount = (USHORT)_wtoi(argv[command]);
      break;
    case L'd':
      g_DebugMode = TRUE;
      break;
    case L's':
      g_UseStdErr = TRUE;
      break;
    case L'n':
      dokanOptions->Options |= DOKAN_OPTION_NETWORK;
      break;
    case L'm':
      dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
      break;
    case L'w':
      dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;
      break;
    case L'o':
      dokanOptions->Options |= DOKAN_OPTION_MOUNT_MANAGER;
      break;
    case L'c':
      dokanOptions->Options |= DOKAN_OPTION_CURRENT_SESSION;
      break;
    case L'f':
      dokanOptions->Options |= DOKAN_OPTION_FILELOCK_USER_MODE;
      break;
    case L'u':
      command++;
      wcscpy_s(UNCName, sizeof(UNCName) / sizeof(WCHAR), argv[command]);
      dokanOptions->UNCName = UNCName;
      DbgPrint(L"UNC Name: %ls\n", UNCName);
      break;
    case L'p':
      g_ImpersonateCallerUser = TRUE;
      break;
    case L'i':
      command++;
      dokanOptions->Timeout = (ULONG)_wtol(argv[command]);
      break;
    case L'a':
      command++;
      dokanOptions->AllocationUnitSize = (ULONG)_wtol(argv[command]);
      break;
    case L'k':
      command++;
      dokanOptions->SectorSize = (ULONG)_wtol(argv[command]);
      break;
    default:
      fwprintf(stderr, L"unknown command: %s\n", argv[command]);
      free(dokanOperations);
      free(dokanOptions);
      return EXIT_FAILURE;
    }
  }

  if (wcscmp(UNCName, L"") != 0 &&
      !(dokanOptions->Options & DOKAN_OPTION_NETWORK)) {
    fwprintf(
             stderr,
             L"  Warning: UNC provider name should be set on network drive only.\n");
  }

  if (dokanOptions->Options & DOKAN_OPTION_NETWORK &&
      dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) {
    fwprintf(stderr, L"Mount manager cannot be used on network drive.\n");
    free(dokanOperations);
    free(dokanOptions);
    return EXIT_FAILURE;
  }

  if (!(dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) &&
      wcscmp(MountPoint, L"") == 0) {
    fwprintf(stderr, L"Mount Point required.\n");
    free(dokanOperations);
    free(dokanOptions);
    return EXIT_FAILURE;
  }

  if ((dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) &&
      (dokanOptions->Options & DOKAN_OPTION_CURRENT_SESSION)) {
    fwprintf(stderr,
             L"Mount Manager always mount the drive for all user sessions.\n");
    free(dokanOperations);
    free(dokanOptions);
    return EXIT_FAILURE;
  }

  if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
    fwprintf(stderr, L"Control Handler is not set.\n");
  }

  // Add security name privilege. Required here to handle GetFileSecurity
  // properly.
  g_HasSeSecurityPrivilege = AddSeSecurityNamePrivilege();
  if (!g_HasSeSecurityPrivilege) {
    fwprintf(stderr, L"Failed to add security privilege to process\n");
    fwprintf(stderr,
             L"\t=> GetFileSecurity/SetFileSecurity may not work properly\n");
    fwprintf(stderr, L"\t=> Please restart big-file-splitter with administrator "
             L"rights to fix it\n");
  }

  if (g_ImpersonateCallerUser && !g_HasSeSecurityPrivilege) {
    fwprintf(stderr, L"Impersonate Caller User requires administrator right to "
             L"work properly\n");
    fwprintf(stderr, L"\t=> Other users may not use the drive properly\n");
    fwprintf(stderr, L"\t=> Please restart big-file-splitter sample with administrator "
             L"rights to fix it\n");
  }

  if (g_DebugMode) {
    dokanOptions->Options |= DOKAN_OPTION_DEBUG;
  }
  if (g_UseStdErr) {
    dokanOptions->Options |= DOKAN_OPTION_STDERR;
  }

  dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;

  ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
  dokanOperations->ZwCreateFile = BFS_CreateFile;
  dokanOperations->Cleanup = BFS_Cleanup;
  dokanOperations->CloseFile = BFS_CloseFile;
  dokanOperations->ReadFile = BFS_ReadFile;
  dokanOperations->WriteFile = BFS_WriteFile;
  dokanOperations->FlushFileBuffers = BFS_FlushFileBuffers;
  dokanOperations->GetFileInformation = BFS_GetFileInformation;
  dokanOperations->FindFiles = BFS_FindFiles;
  dokanOperations->FindFilesWithPattern = NULL;
  dokanOperations->SetFileAttributes = BFS_SetFileAttributes;
  dokanOperations->SetFileTime = BFS_SetFileTime;
  dokanOperations->DeleteFile = BFS_DeleteFile;
  dokanOperations->DeleteDirectory = BFS_DeleteDirectory;
  dokanOperations->MoveFile = BFS_MoveFile;
  dokanOperations->SetEndOfFile = BFS_SetEndOfFile;
  dokanOperations->SetAllocationSize = BFS_SetAllocationSize;
  dokanOperations->LockFile = BFS_LockFile;
  dokanOperations->UnlockFile = BFS_UnlockFile;
  dokanOperations->GetFileSecurity = BFS_GetFileSecurity;
  dokanOperations->SetFileSecurity = BFS_SetFileSecurity;
  dokanOperations->GetDiskFreeSpace = NULL; // BFS_DokanGetDiskFreeSpace;
  dokanOperations->GetVolumeInformation = BFS_GetVolumeInformation;
  dokanOperations->Unmounted = BFS_Unmounted;
  dokanOperations->FindStreams = BFS_FindStreams;
  dokanOperations->Mounted = BFS_Mounted;

  status = DokanMain(dokanOptions, dokanOperations);
  switch (status) {
  case DOKAN_SUCCESS:
    fprintf(stderr, "Success\n");
    break;
  case DOKAN_ERROR:
    fprintf(stderr, "Error\n");
    break;
  case DOKAN_DRIVE_LETTER_ERROR:
    fprintf(stderr, "Bad Drive letter\n");
    break;
  case DOKAN_DRIVER_INSTALL_ERROR:
    fprintf(stderr, "Can't install driver\n");
    break;
  case DOKAN_START_ERROR:
    fprintf(stderr, "Driver something wrong\n");
    break;
  case DOKAN_MOUNT_ERROR:
    fprintf(stderr, "Can't assign a drive letter\n");
    break;
  case DOKAN_MOUNT_POINT_ERROR:
    fprintf(stderr, "Mount point error\n");
    break;
  case DOKAN_VERSION_ERROR:
    fprintf(stderr, "Version error\n");
    break;
  default:
    fprintf(stderr, "Unknown error: %d\n", status);
    break;
  }

  free(dokanOptions);
  free(dokanOperations);
  return EXIT_SUCCESS;
}

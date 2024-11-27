#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "beacon.h"

#define _NO_NTDLL_CRT_
#include "native.h"

#define INITIAL_ARRAY_SIZE 100
#define PATH_MAX_LENGTH 512

#define CAPI(func_name) __declspec(dllimport) __typeof(func_name) func_name;
CAPI(calloc)
CAPI(free)
CAPI(NtQueryInformationProcess)
CAPI(NtQuerySystemInformation)
CAPI(K32GetModuleFileNameExA)
CAPI(memset)
CAPI(realloc)
CAPI(strcmp)
CAPI(strcpy)
CAPI(strlen)

typedef struct {
    DWORD* pids; // Dynamic array of strings
    char** names; // Dynamic array of strings
    size_t count; // Number of stored paths
    size_t capacity; // Maximum capacity of the array
} servicesArray;

void initializeServiceArray(servicesArray* array, size_t initialSize) {
    array->pids = (DWORD*)calloc(initialSize * sizeof(DWORD), sizeof(char));
    array->names = (char**)calloc(initialSize * sizeof(char*), sizeof(char));
    array->count = 0;
    array->capacity = initialSize;
}

void addServiceToArray(servicesArray* array, DWORD pid, const char* name) {
    if (array->count == array->capacity) {
        array->capacity *= 2;
        array->pids = (DWORD*)realloc(array->pids, array->capacity * sizeof(DWORD));
        array->names = (char**)realloc(array->names, array->capacity * sizeof(char*));
    }
    array->pids[array->count] = pid;
    array->names[array->count] = (char*)calloc(strlen(name) + 1, sizeof(char));
    strcpy(array->names[array->count], name);

    array->count++;
}

void freeServiceArray(servicesArray* array) {
    for (size_t i = 0; i < array->count; i++)
        free(array->names[i]);

    free(array->pids);
}

// Declare globals
servicesArray serviceArray;
char* lpUnprotected = "Unprotected";
char* lpPPL = "PsProtected-Light";
char* lpPP = "PsProtected";

char* GetUserFromProcess(HANDLE hProcess)
{
    char* username = NULL;
    HANDLE hToken;
    
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) 
    {
        DWORD size = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &size);

        TOKEN_USER* tokenUser = (TOKEN_USER*)calloc(size, sizeof(char));
        if (tokenUser)
        {
            if (GetTokenInformation(hToken, TokenUser, tokenUser, size, &size))
            {

                CHAR name[256] = {0};
                CHAR domain[256] = {0};
                DWORD nameSize = sizeof(name) / sizeof(CHAR);
                DWORD domainSize = sizeof(domain) / sizeof(CHAR);
                SID_NAME_USE sidType;

                // Resolve SID to username and domain
                if (LookupAccountSid(NULL, tokenUser->User.Sid, name, &nameSize, domain, &domainSize, &sidType))
                {
                    DWORD dwBufLen = nameSize + domainSize + 2;
                    username = calloc(dwBufLen, sizeof(char));
                    if (username)
                        sprintf_s(username, dwBufLen, "%s\\%s", domain, name);
                } 
            }

            free(tokenUser);
        }

        CloseHandle(hToken);
    }

    return username;
}

void enumerateServices(servicesArray* serviceArray) {
    SC_HANDLE hSCManager;
    LPBYTE lpBuffer = NULL;
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;
    DWORD dwBufferSize = 0;

    // Open Service Control Manager
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManager failed. Error: %lu\n", GetLastError());
        return;
    }

    // First, determine the required buffer size
    EnumServicesStatusExA(
        hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded,
        &dwServicesReturned, &dwResumeHandle, NULL);

    if (GetLastError() != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_OUTPUT, "EnumServicesStatusEx failed. Error: %lu\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return;
    }

    // Allocate the buffer
    dwBufferSize = dwBytesNeeded;
    lpBuffer = (LPBYTE)calloc(dwBufferSize, sizeof(char));
    if (!lpBuffer) {
        BeaconPrintf(CALLBACK_OUTPUT, "Memory allocation failed.\n");
        CloseServiceHandle(hSCManager);
        return;
    }

    // Enumerate services
    if (!EnumServicesStatusExA(
            hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, lpBuffer, dwBufferSize,
            &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "EnumServicesStatusEx failed. Error: %lu\n", GetLastError());
        free(lpBuffer);
        CloseServiceHandle(hSCManager);
        return;
    }

    LPENUM_SERVICE_STATUS_PROCESSA pServices = (LPENUM_SERVICE_STATUS_PROCESSA)lpBuffer;

    for (DWORD i = 0; i < dwServicesReturned; i++)
        addServiceToArray(serviceArray, pServices[i].ServiceStatusProcess.dwProcessId, pServices[i].lpServiceName);

    free(lpBuffer);
    CloseServiceHandle(hSCManager);
}

void go (char* args, int length)
{
    // Set up array for data
    initializeServiceArray(&serviceArray, INITIAL_ARRAY_SIZE);

    // Enumerate services and store paths
    enumerateServices(&serviceArray);

    // Set up output buffer
    formatp buffer;
    BeaconFormatAlloc(&buffer, 40960);

    // Retrieve length of buffer required for all processes
    ULONG retLen = 0;
    NtQuerySystemInformation(SystemProcessInformation, 0, 0, &retLen);
    if (retLen == 0) 
    { 
        BeaconFormatPrintf(&buffer, "[-] NtQuerySystemInformation failed.\n");
        goto print;
    }

    // Prepate suitable buffer:
    const size_t bufLen = retLen;
    void *infoBuf = calloc(bufLen, sizeof(char));
    if (!infoBuf)
    {
        BeaconFormatPrintf(&buffer, "[-] calloc failed.\n");
        goto print;
    }

    // Add format columns
    BeaconFormatPrintf(&buffer, "%-7s %-30s %-20s %-30s %-10s %-30s %-100s\n", "PID", "Process Name", "Process Protection", "User", "Session", "Service", "Process Path");
    BeaconFormatPrintf(&buffer, "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    // Enumerate processes:
    SYSTEM_PROCESS_INFORMATION *sys_info = (SYSTEM_PROCESS_INFORMATION *)infoBuf;
    if (NtQuerySystemInformation(SystemProcessInformation, sys_info, bufLen, &retLen) == STATUS_SUCCESS)
    {
        while (TRUE) 
        {
            PS_PROTECTION protection = {0, };

            // Grab PID
            DWORD pid = (DWORD)sys_info->UniqueProcessId;
            
            // Skip system idle process
            if (pid < 3000)
            {
                sys_info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)sys_info + sys_info->NextEntryOffset);
                continue;
            }

            // Open Handle to process
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc)
            {
                // Grab username from process
                char* procuser = GetUserFromProcess(hProc);

                // Query process path
                CHAR filepath[MAX_PATH] = {0};
                char* servicename = NULL;
                if (GetModuleFileNameExA(hProc, NULL, (LPSTR)&filepath, MAX_PATH) == 0)
                {
                    memset(&filepath, 0, MAX_PATH);
                    sprintf_s((char*)&filepath, MAX_PATH, "%s", "[-] Error resolving image path");
                }
                else
                {
                    // Iterate over each service path and check for a match
                    for (size_t i = 0; i < serviceArray.count; i++)
                    {
                        if (pid == serviceArray.pids[i])
                        {
                            servicename = serviceArray.names[i];
                            break;
                        }
                    }                    
                }

                // Query protection level
                NTSTATUS ntstatus = STATUS_SUCCESS;
                ntstatus = NtQueryInformationProcess(hProc, ProcessProtectionInformation, &protection, sizeof(protection), NULL);
                if (NT_SUCCESS(ntstatus))
                {
                    char* prot = NULL;
                    if (protection.Type == PsProtectedTypeNone)
                        prot = lpUnprotected;
                    else if (protection.Type == PsProtectedTypeProtectedLight)
                        prot = lpPPL;
                    else if (protection.Type == PsProtectedTypeProtected)
                        prot = lpPP;
                
                    BeaconFormatPrintf(&buffer, "%-7d %-30ls %-20s %-30s %-10d %-30s %-100s\n", pid, sys_info->ImageName.Buffer, prot, procuser == NULL ? "?" : procuser, sys_info->SessionId, servicename == NULL ? "N/A" : servicename, filepath);
                
                }
                else
                    BeaconFormatPrintf(&buffer, "%-7d %-30ls %-20s %-30s %-10d %-30s %-100s\n", pid, sys_info->ImageName.Buffer, "[-] NtQIP", procuser == NULL ? "?" : procuser, sys_info->SessionId, servicename == NULL ? "N/A" : servicename, filepath);

                // Cleanup
                CloseHandle(hProc);
                memset(&protection, 0, sizeof(protection));                
                if (procuser != NULL)
                {
                    memset(procuser, 0, strlen(procuser));
                    free(procuser);
                }
            }
            else
                BeaconFormatPrintf(&buffer, "%-7d %-30ls %-20s %-30s %-10d %-30s %-100s\n", pid, sys_info->ImageName.Buffer, "[-] OpenProcess", "N/A", sys_info->SessionId, "N/A", "N/A");
                
            // Break if we are out of processes
            if (!sys_info->NextEntryOffset)
                break;

            // Iterate to next process info struct
            sys_info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)sys_info + sys_info->NextEntryOffset);
        }
    }
    else
        BeaconFormatPrintf(&buffer, "[-] NtQuerySystemInformation failed.\n");
    
    // Cleanup
    memset(infoBuf, 0, bufLen);
    free(infoBuf);

print:

    // More cleanup
    freeServiceArray(&serviceArray);

    // Return output
    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));
    BeaconFormatFree(&buffer);
}
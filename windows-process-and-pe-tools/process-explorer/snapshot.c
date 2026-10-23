
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

/*
 * Process Explorer
 *
 * Features:
 *   1. List running processes
 *   2. Find a process by exact executable name
 *   3. Enumerate loaded modules (EXE/DLLs) of a process
 *
 * Build with MinGW GCC on Windows.
 *
 * Note:
 *   PROCESSENTRY32 and MODULEENTRY32 are generic Windows types.
 *   Their character format depends on the UNICODE configuration.
 *   This source uses the generic Tool Help APIs and narrow strings.
 */

typedef enum {
    PROCESS_FOUND,
    PROCESS_NOT_FOUND,
    SNAPSHOT_FAILED,
    ENUMERATION_FAILED,
    INVALID_ARGUMENT
} ProcessStatus;


/* Remove the trailing newline added by fgets(). */
static void RemoveNewline(char *text)
{
    if (text == NULL) {
        return;
    }

    text[strcspn(text, "\r\n")] = '\0';
}


/* Print a Windows API error code and its operation. */
static void PrintWindowsError(const char *operation, DWORD errorCode)
{
    fprintf(stderr, "%s failed. Windows error code: %lu\n",
            operation, (unsigned long)errorCode);
}


/*
 * Find a process by its exact executable name.
 *
 * Inputs:
 *   processName - name such as "notepad.exe"
 *   result      - receives the matching PROCESSENTRY32 structure
 *   errorCode   - receives the Windows error code on API failure
 *
 * Returns:
 *   PROCESS_FOUND       if a match exists
 *   PROCESS_NOT_FOUND   if enumeration completes without a match
 *   SNAPSHOT_FAILED     if the process snapshot cannot be created
 *   ENUMERATION_FAILED  if process enumeration fails
 *   INVALID_ARGUMENT    if an input is invalid
 */
static ProcessStatus GetProcessByName(
    const char *processName,
    PROCESSENTRY32 *result,
    DWORD *errorCode)
{
    HANDLE snapshot;
    PROCESSENTRY32 current;
    DWORD lastError;

    if (processName == NULL || result == NULL || errorCode == NULL ||
        processName[0] == '\0') {
        return INVALID_ARGUMENT;
    }

    *errorCode = ERROR_SUCCESS;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        *errorCode = GetLastError();
        return SNAPSHOT_FAILED;
    }

    memset(&current, 0, sizeof(current));
    current.dwSize = sizeof(current);

    if (!Process32First(snapshot, &current)) {
        lastError = GetLastError();
        CloseHandle(snapshot);

        *errorCode = lastError;
        return ENUMERATION_FAILED;
    }

    do {
        /* Compare executable names without case sensitivity. */
        if (_stricmp(current.szExeFile, processName) == 0) {
            *result = current;
            CloseHandle(snapshot);
            return PROCESS_FOUND;
        }

        SetLastError(ERROR_SUCCESS);

    } while (Process32Next(snapshot, &current));

    lastError = GetLastError();
    CloseHandle(snapshot);

    /* ERROR_NO_MORE_FILES indicates normal completion. */
    if (lastError != ERROR_NO_MORE_FILES &&
        lastError != ERROR_SUCCESS) {
        *errorCode = lastError;
        return ENUMERATION_FAILED;
    }

    return PROCESS_NOT_FOUND;
}


/*
 * List running processes.
 *
 * Each entry contains the process ID (PID) and executable name.
 * The snapshot is a point-in-time view, not a continuously updated list.
 */
static void ListProcesses(void)
{
    HANDLE snapshot;
    PROCESSENTRY32 entry;
    DWORD lastError;
    unsigned long count = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        PrintWindowsError("CreateToolhelp32Snapshot",
                          GetLastError());
        return;
    }

    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);

    if (!Process32First(snapshot, &entry)) {
        lastError = GetLastError();
        CloseHandle(snapshot);
        PrintWindowsError("Process32First", lastError);
        return;
    }

    printf("\n%-10s %s\n", "PID", "PROCESS NAME");
    printf("----------------------------------------\n");

    do {
        printf("%-10lu %s\n",
               (unsigned long)entry.th32ProcessID,
               entry.szExeFile);

        count++;
        SetLastError(ERROR_SUCCESS);

    } while (Process32Next(snapshot, &entry));

    lastError = GetLastError();
    CloseHandle(snapshot);

    printf("\nTotal processes listed: %lu\n", count);

    if (lastError != ERROR_NO_MORE_FILES &&
        lastError != ERROR_SUCCESS) {
        PrintWindowsError("Process32Next", lastError);
    }
}


/*
 * Display details for a process identified by its executable name.
 *
 * OpenProcess obtains a handle with limited query permissions.
 * QueryFullProcessImageNameA retrieves the executable's full path.
 */
static void FindProcess(void)
{
    char processName[MAX_PATH];
    PROCESSENTRY32 entry;
    ProcessStatus status;
    DWORD errorCode = ERROR_SUCCESS;

    printf("Enter executable name (e.g. notepad.exe): ");

    if (fgets(processName, sizeof(processName), stdin) == NULL) {
        printf("Unable to read process name.\n");
        return;
    }

    RemoveNewline(processName);

    if (processName[0] == '\0') {
        printf("Process name cannot be empty.\n");
        return;
    }

    status = GetProcessByName(processName, &entry, &errorCode);

    if (status != PROCESS_FOUND) {
        switch (status) {
        case PROCESS_NOT_FOUND:
            printf("Process '%s' was not found.\n", processName);
            break;

        case SNAPSHOT_FAILED:
            PrintWindowsError("CreateToolhelp32Snapshot", errorCode);
            break;

        case ENUMERATION_FAILED:
            PrintWindowsError("Process enumeration", errorCode);
            break;

        case INVALID_ARGUMENT:
            printf("Invalid input.\n");
            break;

        default:
            printf("Unexpected process lookup error.\n");
            break;
        }

        return;
    }

    printf("\nProcess found.\n");
    printf("Name: %s\n", entry.szExeFile);
    printf("PID:  %lu\n", (unsigned long)entry.th32ProcessID);

    HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        entry.th32ProcessID
    );

    if (process == NULL) {
        PrintWindowsError("OpenProcess", GetLastError());
        printf("The process exists, but its details could not be queried.\n");
        return;
    }

    char imagePath[32768];
    DWORD pathLength = (DWORD)sizeof(imagePath);

    if (QueryFullProcessImageNameA(
            process, 0, imagePath, &pathLength)) {
        printf("Executable path: %s\n", imagePath);
    } else {
        PrintWindowsError("QueryFullProcessImageNameA", GetLastError());
    }

    CloseHandle(process);
}


/*
 * Enumerate modules loaded into a process.
 *
 * A module is typically the executable image or a loaded DLL.
 * The module snapshot is separate from the process snapshot.
 *
 * A 64-bit build can generally enumerate both native and 32-bit
 * modules on 64-bit Windows using the combined snapshot flags.
 */
static void ListModules(DWORD processId)
{
    HANDLE snapshot;
    MODULEENTRY32 module;
    DWORD lastError;
    unsigned long count = 0;

    snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        processId
    );

    if (snapshot == INVALID_HANDLE_VALUE) {
        lastError = GetLastError();
        PrintWindowsError("CreateToolhelp32Snapshot (modules)",
                          lastError);

        if (lastError == ERROR_PARTIAL_COPY) {
            printf("This can occur when the tool and target process "
                   "have different architectures.\n");
        }

        return;
    }

    memset(&module, 0, sizeof(module));
    module.dwSize = sizeof(module);

    if (!Module32First(snapshot, &module)) {
        lastError = GetLastError();
        CloseHandle(snapshot);
        PrintWindowsError("Module32First", lastError);
        return;
    }

    printf("\nLoaded modules for PID %lu\n",
           (unsigned long)processId);
    printf("-------------------------------------------------------------------------------\n");
    printf("MODULE NAME: %s\n", module.szModule);

    do {
        printf("\nName:       %s\n", module.szModule);
        printf("Path:       %s\n", module.szExePath);
        printf("Base:       %p\n", (void *)module.modBaseAddr);
        printf("Size:       %lu bytes\n",
               (unsigned long)module.modBaseSize);

        count++;
        SetLastError(ERROR_SUCCESS);

    } while (Module32Next(snapshot, &module));

    lastError = GetLastError();
    CloseHandle(snapshot);

    printf("\nTotal modules listed: %lu\n", count);

    if (lastError != ERROR_NO_MORE_FILES &&
        lastError != ERROR_SUCCESS) {
        PrintWindowsError("Module32Next", lastError);
    }
}


/* Find a process by name, then enumerate its modules. */
static void FindProcessAndListModules(void)
{
    char processName[MAX_PATH];
    PROCESSENTRY32 entry;
    ProcessStatus status;
    DWORD errorCode = ERROR_SUCCESS;

    printf("Enter executable name (e.g. notepad.exe): ");

    if (fgets(processName, sizeof(processName), stdin) == NULL) {
        printf("Unable to read process name.\n");
        return;
    }

    RemoveNewline(processName);

    if (processName[0] == '\0') {
        printf("Process name cannot be empty.\n");
        return;
    }

    status = GetProcessByName(processName, &entry, &errorCode);

    if (status != PROCESS_FOUND) {
        switch (status) {
        case PROCESS_NOT_FOUND:
            printf("Process '%s' was not found.\n", processName);
            break;

        case SNAPSHOT_FAILED:
            PrintWindowsError("CreateToolhelp32Snapshot", errorCode);
            break;

        case ENUMERATION_FAILED:
            PrintWindowsError("Process enumeration", errorCode);
            break;

        case INVALID_ARGUMENT:
            printf("Invalid input.\n");
            break;

        default:
            printf("Unexpected process lookup error.\n");
            break;
        }

        return;
    }

    printf("Found '%s' with PID %lu.\n",
           entry.szExeFile,
           (unsigned long)entry.th32ProcessID);

    ListModules(entry.th32ProcessID);
}


/* Display the interactive menu. */
static void PrintMenu(void)
{
    printf("\n========== Process Explorer ==========\n");
    printf("1. List all processes\n");
    printf("2. Find process by name\n");
    printf("3. List loaded modules of a process\n");
    printf("4. Exit\n");
    printf("Select an option: ");
}


int main(void)
{
    char input[32];
    char *end;
    long choice;

    for (;;) {
        PrintMenu();

        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\nInput closed. Exiting.\n");
            break;
        }

        choice = strtol(input, &end, 10);

        /* Reject input that does not begin with a valid integer. */
        if (end == input) {
            printf("Invalid selection. Enter a number from 1 to 4.\n");
            continue;
        }

        /* Permit whitespace after the number, but no extra text. */
        while (*end == ' ' || *end == '\t' ||
               *end == '\r' || *end == '\n') {
            end++;
        }

        if (*end != '\0') {
            printf("Invalid selection. Enter a number from 1 to 4.\n");
            continue;
        }

        switch (choice) {
        case 1:
            ListProcesses();
            break;

        case 2:
            FindProcess();
            break;

        case 3:
            FindProcessAndListModules();
            break;

        case 4:
            printf("Exiting Process Explorer.\n");
            return 0;

        default:
            printf("Invalid selection. Enter a number from 1 to 4.\n");
            break;
        }
    }

    return 0;
}

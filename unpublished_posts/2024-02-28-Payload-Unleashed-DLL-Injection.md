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
    
2. **Loading the DLL**: The DLL to be injected is loaded into the memory space of the target process. This can be achieved through various means, including using APIs like LoadLibrary or manually mapping the DLL into memory.
    
3. **Injection**: Once the DLL is loaded into the target process, the next step is to execute its code within that process. This is often achieved by creating a remote thread within the target process and directing it to execute a specific function within the injected DLL.

This series isn't just about showcasing the latest malware trends; it's about equipping readers with actionable insights to fortify their defenses and stay one step ahead of cyber adversaries. Through in-depth analysis and practical guidance, we empower cybersecurity professionals, enthusiasts, and organizations to detect, mitigate, and combat evolving threats effectively.

In essence, our blog series isn't merely informative. It bridges the gap between theory and practice, enabling readers to translate knowledge into proactive cybersecurity measures. 

In the following sections we will introduce the different malware TTPs that this blog will cover.

## Payload Unleashed: Techniques for Execution

In this section we will delve into the heart of malware execution as we dissect the myriad techniques utilized to infiltrate and execute our code within target systems. The techniques discussed will be the following: 

| **Technique**                     | **Description**                                                                     |
| --------------------------------- | ----------------------------------------------------------------------------------- |
| 1. DLL Injection                  | Injecting malicious DLLs into legitimate processes for code execution.              |
| 2. Shellcode Injection            | Injecting malicious shellcode directly into the process memory.                     |
| 3. APC Injection                  | Queueing malicious code to be executed during the execution of a legitimate thread. |
| 4. Mapping Injection              | Mapping malicious code into the memory space of a legitimate process.               |
| 5. Stomping Injection             | Overwriting legitimate code with malicious instructions.                            |
| 6. Threadless Injection           | Executing code without creating a new thread, often to evade detection.             |
| 7. Process Hollowing              | Replacing the memory of a legitimate process with malicious code.                   |
| 8. Ghost Process Injection        | Creating a new process with malicious code but hiding it from system monitoring.    |
| 9. Herpaderping Process Injection | Modifying system APIs to hide the presence of malicious code.                       |
| 10. DLL Sideloading               | Loading and executing malicious DLLs that masquerade as legitimate ones.            |

## Evasion Quest: Tactics for Concealment

A deep dive on the intricate strategies employed by malware to conceal its presence from security tools and researchers, navigating through the sophisticated realm of evasion and anti-analysis tactics.

| **Technique**                 | **Description**                                                            |
| ----------------------------- | -------------------------------------------------------------------------- |
| 1. String Obfuscation         | Encoding strings within the malware to obfuscate its functionality.        |
| 2. Payload Encryption         | Encrypting the payload to evade signature-based detection.                 |
| 3. IAT Hiding and Obfuscation | Hiding or obfuscating the Import Address Table (IAT) to thwart analysis.   |
| 4. Anti Debugging Techniques  | Employing techniques to detect and evade debugging attempts.               |
| 5. Anti Sandboxing Techniques | Implementing measures to detect and evade sandbox environments.            |
| 6. NTDLL Unhooking            | Removing hooks placed by security tools within the NTDLL module.           |
| 7. Indirect Syscalls          | Utilizing indirect system calls to obfuscate malware behavior.             |
| 8. File Bloating              | Adding meaningless data to files to increase their size and complexity.    |
| 9. ETW Bypass                 | Evading detection by bypassing Event Tracing for Windows (ETW) mechanisms. |
| 10. AMSI Bypass               | Circumventing Antimalware Scan Interface (AMSI) checks to avoid detection. |

## Persistence Conundrums: Strategies for Longevity

In this segment, we will delve into the strategies employed by malware to establish persistence within compromised systems, ensuring continued access and control for malicious actors.

| **Persistence Conundrums**      | **Description**                                                                   |
| ------------------------------- | --------------------------------------------------------------------------------- |
| 1. Registry Modifications       | Manipulating system registry entries to execute malicious code at startup.        |
| 2. Startup Services             | Creating or modifying services to automatically execute malware upon system boot. |
| 3. Scheduled Tasks              | Utilizing scheduled tasks to execute malicious actions at predefined intervals.   |
| 4. Bootkits                     | Subverting the boot process to load malware before the operating system.          |
| 5. System Firmware Modification | Altering system firmware to embed malware and ensure persistence across reboots.  |

## Cover Connections: Methods for Covert Communication

This section will explore the covert methods employed by malware to communicate with command and control servers, exfiltrate sensitive data, and evade detection on network infrastructures.

| **Cover Connections**           | **Description**                                                                     |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| 1. DNS Tunneling                | Using DNS queries and responses to establish covert communication channels.         |
| 2. HTTP(S) Communication        | Leveraging HTTP or HTTPS protocols to transmit data to and from C2 servers.         |
| 3. Domain Generation Algorithms | Generating domain names algorithmically to evade detection and sinkholing efforts.  |
| 4. ICMP Tunneling               | Encapsulating data within ICMP packets for covert communication purposes.           |
| 5. Covert Channels              | Exploiting legitimate network protocols to establish hidden communication channels. |
| 6. Domain Fronting              | Camouflaging malicious traffic within legitimate domains to evade detection.        |
| 7. Steganography                | Embedding data within innocuous files to conceal communication with C2 servers.     |

## Future work 

Our commitment is to empower the cybersecurity community. We want to follow this series with a collection of how-to guides and hands-on exercises in reverse engineering, with the same model as this blog. These practical will intent to provide readers with actionable steps to apply the insights gained from our blog series in real-world scenarios. By bridging the gap between theory and practice, we aim to develop practical skills in analyzing and mitigating malware threats. I hope you enjoy this journey as much as I will.  

Until next time,

Noel

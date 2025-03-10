# Process Hollowing Attack and Detection

## 📌 What is Process Hollowing?
Process hollowing is a **code injection technique** where a legitimate process is created in a suspended state and its memory is replaced with malicious code. The goal is to **evade security solutions** by making malicious code execute under the guise of a legitimate process.

Attackers often use this technique for **stealthy malware execution**, such as launching a trojanized version of `notepad.exe` while actually running a backdoor or a remote access trojan (RAT).

---

## 🔥 Exploitation Phases
The process hollowing technique consists of **several key steps**:

### **1️⃣ Create a Suspended Process**
The attacker creates a new process (e.g., `notepad.exe`) in a **suspended state** using `CreateProcessA()` or `CreateProcessW()`.

### **2️⃣ Unmap the Process Memory**
The attack code uses `NtUnmapViewOfSection()` to remove the legitimate executable code from memory while keeping the process structure intact.

### **3️⃣ Allocate New Memory for Malicious Code**
Using `VirtualAllocEx()`, the attacker allocates memory in the suspended process and writes malicious shellcode into it.

### **4️⃣ Write Malicious Code to Target Process**
The attacker writes the malicious payload into the allocated memory using `WriteProcessMemory()`.

### **5️⃣ Set Entry Point and Resume Execution**
By modifying the **entry point** in the process's **PEB (Process Environment Block)**, the malware ensures execution starts from its injected code. The process is then resumed using `ResumeThread()`.

---

## 🚀 Repository Contents

This repository contains a **C implementation of the process hollowing technique**, along with **detection mechanisms** using **YARA** and **Sigma rules**.

### **📝 Source Code: Process Hollowing (C)**
The following files are included:
- `process_hollowing.c` → The core implementation of process hollowing.
- `Makefile` → A simple Makefile to compile the project.
- `README.md` → This documentation.

### **🔍 Detection Rules**
This repository provides **YARA and Sigma rules** to detect process hollowing behavior.

| **Detection Method** | **File** |
|----------------------|----------------|
| **YARA Rules** | `proc_hollow.yara` |
| **Sigma Rules** | `proc_hollow.yml` |

---

## YARA Rule for Detecting Process Hollowing

```yara
rule process_hollowing {
    meta:
        description = "Detects process hollowing attempt"
        author = "Prodromos - Anargyros Nasis"
        date = "2025-03-10"
        reference = "Process Hollowing - https://attack.mitre.org/techniques/T1055/012/"
        severity = "high"
        mitre_attack = "T1055, T1055.012, T1106, T1204.002"
    strings:
        $api1 = "CreateProcessA" nocase
        $api2 = "VirtualAllocEx" nocase
        $api3 = "WriteProcessMemory" nocase
        $api4 = "CreateRemoteThread" nocase
    condition:
        (uint16(0) == 0x5A4D) and all of them
}
```

---

## Sigma Rule for Process Hollowing Detection (Sysmon)

```yaml
title: Process Hollowing via Windows API Calls
id: 123e4567-e89b-12d3-a456-426614174000
status: experimental
description: Detects process hollowing
author: Prodromos - Anargyros Nasis
date: 2025-03-10
references:
  - https://attack.mitre.org/techniques/T1055/
  - https://attack.mitre.org/techniques/T1055/012/
  - https://attack.mitre.org/techniques/T1106/
  - https://attack.mitre.org/techniques/T1204/002

logsource:
  category: process_creation
  product: windows

detection:
  selection:
    Image:
      - "C:\\Windows\\System32\\notepad.exe"
    CommandLine|contains:
      - "CreateProcessA"
      - "VirtualAllocEx"
      - "WriteProcessMemory"
      - "CreateRemoteThread"
      - "NtQueryInformationProcess"

  condition: selection

falsepositives:
  - Debugging tools
  - Legitimate software using memory injection

level: high
tags:
  - attack.t1055
  - attack.t1055.012
  - attack.t1106
  - attack.t1204.002
  - process_injection
  - windows
```

---

## MITRE ATT&CK Mapping

| Technique | Name |
|-----------|-------------------------------|
| **T1055** | Process Injection |
| **T1055.012** | Process Hollowing |
| **T1106** | Native API Abuse |
| **T1204.002** | User Execution: Malicious File |

---

## How to Use

### **1️ Compile the Code**
```bash
gcc process_hollowing.c -o process_hollowing.exe
```

### **2️ Run the Process Hollowing Program**
```bash
process_hollowing.exe
```

### **3️ Use YARA to Detect the Technique**
```bash
yara -r proc_hollow.yara ../poc/
```

### **4️ Monitor with Sigma (Using a SIEM or Splunk)**
Upload `proc_hollow.yml` to your SIEM tool to detect suspicious behavior.

---

## Disclaimer
**This repository is for educational purposes only!** The goal is to understand how attackers use **Process Hollowing** and how defenders can **detect and mitigate** such attacks. **Do not use this in unauthorized environments.**

---

## References
- [MITRE ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Windows API Reference](https://learn.microsoft.com/en-us/windows/win32/api/)

---

⭐ **If you find this useful, feel free to star the repository!**


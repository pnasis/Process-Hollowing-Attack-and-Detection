rule process_hollowing {
    meta:
        description = "Detects process hollowing attempt into Notepad using shellcode"
        author = "Prodromos - Anargyros Nasis"
        date = "2025-03-10"
        reference = "Process Hollowing - https://attack.mitre.org/techniques/T1055/012/"
        severity = "high"
        mitre_attack = "T1055"
    strings:
        $proc = "CreateProcessA" nocase
        $alloc = "VirtualAllocEx" nocase
        $write = "WriteProcessMemory" nocase
        $thread = "CreateRemoteThread" nocase
    condition:
        (uint16(0) == 0x5A4D) and 4 of them
}

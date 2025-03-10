rule process_hollowing {
    meta:
        description = "Detects process hollowing attempt into Notepad using shellcode"
        author = "Prodromos - Anargyros Nasis"
        date = "2025-03-10"
        reference = "Process Hollowing - https://attack.mitre.org/techniques/T1055/012/"
        severity = "high"
        mitre_attack = "T1055"
    strings:
        $api1 = "CreateProcessA" nocase
        $api2 = "VirtualAllocEx" nocase
        $api3 = "WriteProcessMemory" nocase
        $api4 = "CreateRemoteThread" nocase
    condition:
        (uint16(0) == 0x5A4D) and all of them
}

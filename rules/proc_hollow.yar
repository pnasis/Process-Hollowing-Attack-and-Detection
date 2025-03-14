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
        $api2 = "NtQueryInformationProcess" nocase
        $api3 = "VirtualAllocEx" nocase
        $api4 = "WriteProcessMemory" nocase
        $api5 = "CreateRemoteThread" nocase
    condition:
        (uint16(0) == 0x5A4D) and all of them
}

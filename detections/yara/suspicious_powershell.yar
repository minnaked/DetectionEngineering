rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects encoded or obfuscated PowerShell commands"
        author = "Mahesh Inna Kedage"
        date = "2026-05-12"
        mitre = "T1059.001, T1027"
        reference = "github.com/minnaked/DetectionEngineering"

    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $iex  = "Invoke-Expression" nocase
        $b64  = "FromBase64String" nocase
        $dl   = "DownloadString" nocase
        $hide = "-WindowStyle Hidden" nocase

    condition:
        any of them
}

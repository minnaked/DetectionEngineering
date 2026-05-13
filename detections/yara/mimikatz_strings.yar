rule Mimikatz_Strings {
    meta:
        description = "Detects common Mimikatz strings"
        author = "Mahesh Inna Kedage"
        date = "2026-05-12"
        mitre = "T1003.001"
        reference = "github.com/minnaked/DetectionEngineering"

    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
        $s3 = "privilege::debug" nocase
        $s4 = "sekurlsa::wdigest" nocase
        $s5 = "mimikatz" nocase

    condition:
        2 of them
}

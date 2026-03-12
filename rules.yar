rule Suspicious_PowerShell
{
    strings:
        $ps = "powershell -enc"
    condition:
        $ps
}
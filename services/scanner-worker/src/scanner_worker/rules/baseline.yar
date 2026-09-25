/*
  Baseline YARA rules shipped with the malware sandbox. Tenants' threat-intel teams can add
  rule packs via the rules volume; these cover common web-compromise artefacts.
*/

rule WebShell_PHP_Generic
{
    meta:
        description = "PHP web shell primitives (eval of request data)"
        severity = "high"
    strings:
        $a = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase
        $b = /(system|passthru|shell_exec|exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $c = "assert($_POST" nocase
    condition:
        any of them
}

rule JS_Skimmer_Generic
{
    meta:
        description = "Payment-page skimmer patterns (Magecart-style)"
        severity = "high"
    strings:
        $a = /(cc_?number|card_?number|cvv|expir)/ nocase
        $b = /(atob|String\.fromCharCode)\s*\(/ nocase
        $c = /new\s+Image\(\)\.src\s*=/ nocase
    condition:
        $a and $b and $c
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "PowerShell download cradle"
        severity = "medium"
    strings:
        $a = "DownloadString(" nocase
        $b = "IEX" nocase
        $c = "-EncodedCommand" nocase
    condition:
        2 of them
}

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless test signature)"
        severity = "high"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

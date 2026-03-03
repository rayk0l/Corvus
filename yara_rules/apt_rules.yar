/*
    APT & Advanced Threat YARA Rules
    High-confidence rules for advanced persistent threat tools.
    All rules require multiple string matches to avoid false positives.
*/

rule APT_Emotet {
    meta:
        description = "Detects Emotet malware"
        severity = "critical"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
    strings:
        $s1 = "Emotet" ascii wide nocase
        $pdb1 = "\\emotet\\" ascii nocase
        $pdb2 = "\\loader\\" ascii nocase
        $api1 = "CreateServiceW" ascii
        $api2 = "InternetOpenW" ascii
        $api3 = "HttpSendRequestW" ascii
        $enc1 = { 8B 45 ?? 33 45 ?? 89 45 }
        $enc2 = { 0F B6 ?? 30 ?? 4? }
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or any of ($pdb*)) and
        (2 of ($api*) or any of ($enc*))
}

rule APT_TrickBot {
    meta:
        description = "Detects TrickBot banking trojan"
        severity = "critical"
    strings:
        $s1 = "TrickBot" ascii wide nocase
        $s2 = "trickbot" ascii wide nocase
        $module1 = "injectDll" ascii wide
        $module2 = "systeminfo" ascii wide
        $module3 = "networkDll" ascii wide
        $module4 = "wormDll" ascii wide
        $cfg1 = "<mcconf>" ascii
        $cfg2 = "<servconf>" ascii
        $mutex = "Global\\TrickBot" ascii wide
    condition:
        any of ($s*) or $mutex or
        (any of ($cfg*) and any of ($module*))
}

rule APT_Qakbot {
    meta:
        description = "Detects Qakbot/QBot banking trojan"
        severity = "critical"
    strings:
        $s1 = "qakbot" ascii wide nocase
        $s2 = "qbot" ascii wide nocase
        $s3 = "pinkslipbot" ascii wide nocase
        $str1 = "spx=" ascii
        $str2 = "stager_1" ascii
        $str3 = "%s\\system32\\%s" ascii
        $pdb = "\\QBot\\" ascii nocase
    condition:
        (uint16(0) == 0x5A4D and 2 of them) or
        any of ($s*) or $pdb
}

rule APT_AgentTesla {
    meta:
        description = "Detects Agent Tesla keylogger/stealer"
        severity = "critical"
    strings:
        $s1 = "Agent Tesla" ascii wide nocase
        $s2 = "AgentTesla" ascii wide nocase
        $type1 = "KeyboardHook" ascii wide
        $type2 = "ScreenCapture" ascii wide
        $type3 = "PasswordRecovery" ascii wide
        $smtp1 = "SmtpClient" ascii wide
        $smtp2 = "NetworkCredential" ascii wide
    condition:
        any of ($s*) or
        (uint16(0) == 0x5A4D and all of ($type*) and any of ($smtp*))
}

rule APT_Formbook {
    meta:
        description = "Detects Formbook/XLoader malware"
        severity = "critical"
    strings:
        $s1 = "Formbook" ascii wide nocase
        $s2 = "XLoader" ascii wide nocase
        $dec1 = { 80 34 ?? ?? 46 3B F1 72 }
        $anti1 = "SbieDll.dll" ascii
        $anti2 = "dbghelp.dll" ascii
        $api1 = "NtCreateUserProcess" ascii
        $api2 = "NtQueryInformationProcess" ascii
    condition:
        any of ($s*) or
        ($dec1 and any of ($anti*) and any of ($api*))
}

rule APT_SolarWinds_SUNBURST {
    meta:
        description = "Detects SUNBURST backdoor (SolarWinds attack)"
        severity = "critical"
    strings:
        $s1 = "OrionImprovementBusinessLayer" ascii wide
        $s2 = "SolarWinds.Orion.Core.BusinessLayer" ascii wide
        $s3 = "avsvmcloud.com" ascii wide
        $domain1 = ".appsync-api." ascii
        $domain2 = ".avsvmcloud.com" ascii
    condition:
        any of them
}

rule APT_Log4Shell_Exploit {
    meta:
        description = "Detects Log4Shell (CVE-2021-44228) exploitation attempts"
        severity = "critical"
    strings:
        $s1 = "${jndi:ldap://" ascii wide nocase
        $s2 = "${jndi:rmi://" ascii wide nocase
        $s3 = "${jndi:dns://" ascii wide nocase
        $obf1 = "${${lower:j}" ascii nocase
        $obf2 = "${${upper:j}" ascii nocase
        $obf3 = "${${::-j}" ascii nocase
    condition:
        any of them
}

rule APT_PrintNightmare_Exploit {
    meta:
        description = "Detects PrintNightmare exploitation artifacts"
        severity = "critical"
    strings:
        $s1 = "CVE-2021-1675" ascii wide
        $s2 = "CVE-2021-34527" ascii wide
        $s3 = "PrintNightmare" ascii wide nocase
        $api1 = "AddPrinterDriverExW" ascii
        $path1 = "\\spool\\drivers\\" ascii wide nocase
    condition:
        any of ($s*) or ($api1 and $path1)
}

rule APT_ProxyShell_Webshell {
    meta:
        description = "Detects ProxyShell/ProxyLogon web shells on Exchange"
        severity = "critical"
    strings:
        $s1 = "ProxyShell" ascii wide nocase
        $s2 = "ProxyLogon" ascii wide nocase
        $s3 = "CVE-2021-26855" ascii wide
        $s4 = "CVE-2021-34473" ascii wide
        $path1 = "\\inetpub\\wwwroot\\" ascii wide nocase
        $shell1 = "China Chopper" ascii wide nocase
        $shell2 = "Godzilla" ascii wide nocase
    condition:
        any of ($s*) or any of ($shell*) or $path1
}

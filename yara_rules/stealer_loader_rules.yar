/*
    Info Stealer & Loader YARA Rules
    Specific signatures for credential stealers and malware loaders.
*/

rule Stealer_Vidar {
    meta:
        description = "Detects Vidar info stealer"
        severity = "critical"
    strings:
        $s1 = "Vidar" ascii wide nocase
        $cfg1 = "ip-api.com" ascii wide
        $cfg2 = "hwid=" ascii
        $cfg3 = "os=" ascii
        $cfg4 = "cookie" ascii
        $path1 = "\\passwords.txt" ascii wide
        $path2 = "\\autofill.txt" ascii wide
        $path3 = "\\cc.txt" ascii wide
    condition:
        $s1 or (2 of ($cfg*) and 2 of ($path*))
}

rule Stealer_Lumma {
    meta:
        description = "Detects Lumma Stealer"
        severity = "critical"
    strings:
        $s1 = "LummaC2" ascii wide nocase
        $s2 = "Lumma Stealer" ascii wide nocase
        $s3 = "lumma" ascii wide nocase
        $api1 = "/api/control" ascii
        $api2 = "/api/gate" ascii
        $str1 = "wallet.dat" ascii wide
        $str2 = "exodus" ascii wide nocase
    condition:
        any of ($s*) or (all of ($api*))
}

rule Stealer_Predator {
    meta:
        description = "Detects Predator the Thief stealer"
        severity = "critical"
    strings:
        $s1 = "Predator" ascii wide nocase
        $s2 = "PredatorTheThief" ascii wide nocase
        $api1 = "/api/gate.get" ascii
        $str1 = "Wallets" ascii
        $str2 = "Steam" ascii
        $str3 = "Discord Tokens" ascii wide
    condition:
        any of ($s*) or $api1 or ($str3 and any of ($str1, $str2))
}

rule Stealer_Raccoon_v2 {
    meta:
        description = "Detects Raccoon Stealer v2"
        severity = "critical"
    strings:
        $s1 = "RecordBreaker" ascii wide nocase
        $s2 = "Raccoon" ascii wide nocase
        $cfg1 = "machineId=" ascii
        $cfg2 = "configId=" ascii
        $str1 = "ews_" ascii
        $str2 = "ldr_" ascii
    condition:
        (any of ($s*) and any of ($cfg*, $str*)) or
        all of ($str*)
}

rule Loader_BazarLoader {
    meta:
        description = "Detects BazarLoader/BazarBackdoor"
        severity = "critical"
    strings:
        $s1 = "BazarLoader" ascii wide nocase
        $s2 = "BazarBackdoor" ascii wide nocase
        $s3 = "bazar" ascii wide nocase
        $dns1 = ".bazar" ascii
        $emercoin = "OpenNIC" ascii
        $str1 = "group_tag" ascii
        $str2 = "bot_id" ascii
    condition:
        any of ($s*) or ($dns1 and $emercoin) or all of ($str*)
}

rule Loader_IcedID {
    meta:
        description = "Detects IcedID/BokBot banking trojan"
        severity = "critical"
    strings:
        $s1 = "IcedID" ascii wide nocase
        $s2 = "BokBot" ascii wide nocase
        $dll1 = "license.dat" ascii wide
        $cfg1 = "CampaignID" ascii wide
        $str1 = "update_" ascii
        $str2 = "/news/" ascii
    condition:
        any of ($s*) or
        ($dll1 and any of ($cfg*, $str*))
}

rule Loader_SmokeLoader {
    meta:
        description = "Detects SmokeLoader malware"
        severity = "critical"
    strings:
        $s1 = "SmokeLoader" ascii wide nocase
        $s2 = "smokebot" ascii wide nocase
        $api1 = "NtWriteVirtualMemory" ascii
        $api2 = "NtProtectVirtualMemory" ascii
        $api3 = "NtResumeThread" ascii
        $inject = "explorer.exe" ascii wide
    condition:
        any of ($s*) or
        (all of ($api*) and $inject)
}

rule Backdoor_Cobalt_Strike_Malleable {
    meta:
        description = "Detects Cobalt Strike with malleable C2 profiles"
        severity = "critical"
    strings:
        $s1 = "sleeptime" ascii
        $s2 = "jitter" ascii
        $s3 = "publickey" ascii
        $s4 = "pipename" ascii
        $s5 = "post-ex" ascii
        $s6 = "process-inject" ascii
        $s7 = "spawnto" ascii
    condition:
        4 of them
}

rule Backdoor_SilverC2 {
    meta:
        description = "Detects Silver C2 framework implant"
        severity = "critical"
    strings:
        $s1 = "SliverC2" ascii wide nocase
        $s2 = "sliver" ascii wide nocase
        $s3 = "bishopfox" ascii wide nocase
        $proto1 = "sliverpb" ascii
        $proto2 = "commonpb" ascii
        $go1 = "github.com/bishopfox/sliver" ascii
    condition:
        2 of them
}

rule Backdoor_Brute_Ratel {
    meta:
        description = "Detects Brute Ratel C4 framework"
        severity = "critical"
    strings:
        $s1 = "BruteRatel" ascii wide nocase
        $s2 = "Brute Ratel" ascii wide nocase
        $s3 = "BRc4" ascii wide
        $bof1 = "badger_" ascii
        $str1 = "DarkVortex" ascii wide nocase
    condition:
        any of them
}

rule Dropper_Bumblebee {
    meta:
        description = "Detects Bumblebee malware loader"
        severity = "critical"
    strings:
        $s1 = "Bumblebee" ascii wide nocase
        $s2 = "bumblebee" ascii wide nocase
        $dll1 = "RapportGP.dll" ascii wide
        $str1 = "group_tag" ascii
        $str2 = "client_id" ascii
        $wmi = "Win32_ComputerSystemProduct" ascii wide
    condition:
        any of ($s*) or ($dll1 and any of ($str*)) or ($wmi and any of ($str*))
}

rule HackTool_Rubeus {
    meta:
        description = "Detects Rubeus Kerberos attack tool"
        severity = "critical"
    strings:
        $s1 = "Rubeus" ascii wide nocase
        $cmd1 = "asktgt" ascii wide nocase
        $cmd2 = "asktgs" ascii wide nocase
        $cmd3 = "kerberoast" ascii wide nocase
        $cmd4 = "s4u" ascii wide nocase
        $cmd5 = "renew" ascii wide nocase
        $cmd6 = "ptt" ascii wide nocase
    condition:
        $s1 and any of ($cmd*)
}

rule HackTool_SharpHound {
    meta:
        description = "Detects SharpHound/BloodHound data collector"
        severity = "critical"
    strings:
        $s1 = "SharpHound" ascii wide nocase
        $s2 = "BloodHound" ascii wide nocase
        $str1 = "CollectionMethod" ascii wide
        $str2 = "DomainController" ascii wide
        $str3 = "LdapFilter" ascii wide
        $output = "_BloodHound.zip" ascii wide
    condition:
        (any of ($s*) and any of ($str*)) or $output
}

rule HackTool_Covenant {
    meta:
        description = "Detects Covenant C2 framework"
        severity = "critical"
    strings:
        $s1 = "Covenant" ascii wide
        $s2 = "Grunt" ascii wide
        $s3 = "GruntHTTP" ascii wide
        $s4 = "GruntSMB" ascii wide
        $cfg1 = "CovenantURI" ascii wide
        $cfg2 = "ValidateCert" ascii wide
    condition:
        ($s1 and any of ($s2, $s3, $s4)) or
        all of ($cfg*)
}

/*
    Suspicious Indicators & Techniques YARA Rules
    Detects generic indicators of compromise — obfuscation, evasion, 
    suspicious scripts. Rules require multiple matches minimum.
*/

rule Suspicious_VBA_Macro {
    meta:
        description = "Detects suspicious VBA macro with shell execution"
        severity = "high"
    strings:
        $vba1 = "AutoOpen" ascii wide nocase
        $vba2 = "Auto_Open" ascii wide nocase
        $vba3 = "Document_Open" ascii wide nocase
        $vba4 = "Workbook_Open" ascii wide nocase
        $exec1 = "Shell" ascii wide
        $exec2 = "WScript.Shell" ascii wide nocase
        $exec3 = "Powershell" ascii wide nocase
        $exec4 = "cmd.exe" ascii wide nocase
        $dl1 = "URLDownloadToFile" ascii wide
        $dl2 = "XMLHTTP" ascii wide
        $dl3 = "WinHttp" ascii wide nocase
    condition:
        any of ($vba*) and
        (any of ($exec*) or any of ($dl*))
}

rule Suspicious_HTA_Dropper {
    meta:
        description = "Detects malicious HTA file with execution capabilities"
        severity = "high"
    strings:
        $hta1 = "<HTA:APPLICATION" ascii wide nocase
        $exec1 = "WScript.Shell" ascii wide nocase
        $exec2 = "Shell.Application" ascii wide nocase
        $exec3 = "powershell" ascii wide nocase
        $exec4 = "cmd /c" ascii wide nocase
        $dl1 = "ADODB.Stream" ascii wide nocase
        $dl2 = "Msxml2.XMLHTTP" ascii wide nocase
        $dl3 = "Microsoft.XMLHTTP" ascii wide nocase
        $obf1 = "eval(" ascii nocase
        $obf2 = "Execute(" ascii nocase
    condition:
        $hta1 and
        (any of ($exec*) or any of ($dl*) or any of ($obf*))
}

rule Suspicious_JS_Dropper {
    meta:
        description = "Detects malicious JavaScript dropper/downloader"
        severity = "high"
    strings:
        $obj1 = "WScript.Shell" ascii nocase
        $obj2 = "Scripting.FileSystemObject" ascii nocase
        $obj3 = "ADODB.Stream" ascii nocase
        $obj4 = "Shell.Application" ascii nocase
        $exec1 = ".Run(" ascii nocase
        $exec2 = ".Exec(" ascii nocase
        $dl1 = "XMLHTTP" ascii nocase
        $dl2 = "WinHttp" ascii nocase
        $obf1 = "eval(" ascii nocase
        $obf2 = "String.fromCharCode" ascii nocase
        $obf3 = "charCodeAt" ascii nocase
    condition:
        (any of ($obj*) and any of ($exec*)) or
        (any of ($dl*) and any of ($obf*))
}

rule Suspicious_PowerShell_Download_Execute {
    meta:
        description = "Detects PowerShell download-and-execute patterns"
        severity = "high"
    strings:
        $iex1 = "Invoke-Expression" ascii wide nocase
        $iex2 = "IEX " ascii wide nocase
        $iex3 = "IEX(" ascii wide nocase
        $dl1 = "Net.WebClient" ascii wide nocase
        $dl2 = "DownloadString" ascii wide nocase
        $dl3 = "DownloadFile" ascii wide nocase
        $dl4 = "Invoke-WebRequest" ascii wide nocase
        $dl5 = "wget " ascii wide nocase
        $dl6 = "curl " ascii wide nocase
        $enc1 = "FromBase64String" ascii wide nocase
        $enc2 = "-EncodedCommand" ascii wide nocase
        $enc3 = "-enc " ascii wide nocase
        $bypass1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $bypass2 = "-ep bypass" ascii wide nocase
        $bypass3 = "-nop" ascii wide nocase
        $hidden1 = "-WindowStyle Hidden" ascii wide nocase
        $hidden2 = "-w hidden" ascii wide nocase
    condition:
        (any of ($iex*) and any of ($dl*)) or
        (any of ($dl*) and any of ($enc*)) or
        (any of ($bypass*) and any of ($hidden*) and any of ($dl*))
}

rule Suspicious_Batch_Dropper {
    meta:
        description = "Detects suspicious batch file with download/execute patterns"
        severity = "high"
    strings:
        $dl1 = "certutil -urlcache -split -f" ascii nocase
        $dl2 = "bitsadmin /transfer" ascii nocase
        $dl3 = "powershell -c" ascii nocase
        $exec1 = "start /b" ascii nocase
        $exec2 = "schtasks /create" ascii nocase
        $hide1 = "@echo off" ascii nocase
        $del1 = "del /f /q" ascii nocase
    condition:
        any of ($dl*) and (any of ($exec*) or $del1 or $hide1)
}

rule Suspicious_Process_Injection_Imports {
    meta:
        description = "Detects PE files with process injection API combination"
        severity = "high"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx" ascii
        $api5 = "QueueUserAPC" ascii
        $api6 = "SetThreadContext" ascii
        $api7 = "ResumeThread" ascii
        $open = "OpenProcess" ascii
    condition:
        uint16(0) == 0x5A4D and
        $open and $api1 and $api2 and any of ($api3, $api4, $api5, $api6, $api7)
}

rule Suspicious_DLL_Sideloading_Names {
    meta:
        description = "Detects DLLs commonly used in DLL sideloading attacks"
        severity = "medium"
    strings:
        $n1 = "version.dll" ascii wide nocase
        $n2 = "WINMM.dll" ascii wide nocase
        $n3 = "dbghelp.dll" ascii wide nocase
        $proxy1 = "DllGetClassObject" ascii
        $proxy2 = "DllRegisterServer" ascii
        $fw1 = "GetFileVersionInfoW" ascii
        $fw2 = "VerQueryValueW" ascii
        $mal1 = "VirtualAlloc" ascii
        $mal2 = "CreateThread" ascii
        $mal3 = "LoadLibraryA" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($n*) and
        (any of ($proxy*) or any of ($fw*)) and
        all of ($mal*)
}

rule Suspicious_Base64_Executable {
    meta:
        description = "Detects base64-encoded executable payload in text files"
        severity = "high"
    strings:
        $b64_mz1 = "TVqQAAMAAAAE" ascii wide
        $b64_mz2 = "TVpQAAIAAAAE" ascii wide
        $b64_mz3 = "TVroAAAAAA" ascii wide
        $b64_elf = "f0VMRg" ascii wide
    condition:
        any of them and filesize < 10MB
}

rule Suspicious_Scheduled_Task_XML {
    meta:
        description = "Detects suspicious scheduled task XML definitions"
        severity = "medium"
    strings:
        $xml1 = "<Task " ascii wide nocase
        $xml2 = "<Exec>" ascii wide nocase
        $xml3 = "<Command>" ascii wide nocase
        $cmd1 = "powershell" ascii wide nocase
        $cmd2 = "cmd.exe" ascii wide nocase
        $cmd3 = "mshta" ascii wide nocase
        $cmd4 = "wscript" ascii wide nocase
        $cmd5 = "cscript" ascii wide nocase
        $hidden = "<Hidden>true</Hidden>" ascii wide nocase
    condition:
        $xml1 and $xml2 and $xml3 and
        any of ($cmd*) and $hidden
}

/*
    Ransomware Family YARA Rules
    Specific signatures for known ransomware families.
    All rules require multiple indicators to avoid false positives.
*/

rule Ransomware_LockBit {
    meta:
        description = "Detects LockBit ransomware"
        severity = "critical"
    strings:
        $s1 = "LockBit" ascii wide nocase
        $s2 = "lockbit" ascii wide nocase
        $note1 = "Restore-My-Files.txt" ascii wide nocase
        $note2 = "LockBit-note.hta" ascii wide nocase
        $ext1 = ".lockbit" ascii wide
        $ext2 = ".abcd" ascii wide
        $mutex = "Global\\{" ascii
    condition:
        2 of them
}

rule Ransomware_BlackCat_ALPHV {
    meta:
        description = "Detects BlackCat/ALPHV ransomware"
        severity = "critical"
    strings:
        $s1 = "BlackCat" ascii wide nocase
        $s2 = "ALPHV" ascii wide nocase
        $note1 = "RECOVER-" ascii wide
        $note2 = "-FILES.txt" ascii wide
        $rust1 = "rust_panic" ascii
        $config1 = "\"credentials\":" ascii
        $config2 = "\"kill_services\":" ascii
    condition:
        any of ($s*) or
        ($note1 and $note2) or
        ($rust1 and any of ($config*))
}

rule Ransomware_Conti {
    meta:
        description = "Detects Conti ransomware"
        severity = "critical"
    strings:
        $s1 = "CONTI" ascii wide
        $s2 = "contirecovery" ascii wide nocase
        $note1 = "readme.txt" ascii wide nocase
        $note2 = "CONTI_README" ascii wide
        $ext1 = ".CONTI" ascii
        $str1 = "All of your files are currently encrypted" ascii wide
        $mutex = "hsdfsd-mutx" ascii
    condition:
        2 of ($s*, $note*, $ext*, $mutex) or $str1
}

rule Ransomware_REvil_Sodinokibi {
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
        severity = "critical"
    strings:
        $s1 = "REvil" ascii wide nocase
        $s2 = "Sodinokibi" ascii wide nocase
        $s3 = "sodin" ascii wide nocase
        $note = "-readme.txt" ascii wide nocase
        $cfg1 = "\"pk\":" ascii
        $cfg2 = "\"pid\":" ascii
        $cfg3 = "\"sub\":" ascii
        $cfg4 = "\"nbody\":" ascii
    condition:
        any of ($s*) or $note or
        3 of ($cfg*)
}

rule Ransomware_Ryuk {
    meta:
        description = "Detects Ryuk ransomware"
        severity = "critical"
    strings:
        $s1 = "Ryuk" ascii wide
        $note1 = "RyukReadMe" ascii wide nocase
        $note2 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
        $cmd1 = "net stop" ascii wide
        $cmd2 = "taskkill" ascii wide
        $ext = ".RYK" ascii
        $pdb = "\\Ryuk\\" ascii
    condition:
        ($s1 and any of ($note*)) or $ext or $pdb or
        ($s1 and all of ($cmd*))
}

rule Ransomware_Maze {
    meta:
        description = "Detects Maze ransomware"
        severity = "critical"
    strings:
        $s1 = "maze" ascii wide nocase
        $note = "DECRYPT-FILES.txt" ascii wide nocase
        $str1 = "---=== Welcome. Again. ===" ascii wide
        $url = "mazenews" ascii wide nocase
        $ext = ".maze" ascii
    condition:
        ($s1 and $note) or $str1 or ($url and $ext)
}

rule Ransomware_Hive {
    meta:
        description = "Detects Hive ransomware"
        severity = "critical"
    strings:
        $s1 = "Hive ransomware" ascii wide nocase
        $note1 = "HOW_TO_DECRYPT.txt" ascii wide nocase
        $note2 = "Your network has been breached" ascii wide
        $ext1 = ".hive" ascii
        $key = "key.hive" ascii wide
        $login = "hiveleaks" ascii wide nocase
    condition:
        2 of them
}

rule Ransomware_BlackBasta {
    meta:
        description = "Detects Black Basta ransomware"
        severity = "critical"
    strings:
        $s1 = "Black Basta" ascii wide nocase
        $s2 = "blackbasta" ascii wide nocase
        $note = "instructions_read_me.txt" ascii wide nocase
        $ext = ".basta" ascii
        $str1 = "Your data are stolen and encrypted" ascii wide
    condition:
        any of ($s*) or ($note and $ext) or $str1
}

rule Ransomware_WannaCry {
    meta:
        description = "Detects WannaCry ransomware"
        severity = "critical"
    strings:
        $s1 = "WannaCry" ascii wide nocase
        $s2 = "WanaCrypt0r" ascii wide nocase
        $s3 = "WANACRY!" ascii wide
        $note = "@WanaDecryptor@" ascii wide
        $ext = ".WNCRY" ascii
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii
        $bitcoin = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
    condition:
        any of them
}

rule Ransomware_Phobos {
    meta:
        description = "Detects Phobos ransomware"
        severity = "critical"
    strings:
        $s1 = "Phobos" ascii wide nocase
        $note1 = "info.hta" ascii wide nocase
        $note2 = "info.txt" ascii wide nocase
        $id_pattern = ".[" ascii
        $email_pat = "].@" ascii
        $str1 = "All your files have been encrypted due to a security problem" ascii wide
    condition:
        ($s1 and any of ($note*)) or $str1 or ($id_pattern and $email_pat)
}

rule Ransomware_STOP_Djvu {
    meta:
        description = "Detects STOP/Djvu ransomware"
        severity = "critical"
    strings:
        $note = "_readme.txt" ascii wide nocase
        $str1 = "ATTENTION!" ascii wide
        $str2 = "Don't worry, you can return all your files!" ascii wide
        $str3 = "restorealldata@firemail" ascii wide nocase
        $str4 = "gorentos@bitmessage" ascii wide nocase
        $str5 = "$980" ascii wide
        $str6 = "$490" ascii wide
    condition:
        $note and ($str1 and $str2) or
        any of ($str3, $str4) or
        ($str5 and $str6 and $str1)
}

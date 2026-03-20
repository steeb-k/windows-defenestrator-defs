/*
    PUA - Adware
    Detects known adware families that inject advertisements, hijack search
    results, install root certificates for MITM, or track browsing.

    Author: System Defenestrator project
    License: MIT
*/

rule PUA_Pirrit : pua adware
{
    meta:
        description = "Pirrit adware - ad injection and browser hijacking"
        severity = "medium"
        family = "Pirrit"

    strings:
        $company = "Pirrit" ascii wide nocase
        $domain  = "pirrit.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        all of them
}

rule PUA_Genieo : pua adware
{
    meta:
        description = "Genieo - homepage/search hijacker"
        severity = "medium"
        family = "Genieo"

    strings:
        $company = "Genieo Innovation" ascii wide nocase
        $product = "Genieo" ascii wide nocase
        $domain1 = "genieo.com" ascii wide nocase
        $domain2 = "search.genieo.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        ($company or $domain2 or ($product and $domain1))
}

rule PUA_Superfish : pua adware
{
    meta:
        description = "Superfish VisualDiscovery - MITM adware that installs root CA (Lenovo)"
        severity = "high"
        family = "Superfish"

    strings:
        $company  = "Superfish" ascii wide nocase
        $product  = "VisualDiscovery" ascii wide nocase
        $komodia1 = "Komodia" ascii wide nocase
        $komodia2 = "ssl digestor" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        ($company or $product or any of ($komodia*))
}

rule PUA_Yontoo : pua adware
{
    meta:
        description = "Yontoo / Sambreel - ad injection browser extension platform"
        severity = "medium"
        family = "Yontoo"

    strings:
        $company1 = "Yontoo LLC" ascii wide nocase
        $company2 = "Sambreel" ascii wide nocase
        $product  = "Yontoo" ascii wide nocase
        $domain   = "yontoo.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_Wajam : pua adware
{
    meta:
        description = "Wajam / IMALI Media - MITM ad injector with anti-analysis capabilities"
        severity = "high"
        family = "Wajam"

    strings:
        $company  = "Wajam Internet Technologies" ascii wide nocase
        // Internal component names unique to Wajam
        $comp1    = "WaNetworkEnhancer" ascii wide nocase
        $comp2    = "WInterEnhancer" ascii wide nocase
        $comp3    = "WNetEnhance" ascii wide nocase
        $comp4    = "WNetEnhancer" ascii wide nocase
        $comp5    = "WajaNetEn" ascii wide nocase
        $comp6    = "WajaIEnhancer" ascii wide nocase
        $comp7    = "WajWebEnhance" ascii wide nocase
        // Rebrandings
        $rebrand1 = "Social2Search" ascii wide nocase
        $rebrand2 = "SearchAwesome" ascii wide nocase
        // Root cert
        $cert     = "WNetEnhance_root_cer" ascii wide nocase
        $reg1     = "SOFTWARE\\WaNetworkEnhancer" ascii wide nocase
        $domain   = "wajam.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_DealPly : pua adware
{
    meta:
        description = "DealPly - persistent adware with anti-VM and modular loader"
        severity = "medium"
        family = "DealPly"

    strings:
        $company  = "DealPly Technologies" ascii wide nocase
        $product  = "DealPly" ascii wide nocase
        $file1    = "DealPlyUpdate.exe" ascii wide nocase
        $file2    = "DealPlyLive.exe" ascii wide nocase
        $file3    = "DealPlyIE.dll" ascii wide nocase
        $param    = "--IsErIk" ascii wide
        $domain   = "cwnpu.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (any of ($company, $file1, $file2, $file3, $param, $domain) or
         ($product and 1 of ($file*, $param, $domain)))
}

rule PUA_Adpeak : pua adware
{
    meta:
        description = "Adpeak - ad injection adware targeting IE, Chrome, Firefox"
        severity = "medium"
        family = "Adpeak"

    strings:
        $company = "Adpeak, Inc" ascii wide nocase
        $alt     = "Adpeak Inc" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_OutBrowse : pua adware
{
    meta:
        description = "OutBrowse - adware/bundleware platform"
        severity = "medium"
        family = "OutBrowse"

    strings:
        $company = "OUTbrowse" ascii wide nocase
        $alt     = "OutBrowse Ltd" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_Presenoker : pua adware
{
    meta:
        description = "Presenoker - adware/browser hijacker family frequently flagged as PUA by Defender"
        severity = "medium"
        family = "Presenoker"

    strings:
        $brand1  = "Presenoker" ascii wide nocase
        $brand2  = "Adware:Win32/Presenoker" ascii wide nocase
        $file1   = "Presenoker.exe" ascii wide nocase
        $file2   = "presenoker.dll" ascii wide nocase
        $reg1    = "Software\\Presenoker" ascii wide nocase
        $task1   = "\\Presenoker" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($brand*) and 1 of ($file*, $reg1, $task1))
}

rule PUA_PCAppStore : pua adware
{
    meta:
        description = "PC App Store - deceptive third-party app store and adware platform"
        severity = "medium"
        family = "PCAppStore"

    strings:
        $brand1  = "PC App Store" ascii wide nocase
        $brand2  = "pcappstore" ascii wide nocase
        $file1   = "PCAppStore.exe" ascii wide nocase
        $file2   = "pcappstore.exe" ascii wide nocase
        $reg1    = "Software\\PC App Store" ascii wide nocase
        $domain1 = "pcappstore.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($brand*) and 1 of ($file*, $reg1, $domain1))
}

rule PUA_Vigua : pua adware
{
    meta:
        description = "Vigua - fake optimizer/adware family commonly distributed through bundled installers"
        severity = "medium"
        family = "Vigua"

    strings:
        $brand1  = "Vigua" ascii wide nocase
        $brand2  = "Vigua.A" ascii wide nocase
        $file1   = "Vigua.exe" ascii wide nocase
        $file2   = "vigua.dll" ascii wide nocase
        $reg1    = "Software\\Vigua" ascii wide nocase
        $task1   = "\\Vigua" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($brand*) and 1 of ($file*, $reg1, $task1))
}

rule PUA_ByteFence : pua adware
{
    meta:
        description = "ByteFence - potentially unwanted anti-malware product often bundled and difficult to remove"
        severity = "medium"
        family = "ByteFence"

    strings:
        $brand1    = "ByteFence" ascii wide nocase
        $brand2    = "Byte Technologies LLC" ascii wide nocase
        $artifact1 = "ByteFenceService.exe" ascii wide nocase
        $artifact2 = "ByteFence.exe" ascii wide nocase
        $artifact3 = "ByteFence Anti-Malware" ascii wide nocase
        $artifact4 = "SYSTEM\\CurrentControlSet\\Services\\ByteFenceService" ascii wide nocase
        $artifact5 = "\\ByteFence\\" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($brand*) and 1 of ($artifact*))
}

rule PUA_WebCompanion : pua adware
{
    meta:
        description = "Web Companion - browser companion/hijacker associated with Lavasoft ecosystem"
        severity = "medium"
        family = "WebCompanion"

    strings:
        $brand1    = "Web Companion" ascii wide nocase
        $brand2    = "Lavasoft" ascii wide nocase
        $artifact1 = "Lavasoft.WCAssistant.WinService.exe" ascii wide nocase
        $artifact2 = "Lavasoft.AdAware.dll" ascii wide nocase
        $artifact3 = "\\Lavasoft\\Web Companion\\" ascii wide nocase
        $artifact4 = "WCAssistant.WinService" ascii wide nocase
        $artifact5 = "wcdownloader.lavasoft.com" ascii wide nocase
        $artifact6 = "webcompanion.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($brand*) and 1 of ($artifact*))
}

rule PUA_PCAcceleratePro : pua adware
{
    meta:
        description = "PC Accelerate Pro - fake optimizer/scareware utility"
        severity = "medium"
        family = "PCAcceleratePro"

    strings:
        $brand1    = "PC Accelerate Pro" ascii wide nocase
        $brand2    = "PCAcceleratePro" ascii wide nocase
        $artifact1 = "PCAcceleratePro.exe" ascii wide nocase
        $artifact2 = "\\PCAcceleratePro\\" ascii wide nocase
        $artifact3 = "PC Accelerate Pro has detected" ascii wide nocase
        $artifact4 = "InstantSupport" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($brand*) and 1 of ($artifact1, $artifact2, $artifact3, $artifact4))
}

rule PUA_Segurazo_SAntivirus : pua adware
{
    meta:
        description = "Segurazo / SAntivirus - potentially unwanted fake-security product family"
        severity = "medium"
        family = "Segurazo"

    strings:
        $brand1    = "Segurazo" ascii wide nocase
        $brand2    = "SAntivirus Realtime Protection Lite" ascii wide nocase
        $brand3    = "SAntivirus" ascii wide nocase
        $artifact1 = "SegurazoService.exe" ascii wide nocase
        $artifact2 = "SAntivirusService.exe" ascii wide nocase
        $artifact3 = "SegurazoIC.exe" ascii wide nocase
        $artifact4 = "SAntivirusIC.exe" ascii wide nocase
        $artifact5 = "SegurazoSvc" ascii wide nocase
        $artifact6 = "\\Segurazo\\" ascii wide nocase
        $artifact7 = "segurazo.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($brand*) and 1 of ($artifact*))
}

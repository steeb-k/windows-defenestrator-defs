/*
    PUA - Chromium-based Junkware Browsers
    Detects Chromium forks distributed as bundleware/adware that hijack
    browser defaults, inject ads, or track browsing without informed consent.

    Severity: medium (PUA, not malware)
    Author: System Defenestrator project
    License: MIT
*/

rule PUA_WaveBrowser : pua adware
{
    meta:
        description = "Wave Browser - ad-injecting Chromium fork by Wavesor/Genimous/Polarity"
        severity = "medium"
        family = "WaveBrowser"

    strings:
        $company1 = "Wavesor Software" ascii wide nocase
        $company2 = "iSign International" ascii wide nocase
        $company3 = "Eightpoint Technologies" ascii wide nocase
        $company4 = "Genimous Technology" ascii wide nocase
        $company5 = "Polarity Technologies Ltd" ascii wide nocase
        $product  = "WaveBrowser" ascii wide nocase
        $domain1  = "wavebrowser.co" ascii wide nocase
        $domain2  = "gowavebrowser.com" ascii wide nocase
        $file1    = "SWUpdater.exe" ascii wide nocase
        $file2    = "SWUpdaterCore.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (any of ($company*) or $product or any of ($domain*) or all of ($file*))
}

rule PUA_TorchBrowser : pua adware
{
    meta:
        description = "Torch Browser - ad-supported Chromium fork by Torch Media"
        severity = "medium"
        family = "TorchBrowser"

    strings:
        $company = "Torch Media" ascii wide nocase
        $product = "Torch" ascii wide
        $domain  = "torchbrowser.com" ascii wide nocase
        $file1   = "torch.exe" ascii wide nocase
        $file2   = "TorchCrashHandler.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        ($company or $domain or ($product and any of ($file*)))
}

rule PUA_ChedotBrowser : pua adware
{
    meta:
        description = "Chedot Browser - ad-injecting Chromium fork"
        severity = "medium"
        family = "Chedot"

    strings:
        $company = "Chedot" ascii wide nocase
        $reg     = "SOFTWARE\\Chedot" ascii wide nocase
        $domain  = "chedot.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PUA_BoBrowser : pua adware
{
    meta:
        description = "BoBrowser - browser hijacker that replaces Chrome and injects ads"
        severity = "medium"
        family = "BoBrowser"

    strings:
        $company1 = "ClaraLabs" ascii wide nocase
        $company2 = "Clara Labs Software" ascii wide nocase
        $product  = "BoBrowser" ascii wide nocase
        $file     = "bobrowser.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_OrbitumBrowser : pua adware
{
    meta:
        description = "Orbitum Browser - data-harvesting Chromium fork"
        severity = "medium"
        family = "Orbitum"

    strings:
        $company = "Orbitum" ascii wide nocase
        $domain  = "orbitum.com" ascii wide nocase
        $file    = "orbitum.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PUA_CoowonBrowser : pua adware
{
    meta:
        description = "Coowon Browser - ad-injecting Chromium fork"
        severity = "medium"
        family = "Coowon"

    strings:
        $product = "Coowon" ascii wide nocase
        $domain  = "coowon.com" ascii wide nocase
        $file    = "coowon.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PUA_CitrioBrowser : pua adware
{
    meta:
        description = "Citrio Browser - ad-supported Chromium fork by Catalina Group"
        severity = "medium"
        family = "Citrio"

    strings:
        $company = "CATALINA GROUP" ascii wide nocase
        $product = "Citrio" ascii wide nocase
        $domain  = "citrio.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PUA_UCBrowser : pua adware
{
    meta:
        description = "UC Browser - flagged for data collection and MITM concerns"
        severity = "medium"
        family = "UCBrowser"

    strings:
        $company1 = "UCWeb" ascii wide nocase
        $company2 = "UCWeb Inc" ascii wide nocase
        $product  = "UC Browser" ascii wide nocase
        $domain1  = "ucweb.com" ascii wide nocase
        $domain2  = "uc.cn" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (any of ($company*) and ($product or any of ($domain*)))
}

rule PUA_WebNavigatorBrowser : pua adware
{
    meta:
        description = "WebNavigator Browser - browser hijacker related to Wave Browser ecosystem"
        severity = "medium"
        family = "WebNavigator"

    strings:
        $product = "WebNavigatorBrowser" ascii wide nocase
        $alt     = "WebNavigator Browser" ascii wide nocase
        $search  = "Search Encrypt" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_WebDiscoverBrowser : pua adware
{
    meta:
        description = "WebDiscover Browser - ad-injecting Chromium fork by Aztec Media that hijacks default search"
        severity = "medium"
        family = "WebDiscover"

    strings:
        $company  = "Aztec Media" ascii wide nocase
        $product1 = "WebDiscover Browser" ascii wide nocase
        $product2 = "WebDiscoverBrowser" ascii wide nocase
        $domain   = "webdiscoverbrowser.com" ascii wide nocase
        $file     = "WebDiscover.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PUA_OneLaunch : pua adware
{
    meta:
        description = "OneLaunch - bundleware dock and Chromium browser replacement by OneLaunch Technologies"
        severity = "medium"
        family = "OneLaunch"

    strings:
        $company  = "OneLaunch Technologies" ascii wide nocase
        $product  = "OneLaunch" ascii wide nocase
        $domain   = "onelaunch.com" ascii wide nocase
        $file1    = "OneLaunch.exe" ascii wide nocase
        $file2    = "OneLaunchBrowser.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PUA_OneStartBrowser : pua adware
{
    meta:
        description = "OneStart Browser - bundleware Chromium fork distributed via software installers"
        severity = "medium"
        family = "OneStart"

    strings:
        $product1 = "OneStart Browser" ascii wide nocase
        $product2 = "OneStartBrowser" ascii wide nocase
        $domain1  = "onestart.ai" ascii wide nocase
        $domain2  = "onestart.com" ascii wide nocase
        $file     = "OneStart.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PUA_ShiftBrowser : pua adware
{
    meta:
        description = "Shift Browser - multi-account browser by Shift Technologies distributed as bundleware"
        severity = "medium"
        family = "Shift"

    strings:
        $company  = "Shift Technologies" ascii wide nocase
        $product  = "Shift Browser" ascii wide nocase
        $domain   = "tryshift.com" ascii wide nocase
        $file     = "Shift.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

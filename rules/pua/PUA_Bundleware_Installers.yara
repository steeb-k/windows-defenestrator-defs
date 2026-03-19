/*
    PUA - Bundleware and Deceptive Installers
    Detects installer wrappers that bundle unwanted software with legitimate
    downloads, often with deceptive opt-out UIs.

    Severity: medium (PUA, not malware)
    Author: Windows Defenestrator project
    License: MIT
*/

rule PUA_OpenCandy : pua adware
{
    meta:
        description = "OpenCandy / SweetLabs - bundleware recommendation engine embedded in installers"
        severity = "medium"
        family = "OpenCandy"

    strings:
        $company1 = "OpenCandy, Inc" ascii wide nocase
        $company2 = "SweetLabs, Inc" ascii wide nocase
        $product  = "OpenCandy" ascii wide nocase
        $file1    = "OCSetupHlp.dll" ascii wide nocase
        $file2    = "OCSetupHlp" ascii wide nocase
        $reg1     = "SOFTWARE\\OpenCandy" ascii wide nocase
        $domain   = "opencandy.com" ascii wide nocase
        $desc     = "OpenCandy recommendation engine" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_InstallCore : pua adware
{
    meta:
        description = "InstallCore - ironSource bundleware platform that wraps legitimate installers"
        severity = "medium"
        family = "InstallCore"

    strings:
        $company1 = "ironSource" ascii wide nocase
        $product  = "InstallCore" ascii wide nocase
        $reg1     = "Software\\InstallCore" ascii wide nocase
        $domain   = "installcore.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PUA_Crossrider : pua adware
{
    meta:
        description = "Crossrider - adware platform for browser extensions (now Kape Technologies)"
        severity = "medium"
        family = "Crossrider"

    strings:
        $company = "Crossrider" ascii wide nocase
        $pdb1    = "CrossriderNotification.pdb" ascii wide nocase
        $pdb2    = "CrossriderBrowserInstaller.pdb" ascii wide nocase
        $pdb3    = "cross\\Desktop\\compilation_bot" ascii wide nocase
        $reg1    = "SOFTWARE\\Crossrider" ascii wide nocase
        $domain  = "crossrider.com" ascii wide nocase
        $clsid1  = "{02A96331-0CA6-40E2-A87D-C224601985EB}" ascii wide nocase
        $clsid2  = "{E0ADB535-D7B5-4D8B-B15D-578BDD20D76A}" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_SoftonicDownloader : pua adware
{
    meta:
        description = "Softonic Downloader - bundleware wrapper from softonic.com"
        severity = "medium"
        family = "SoftonicDownloader"

    strings:
        $company = "Softonic International" ascii wide nocase
        $product = "Softonic Downloader" ascii wide nocase
        $alt     = "SoftonicDownloader" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_CNETDownloader : pua adware
{
    meta:
        description = "CNET Download.com Installer - bundleware wrapper"
        severity = "medium"
        family = "CNETDownloader"

    strings:
        $product1 = "CNET Download.com Installer" ascii wide nocase
        $product2 = "CBS Interactive Download Manager" ascii wide nocase
        $product3 = "CNET TechTracker" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

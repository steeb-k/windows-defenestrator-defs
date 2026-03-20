/*
    PUA - Browser Toolbars and Search Hijackers
    Detects browser toolbars and search hijackers that modify browser settings,
    redirect searches, and track browsing activity.

    Severity: medium (PUA, not malware)
    Author: System Defenestrator project
    License: MIT
*/

rule PUA_Mindspark_Toolbar : pua adware
{
    meta:
        description = "Mindspark/IAC toolbar - browser hijacker family with dozens of branded toolbars"
        severity = "medium"
        family = "Mindspark"

    strings:
        $company1 = "Mindspark Interactive Network" ascii wide nocase
        $company2 = "Ask Partner Network" ascii wide nocase
        $reg1     = "SOFTWARE\\Mindspark" ascii wide nocase
        $domain1  = "hp.myway.com" ascii wide nocase
        $domain2  = "mindspark.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_AskToolbar : pua adware
{
    meta:
        description = "Ask Toolbar - browser hijacker bundled with Java and other installers"
        severity = "medium"
        family = "AskToolbar"

    strings:
        $company1 = "APN LLC" ascii wide nocase
        $product  = "Ask Toolbar" ascii wide nocase
        $file1    = "ApnStub.exe" ascii wide nocase
        $file2    = "ApnSetup.exe" ascii wide nocase
        $file3    = "ApnToolbarInstaller.exe" ascii wide nocase
        $reg1     = "SOFTWARE\\Ask.com" ascii wide nocase
        $reg2     = "SOFTWARE\\AskPartnerNetwork" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_Conduit_Toolbar : pua adware
{
    meta:
        description = "Conduit Toolbar - browser hijacker and search redirector"
        severity = "medium"
        family = "Conduit"

    strings:
        $company = "Conduit Ltd" ascii wide nocase
        $product = "Conduit Toolbar" ascii wide nocase
        $file1   = "ConduitEngine.dll" ascii wide nocase
        $file2   = "TBUpdater.dll" ascii wide nocase
        $reg1    = "SOFTWARE\\Conduit" ascii wide nocase
        $domain1 = "search.conduit.com" ascii wide nocase
        $domain2 = "api.conduit.com" ascii wide nocase
        $clsid   = "{30F9B915-B755-4826-820B-08FBA6BD249D}" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_SearchProtect : pua adware
{
    meta:
        description = "Search Protect / Client Connect - persistent browser settings hijacker"
        severity = "medium"
        family = "SearchProtect"

    strings:
        $company1 = "Client Connect Ltd" ascii wide nocase
        $product  = "Search Protect" ascii wide nocase
        $file1    = "cltmng.exe" ascii wide nocase
        $file2    = "CltMngSvc.exe" ascii wide nocase
        $reg1     = "SOFTWARE\\SearchProtect" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_DeltaToolbar : pua adware
{
    meta:
        description = "Delta Toolbar / Delta Search - browser hijacker"
        severity = "medium"
        family = "DeltaToolbar"

    strings:
        $company1 = "Montera Technologeis" ascii wide nocase
        $product  = "Delta Toolbar" ascii wide nocase
        $file1    = "DeltaTB.exe" ascii wide nocase
        $file2    = "deltasrch.dll" ascii wide nocase
        $reg1     = "SOFTWARE\\DeltaToolbar" ascii wide nocase
        $domain1  = "delta-search.com" ascii wide nocase
        $domain2  = "delta-homes.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_BabylonToolbar : pua adware
{
    meta:
        description = "Babylon Toolbar - browser hijacker and search redirector"
        severity = "medium"
        family = "BabylonToolbar"

    strings:
        $company = "Babylon Ltd" ascii wide nocase
        $product = "Babylon Toolbar" ascii wide nocase
        $file1   = "BabylonToolbarsrv.exe" ascii wide nocase
        $file2   = "BabylonIEPI.dll" ascii wide nocase
        $file3   = "BabylonToolbar.dll" ascii wide nocase
        $reg1    = "SOFTWARE\\BabylonToolbar" ascii wide nocase
        $domain1 = "search.babylon.com" ascii wide nocase
        $domain2 = "isearch.babylon.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_MyWebSearch : pua adware
{
    meta:
        description = "MyWebSearch / Fun Web Products - browser hijacker (IAC/Mindspark)"
        severity = "medium"
        family = "MyWebSearch"

    strings:
        $company1 = "FunWebProducts" ascii wide nocase
        $company2 = "Fun Web Products" ascii wide nocase
        $product1 = "MyWebSearch" ascii wide nocase
        $product2 = "MyWay Searchbar" ascii wide nocase
        $reg1     = "SOFTWARE\\FunWebProducts" ascii wide nocase
        $reg2     = "SOFTWARE\\MyWebSearch" ascii wide nocase
        $domain1  = "mywebsearch.com" ascii wide nocase
        $domain2  = "funwebproducts.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PUA_SafeFinder_Linkury : pua adware
{
    meta:
        description = "SafeFinder / Linkury SmartBar - browser hijacker"
        severity = "medium"
        family = "SafeFinder"

    strings:
        $company  = "Linkury" ascii wide nocase
        $product1 = "SafeFinder" ascii wide nocase
        $product2 = "SmartBar" ascii wide nocase
        $domain1  = "safefinder.com" ascii wide nocase
        $domain2  = "search.safefinder.com" ascii wide nocase
        $domain3  = "linkury.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

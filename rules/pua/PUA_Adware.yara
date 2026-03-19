/*
    PUA - Adware
    Detects known adware families that inject advertisements, hijack search
    results, install root certificates for MITM, or track browsing.

    Author: Windows Defenestrator project
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

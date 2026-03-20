rule RMM_ScreenConnect : pua rmm
{
    meta:
        description = "ScreenConnect / ConnectWise Control - remote access tool commonly deployed by tech support scammers"
        severity = "medium"
        family = "ScreenConnect"
        remediation = "remove"

    strings:
        $company  = "ConnectWise, LLC" ascii wide nocase
        $product1 = "ScreenConnect" ascii wide nocase
        $product2 = "ConnectWise Control" ascii wide nocase
        $svc      = "ScreenConnect Client" ascii wide nocase
        $path1    = "ScreenConnect.ClientService.exe" ascii wide nocase
        $path2    = "ScreenConnect.WindowsClient.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        // Require vendor/product corroboration to avoid matching cleanup tools
        // that only embed ScreenConnect service/path strings.
        (($company and 1 of ($product*, $svc, $path*)) or
         (all of ($product*) and 1 of ($svc, $path*)))
}

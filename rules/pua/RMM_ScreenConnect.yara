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
        ($svc or any of ($path*) or ($company and any of ($product*)))
}

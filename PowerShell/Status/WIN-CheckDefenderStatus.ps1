<#
    .SYNOPSIS 
    This script check status of MS Defender.
    
    .DESCRIPTION 
    This script check proper status of MS Defender and send alert to MS Teams Channel if something is not right.

    Script could be used as prepared diagnostic or could run periodically as monitoring tool.

    How to create MS Teams webhook:
    https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet
    
    .NOTES 
    This script must be run with administrator rights.

    Exit Codes:
    0 := The script ran successfully.
    2 := The script failed because it was run by a user without administrator privileges.
    3 := The script failed because there was problem with Get-Service
    4 := The script failed because there was problem with Get-MpComputerStatus
    5 := The script failed because there was problem with Get-MpPreference
    20 := The script failed because there was problem during sending message
    21 := The script failed because answer from server was empty

    .RELEASED 
    2024-07-12 21:00:00

    .AUTHOR 
    David Burel
    
    .KEYWORDS 
    windows, defender, av, atp, edr, alert, service
    
    .ABSOLUTEPARSE 
    True
#>

# Change the Window Title for Copyright Information
$year = Get-Date -format "yyyy"
$host.UI.RawUI.WindowTitle = "COPYRIGHT © $year David Burel. All Rights Reserved."
Clear-Host

# Script will not run unless user has adminstrator privileges
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script.`nRe-run this script as an Administrator."
    exit 2

}

# Some internal variables
$hostname = $env:COMPUTERNAME
$recErrors = New-Object System.Collections.ArrayList
# ! Define services here ...
# If checking is not required, keep array empty
[string[]]$checkServices = @(
    "MDCoreSvc"
    , "mpssvc"
    , "Sense"
    , "WdNisSvc"
    , "WinDefend"
)
# ! Define statuses here ...
# If checking is not required, keep hash table empty
$checkStatuses = @{
    AMServiceEnabled = $true
    ; AntispywareEnabled = $true
    ; AntivirusEnabled = $true
    ; BehaviorMonitorEnabled = $true
    ; DefenderSignaturesOutOfDate = $false
    ; IoavProtectionEnabled = $true
    ; IsTamperProtected = $true
    ; NISEnabled = $true
    ; OnAccessProtectionEnabled = $true
    ; RealTimeProtectionEnabled = $true
    ; RebootRequired = $false
}
# ! Define preferencies here ...
# If checking is not required, keep hash table empty
$checkPreferencies = @{
    DisableArchiveScanning = $false
    ; DisableAutoExclusions = $false
    ; DisableBehaviorMonitoring = $false
    ; DisableBlockAtFirstSeen = $false
    ; DisableCacheMaintenance = $false
    ; DisableCatchupFullScan = $false
    ; DisableCatchupQuickScan = $true
    ; DisableCoreServiceECSIntegration = $false
    ; DisableCoreServiceTelemetry = $false
    ; DisableCpuThrottleOnIdleScans = $true
    ; DisableDatagramProcessing = $false
    ; DisableDnsOverTcpParsing = $false
    ; DisableDnsParsing = $false
    ; DisableEmailScanning = $true
    ; DisableFtpParsing = $false
    ; DisableGradualRelease = $false
    ; DisableHttpParsing = $false
    ; DisableInboundConnectionFiltering = $false
    ; DisableIOAVProtection = $false
    ; DisableNetworkProtectionPerfTelemetry = $false
    ; DisablePrivacyMode = $false
    ; DisableQuicParsing = $false
    ; DisableRdpParsing = $false
    ; DisableRealtimeMonitoring = $false
    ; DisableRemovableDriveScanning = $true
    ; DisableRestorePoint = $true
    ; DisableScanningMappedNetworkDrivesForFullScan = $true
    ; DisableScanningNetworkFiles = $true
    ; DisableScriptScanning = $false
    ; DisableSmtpParsing = $false
    ; DisableSshParsing = $false
    ; DisableTamperProtection = $false
    ; DisableTlsParsing = $false
    ; EnableControlledFolderAccess = 2
    ; EnableConvertWarnToBlock = $false
    ; EnableDnsSinkhole = $true
    ; EnableEcsConfiguration = $false
    ; EnableFileHashComputation = $false
    ; EnableFullScanOnBatteryPower = $false
    ; EnableLowCpuPriority = $true
    ; EnableNetworkProtection = 1
    ; EnableUdpReceiveOffload = $false
    ; EnableUdpSegmentationOffload = $false
}

# Webhook parameters ...
# https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet
$sendMessage = $false # if true, then script sends messages if something is not correct
$organization = "<organization>"
$groupId = "<group-id>"
$tenantId = "<tenant-id>"
$webhookId = "<webhook-id>"
$channelId = "<channel-id>"
$uri = "https://$($organization).webhook.office.com/webhookb2/$($groupId)@$($tenantId)/IncomingWebhook/$($webhookId)/$($channelId)"

# Checking for services ...
Write-Host "Checking available services ..."
try {
    $servall = Get-Service -Name $checkServices -ErrorAction SilentlyContinue
    $servallmeas = $servall | Measure-Object

} catch {
    Write-Warning "`t... problem with Get-Service"
    Write-Warning $_
    exit 3

}

# ... if service is available ...
if ($servallmeas.Count -lt $checkServices.Count) {
    Write-Warning "`tSome services are not available ..."

    $checkServices | ForEach-Object {
        $chcksrv = $_
        $chckmeas = $servall | Where-Object {$_.Name -eq $chcksrv} | Measure-Object
        if ($chckmeas.Count) {
            Write-Host "`t$($chcksrv) ... OK"

        } else {
            $recErrors.Add([string]"Service $($chcksrv) is not available.") | Out-Null
            Write-Host "`t$($chcksrv) ... N/A"

        }

    }

} else {
    Write-Host "`t[OK:] All services are available ..."

}

# ... if service is running ...
Write-Host "Checking running services ..."
$serv = $servall | Where-Object {$_.Status -ne "Running" -and $_.Status -ne "StartPending"}
$servmeas = $serv | Measure-Object

if ($servmeas.Count -gt 0) {
    Write-Warning "`tSome services are not running ..."

    $serv | ForEach-Object {
        $recErrors.Add([string]"Service $($_.Name) is not running.") | Out-Null
        Write-Host "`t$($_.Name)"

    }
    
} else {
    Write-Host "`t[OK:] All available services are running ..."

}

# Checking status of protection ...
Write-Host "Checking status of protection ..."
try {
    $compStatus = Get-MpComputerStatus

    $checkStatuses.GetEnumerator() | ForEach-Object {
        if ($_.Value -ne $compStatus.$($_.Key)) {
            Write-Warning "`tReference value of '$($_.Key)' is: $($_.Value); actual value is: $($compStatus.$($_.Key))"
            $recErrors.Add([string]"Reference value of '$($_.Key)' is: $($_.Value); actual value is: $($compStatus.$($_.Key)).") | Out-Null

        } else {
            Write-Host "`t[OK:] Reference value of '$($_.Key)' is: $($_.Value); actual value is: $($compStatus.$($_.Key))"

        }
    }
    
} catch {
    Write-Warning "`t... problem with Get-MpComputerStatus"
    Write-Warning $_
    exit 4

}

# Checking status of settings ...
Write-Host "Checking status of settings ..."
try {
    $mpPrefer = Get-MpPreference

    $checkPreferencies.GetEnumerator() | ForEach-Object {
        if ($_.Value -ne $mpPrefer.$($_.Key)) {
            Write-Warning "`tReference value of '$($_.Key)' is: $($_.Value); actual value is: $($mpPrefer.$($_.Key))"
            $recErrors.Add([string]"Reference value of '$($_.Key)' is: $($_.Value); actual value is: $($mpPrefer.$($_.Key)).") | Out-Null

        } else {
            Write-Host "`t[OK:] Reference value of '$($_.Key)' is: $($_.Value); actual value is: $($mpPrefer.$($_.Key))"

        }
    }
    
} catch {
    Write-Warning "`t... problem with Get-MpPreference"
    Write-Warning $_
    exit 5

}

# Final results ...
if ($recErrors.Count -gt 0) {
    # Warnings ...
    Write-Host "Warnings ..."
    Write-Host
    $recErrors | ForEach-Object {
        Write-Host "`t$($_)"
    }
    Write-Host

    if ($sendMessage) {
        # Sending message to MS Teams Webhook ...
        Write-Host "Preparing message ..."
        $dateOfAction = Get-Date -format “yyyy-MM-dd HH-mm-ss”
        $message = '{"text":"Monitoring MS Defender status ...<br />Host: ' + $hostname + '<br />Date & Time: ' + $dateOfAction + '<br /><br />'
        $recErrors | ForEach-Object {
            $line = "{0}<br />" -f $_
            $message = $message + $line
        }
        $message = $message + '"}'
    
        Write-Host "Sending message ..."
        try {
            $result = Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $message -Uri $uri
            if (-NOT $result) {
                Write-Warning "`t... answer is empty."
                exit 21

            }
        
        } catch {
            Write-Warning "`t... something went wrong during sending."
            Write-Warning $_
            exit 20

        }

    }

}

# We are done ... 
Write-Host "Everything finished ... "
exit 0

<#
    .SYNOPSIS 
    This script check status of MS Defender.
    
    .DESCRIPTION 
    This script check status of MS Defender and send it to MS Teams Channel.

    How to create MS Teams webhook:
    https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet
    
    .NOTES 
    This script must be run with administrator rights.

    Exit Codes:
    0 := The script ran successfully.
    2 := The script failed because it was run by a user without administrator privileges.
    3 := Problem during evaluation of Get-MpComputerStatus
    4 := Something went wrong during sending message to MS Teams webhook
    5 := Something went wrong during sending message to MS Teams webhook
    6 := Problem during evaluation of Get-MpPreference
    7 := Something went wrong during sending message to MS Teams webhook
    8 := Something went wrong during sending message to MS Teams webhook
    9 := Problem during evaluation of VersionInfo
    10 := Something went wrong during sending message to MS Teams webhook
    11 := Something went wrong during sending message to MS Teams webhook
    12 := Problem during evaluation of Get-service
    13 := Something went wrong during sending message to MS Teams webhook
    14 := Something went wrong during sending message to MS Teams webhook
    15 := Problem during evaluation of Get-WinEvent
    16 := Something went wrong during sending message to MS Teams webhook
    17 := Something went wrong during sending message to MS Teams webhook
    
    .RELEASED 
    2024-07-14 08:00:00

    .AUTHOR 
    David Burel
    
    .KEYWORDS 
    windows, defender, av, atp, edr, status, service
    
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

# Webhook parameters ...
# https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet
$organization = "<organization>"
$groupId = "<group-id>"
$tenantId = "<tenant-id>"
$webhookId = "<webhook-id>"
$channelId = "<channel-id>"
$uri = "https://$($organization).webhook.office.com/webhookb2/$($groupId)@$($tenantId)/IncomingWebhook/$($webhookId)/$($channelId)"

# Get-MpComputerStatus partition ... 
try {
    $dateOfAction = Get-Date -format “yyyy-MM-dd HH-mm-ss”
    $message = '{"text":"Gathering MS Defender status ...<br />Host: ' + $hostname + '<br />Date & Time: ' + $dateOfAction + '<br />'
    $stats = Get-MpComputerStatus
    $message = $message + '<table>'
    # List properties ...
    $stats | Get-Member | ForEach-Object { 
        if( $_.MemberType -eq 'Property' -and $_.Name -notlike “__*”) {
            $line = "<tr><th>{0}</th><td>{1}</td></tr>" -f $_.Name, $stats.$($_.Name)
            $message = $message + $line
        } 
    }
    $message = $message + '</table>'
    $message = $message + '"}'

} catch {
    Write-Warning "Problem during evaluation of Get-MpComputerStatus."
    Write-Warning $_
    exit 3

}

# Send message ...
try {
    $result = Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $message -Uri $uri
    if (-NOT $result) {
        Write-Warning "xxx."
        exit 5
    }
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 4
}

try {
    $dateOfAction = Get-Date -format “yyyy-MM-dd HH-mm-ss”
    $message = '{"text":"Gathering MS Defender references ...<br />Host: ' + $hostname + '<br />Date & Time: ' + $dateOfAction + '<br />'
    $stats = Get-MpPreference
    $message = $message + '<table>'
    $stats | Get-Member | ForEach-Object { 
        if( $_.MemberType -eq 'Property' -and $_.Name -notlike “__*”) {
            $name = $_.Name
            $value = $stats.$($_.Name)
            $meas = $value | Measure-Object

            if ($meas.Count -gt 1) {
                $subline = ""
                $value | ForEach-Object {
                    if(($_.GetType()).Name -eq "String") {
                        $subline = $subline + " <br />" + $_.Replace('\', '\\')
                    } else {
                        $subline = $subline + " <br />" + $_
                    }
                }
                $line = "<tr><td colspan=2><b>{0}</b>{1}</td></tr>" -f $name, $subline
                $line
            } else {
                $line = "<tr><th>{0}</th><td>{1}</td></tr>" -f $name, $value

            }
            $message = $message + $line
        } 
    }
    $message = $message + '</table>'
    $message = $message + '"}'
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 6
}

# Send message ...
try {
    $result = Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $message -Uri $uri
    if (-NOT $result) {
        Write-Warning "xxx."
        exit 8
    }
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 7
}

try {
    $dateOfAction = Get-Date -format “yyyy-MM-dd-HH-mm-ss”
    $message = '{"text":"Gathering MS Defender file version ...<br />Host: ' + $hostname + '<br />Date & Time: ' + $dateOfAction + '<br />'
    $itemVersion = (Get-Item "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe").'VersionInfo'
    $message = $message + '<table>'
    $itemVersion | Get-Member | ForEach-Object {
        if( $_.MemberType -eq 'Property' -and $_.Name -notlike “__*”) {
            $name = $_.Name
            $value = $itemVersion.$($_.Name)
            if(($value.GetType()).Name -eq "String") {
                $value = $value.Replace('\', '\\')
            }
            $line = "<tr><th>{0}</th><td>{1}</td></tr>" -f $name,$value
            $message = $message + $line
        }
    }
    $message = $message + '</table>'
    $message = $message + '"}'
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 9
}

# Send message ...
try {
    $result = Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $message -Uri $uri
    if (-NOT $result) {
        Write-Warning "xxx."
        exit 11
    }
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 10
}

try {
    $dateOfAction = Get-Date -format “yyyy-MM-dd-HH-mm-ss”
    $message = '{"text":"Gathering MS Defender services ...<br />Host: ' + $hostname + '<br />Date & Time: ' + $dateOfAction + '<br />'
    $message = $message + '<table><tr><th>Name</th><th>State</th><th>Description</th></tr>'
    Get-service -displayname *defender* | ForEach-Object {
        $line = "<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>" -f $_.'Name', $_.'Status', $_.'DisplayName'
        $message = $message + $line
    }
    $message = $message + '</table>'
    $message = $message + '"}'
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 12
}

# Send message ...
try {
    $result = Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $message -Uri $uri
    if (-NOT $result) {
        Write-Warning "xxx."
        exit 14
    }
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 13
}

try {
    $xmlQuery = @'
    <QueryList>
      <Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational">
        <Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[( (EventID >= 1000 and EventID <= 1006) ) and TimeCreated[timediff(@SystemTime) <= 604800000]]]</Select>
      </Query>
    </QueryList>
'@

    $scanParam = @{ 
        1 = "Quick Scan"
        ; 2 = "Full Scan"
        ; 3 = "Custom Scan" 
    }
    $eventDescrById = @{ 
        1000 = "An antimalware scan started"
        ; 1001 = "An antimalware scan finished"
        ; 1002 = "An antimalware scan was stopped before it finished"
        ; 1003 = "An antimalware scan was paused"
        ; 1004 = "An antimalware scan was resumed"
        ; 1005 = "An antimalware scan failed"
        ; 1006 = "The antimalware engine found malware or other potentially unwanted software" 
    } 
    $eventXPathById = @{ 
        1000 = @(
            'Event/EventData/Data[@Name="Product Version"]'
            , 'Event/EventData/Data[@Name="Scan ID"]'
            , 'Event/EventData/Data[@Name="Scan Parameters Index"]'
            , 'Event/EventData/Data[@Name="Domain"]'
            , 'Event/EventData/Data[@Name="User"]'
            , 'Event/EventData/Data[@Name="SID"]' 
            , 'Event/EventData/Data[@Name="Scan Resources"]'
        )
        ; 1001 = @(
            'Event/EventData/Data[@Name="Product Version"]'
            , 'Event/EventData/Data[@Name="Scan ID"]'
            , 'Event/EventData/Data[@Name="Scan Parameters Index"]'
            , 'Event/EventData/Data[@Name="Domain"]'
            , 'Event/EventData/Data[@Name="User"]'
            , 'Event/EventData/Data[@Name="SID"]'
            , 'Event/EventData/Data[@Name="Scan Time Hours"]'
            , 'Event/EventData/Data[@Name="Scan Time Minutes"]'
            , 'Event/EventData/Data[@Name="Scan Time Seconds"]' 
        )
        ; 1002 = @(
            'Event/EventData/Data[@Name="Product Version"]'
            , 'Event/EventData/Data[@Name="Scan ID"]'
            , 'Event/EventData/Data[@Name="Scan Parameters Index"]'
            , 'Event/EventData/Data[@Name="Domain"]'
            , 'Event/EventData/Data[@Name="User"]'
            , 'Event/EventData/Data[@Name="SID"]'
        )
        ; 1003 = @(
            'Event/EventData/Data[@Name="Product Version"]'
            , 'Event/EventData/Data[@Name="Scan ID"]'
            , 'Event/EventData/Data[@Name="Scan Parameters Index"]'
            , 'Event/EventData/Data[@Name="Domain"]'
            , 'Event/EventData/Data[@Name="User"]'
            , 'Event/EventData/Data[@Name="SID"]'
        )
        ; 1004 = @(
            'Event/EventData/Data[@Name="Product Version"]'
            , 'Event/EventData/Data[@Name="Scan ID"]'
            , 'Event/EventData/Data[@Name="Scan Parameters Index"]'
            , 'Event/EventData/Data[@Name="Domain"]'
            , 'Event/EventData/Data[@Name="User"]'
            , 'Event/EventData/Data[@Name="SID"]'
        )
        ; 1005 = @(
            'Event/EventData/Data[@Name="Product Version"]'
            , 'Event/EventData/Data[@Name="Scan ID"]'
            , 'Event/EventData/Data[@Name="Scan Parameters Index"]'
            , 'Event/EventData/Data[@Name="Domain"]'
            , 'Event/EventData/Data[@Name="User"]'
            , 'Event/EventData/Data[@Name="SID"]'
        )
        ; 1006 = @(
            'Event/EventData/Data[@Name="Product Version"]'
            , 'Event/EventData/Data[@Name="Scan ID"]'
            , 'Event/EventData/Data[@Name="Scan Parameters Index"]'
            , 'Event/EventData/Data[@Name="Domain"]'
            , 'Event/EventData/Data[@Name="User"]'
            , 'Event/EventData/Data[@Name="SID"]'
        ) 
    }

    $dateOfAction = Get-Date -format “yyyy-MM-dd-HH-mm-ss”
    $message = '{"text":"Gathering MS Defender events log ...<br />Host: ' + $hostname + '<br />Date & Time: ' + $dateOfAction + '<br /><br />'
    $eventslog = Get-WinEvent -FilterXml $xmlQuery
    $eventslog | ForEach-Object {
        $eventrecord = ($_)

        $timecreated = $eventRecord.'TimeCreated'
        $evntid = [int32]$eventRecord.'Id'

        if($eventDescrById.ContainsKey($evntid) -And $eventXPathById.ContainsKey($evntid)) {
            $descr = $eventDescrById[$evntid]
            $props = ""

            [string[]]$xpathRef = $eventXPathById[$evntid]
            $xpathEnum = [System.Collections.Generic.IEnumerable[string]]$xpathRef
            $evntPropSelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($xpathEnum)
            $evntprop = $eventrecord.GetPropertyValues($evntPropSelector)

            if ($evntid -eq 1000) {
                $respath = $evntprop[6].Split(';')
                $respath = $respath -join "<br />"
                $props = "&nbsp;&nbsp;&nbsp;Product version: {0}<br />&nbsp;&nbsp;&nbsp;Scan ID: {1}<br />&nbsp;&nbsp;&nbsp;Scan Type: {2}<br />&nbsp;&nbsp;&nbsp;Identity: {3}\\{4} ({5})<br />&nbsp;&nbsp;&nbsp;Resources:<br />{6}<br />" -f $evntprop[0],$evntprop[1],$scanParam[[int32]$evntprop[2]],$evntprop[3],$evntprop[4],$evntprop[5],$respath.Replace('\', '\\')
               
            }

            if ($evntid -eq 1001) {
                $props = "&nbsp;&nbsp;&nbsp;Product version: {0}<br />&nbsp;&nbsp;&nbsp;Scan ID: {1}<br />&nbsp;&nbsp;&nbsp;Scan Type: {2}<br />&nbsp;&nbsp;&nbsp;Identity: {3}\\{4} ({5})<br />&nbsp;&nbsp;&nbsp;Scan Time: {6}:{7}:{8}<br />" -f $evntprop[0],$evntprop[1],$scanParam[[int32]$evntprop[2]],$evntprop[3],$evntprop[4],$evntprop[5],$evntprop[6],$evntprop[7],$evntprop[8]
               
            }

            if ($evntid -eq 1002) {
                $props = "&nbsp;&nbsp;&nbsp;Product version: {0}<br />&nbsp;&nbsp;&nbsp;Scan ID: {1}<br />&nbsp;&nbsp;&nbsp;Scan Type: {2}<br />&nbsp;&nbsp;&nbsp;Identity: {3}\\{4} ({5})<br />" -f $evntprop[0],$evntprop[1],$scanParam[[int32]$evntprop[2]],$evntprop[3],$evntprop[4],$evntprop[5]
               
            }

            if ($evntid -eq 1003) {
                $props = "&nbsp;&nbsp;&nbsp;Product version: {0}<br />&nbsp;&nbsp;&nbsp;Scan ID: {1}<br />&nbsp;&nbsp;&nbsp;Scan Type: {2}<br />&nbsp;&nbsp;&nbsp;Identity: {3}\\{4} ({5})<br />" -f $evntprop[0],$evntprop[1],$scanParam[[int32]$evntprop[2]],$evntprop[3],$evntprop[4],$evntprop[5]
               
            }

            if ($evntid -eq 1004) {
                $props = "&nbsp;&nbsp;&nbsp;Product version: {0}<br />&nbsp;&nbsp;&nbsp;Scan ID: {1}<br />&nbsp;&nbsp;&nbsp;Scan Type: {2}<br />&nbsp;&nbsp;&nbsp;Identity: {3}\\{4} ({5})<br />" -f $evntprop[0],$evntprop[1],$scanParam[[int32]$evntprop[2]],$evntprop[3],$evntprop[4],$evntprop[5]
               
            }

            if ($evntid -eq 1005) {
                $props = "&nbsp;&nbsp;&nbsp;Product version: {0}<br />&nbsp;&nbsp;&nbsp;Scan ID: {1}<br />&nbsp;&nbsp;&nbsp;Scan Type: {2}<br />&nbsp;&nbsp;&nbsp;Identity: {3}\\{4} ({5})<br />" -f $evntprop[0],$evntprop[1],$scanParam[[int32]$evntprop[2]],$evntprop[3],$evntprop[4],$evntprop[5]
               
            }

            if ($evntid -eq 1006) {
                $props = "&nbsp;&nbsp;&nbsp;Product version: {0}<br />&nbsp;&nbsp;&nbsp;Scan ID: {1}<br />&nbsp;&nbsp;&nbsp;Scan Type: {2}<br />&nbsp;&nbsp;&nbsp;Identity: {3}\\{4} ({5})<br />" -f $evntprop[0],$evntprop[1],$scanParam[[int32]$evntprop[2]],$evntprop[3],$evntprop[4],$evntprop[5]
               
            }

        } else {
            $descr = "Not defined event ..."
            $props = ""

        }

        $line = "Date & Time: {0}<br />Event ID: {1}<br />Description: {2}<br />{3}<br />" -f $timecreated,$evntid,$descr,$props
        $message = $message + $line

    }
    $message = $message + '"}'
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 15
}

# Send message ...
try {
    $result = Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $message -Uri $uri
    if (-NOT $result) {
        Write-Warning "xxx."
        exit 17
    }
} catch {
    Write-Warning "xxx."
    Write-Warning $_
    exit 16
}

# We are done ... 
Write-Host "Everything finished ... "
exit 0

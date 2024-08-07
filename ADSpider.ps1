﻿###################################################################
###################################################################
Function Invoke-ADSpider(
[cmdletbinding()]
[parameter(Mandatory=$true, ParameterSetName = 'Main')][string]$DC,
[parameter(ParameterSetName = 'Main')][switch]$Credentials = $false,
[parameter(ParameterSetName = 'Main')][switch]$FormatList = $false,
[parameter(ParameterSetName = 'Main')][switch]$ExcludelastLogonTimestamp = $false,
[parameter(ParameterSetName = 'Main')][switch]$DumpAllObjects = $false,
[parameter(ParameterSetName = 'Main')][switch]$Short = $false,
[parameter(ParameterSetName = 'Main')][string]$Output = $null,
[parameter(ParameterSetName = 'Main')][array]$ExcludeObjectGUID = $null,
[parameter(ParameterSetName = 'Main')][int]$Sleep = 30,
[parameter(ParameterSetName = 'Main')][int]$USN = $null,
[parameter(Mandatory=$true, ParameterSetName = 'Display')][string]$DisplayXML = $null
)
{
<#

.SYNOPSIS

ADSpider monitor any replicated changes in Microsoft Active Direcotry

.DESCRIPTION

ADSpider use USN to monitor any replicated changes in Microsoft Active Direcotry

#>
###################################################################
## Included functions
###################################################################
Function Convert-UAC ([int]$UAC)
{
$UACPropertyFlags = @(
"SCRIPT",
"ACCOUNTDISABLE",
"RESERVED",
"HOMEDIR_REQUIRED",
"LOCKOUT",
"PASSWD_NOTREQD",
"PASSWD_CANT_CHANGE",
"ENCRYPTED_TEXT_PWD_ALLOWED",
"TEMP_DUPLICATE_ACCOUNT",
"NORMAL_ACCOUNT",
"RESERVED",
"INTERDOMAIN_TRUST_ACCOUNT",
"WORKSTATION_TRUST_ACCOUNT",
"SERVER_TRUST_ACCOUNT",
"RESERVED",
"RESERVED",
"DONT_EXPIRE_PASSWORD",
"MNS_LOGON_ACCOUNT",
"SMARTCARD_REQUIRED",
"TRUSTED_FOR_DELEGATION",
"NOT_DELEGATED",
"USE_DES_KEY_ONLY",
"DONT_REQ_PREAUTH",
"PASSWORD_EXPIRED",
"TRUSTED_TO_AUTH_FOR_DELEGATION",
"RESERVED",
"PARTIAL_SECRETS_ACCOUNT"
"RESERVED"
"RESERVED"
"RESERVED"
"RESERVED"
"RESERVED"
)
return (0..($UACPropertyFlags.Length) | where-object {$UAC -bAnd [math]::Pow(2,$_)} | foreach-object {$UACPropertyFlags[$_]}) -join ” | ”
} ## Function Convert-UAC
###################################################################
## Main
###################################################################
## Beautifull logo :)
Write-host '
                                                                                         (
       d8888 8888888b.   .d8888b.           d8b      888                                  )
      d88888 888  "Y88b d88P  Y88b          Y8P      888                                 ( 
     d88P888 888    888 Y88b.                        888                           /\  .-"""-.  /\ 
    d88P 888 888    888  "Y888b.   88888b.  888  .d88888  .d88b.  888d888         //\\/  ,,,  \//\\ 
   d88P  888 888    888     "Y88b. 888 "88b 888 d88" 888 d8P  Y8b 888P"           |/\| ,;;;;;, |/\| 
  d88P   888 888    888       "888 888  888 888 888  888 88888888 888             //\\\;-"""-;///\\ 
 d8888888888 888  .d88P Y88b  d88P 888 d88P 888 Y88b 888 Y8b.     888            //  \/   .   \/  \\ 
d88P     888 8888888P"   "Y8888P"  88888P"  888  "Y88888  "Y8888  888           (| ,-_| \ | / |_-, |) 
                                   888                                            //`__\.-.-./__`\\ 
                                   888                                           // /.-(() ())-.\ \\ 
                                   888                                          (\ |)   "---"   (| /) 
                                                                                 ` (|           |) ` 
                                                             By DrunkF0x.          \)           (/
'
## If all we need just pretty display saved result
if ($DisplayXML) {
    "Reading data from $DisplayXML"
    $OutputData = Import-Clixml $DisplayXML
    $DomainDN = ($OutputData.Object -split(",") | where-object {$_ -match "^DC="}) -join(",")
    $OutputData | format-table -Property @{Label='Object';Expression={$_.Object.TrimEnd($DomainDN)};Width=[int](($Host.UI.RawUI.WindowSize.Width - 77)/4)},
        @{Label='AttributeName';Expression={$_.AttributeName};Width=[int](($Host.UI.RawUI.WindowSize.Width - 77)/5)},
        @{Label='AttributeValue';Expression={$_.AttributeValue};Width=[int](($Host.UI.RawUI.WindowSize.Width - 77)/4)},
        @{Label='LastOriginChangeTime';Expression={$_.LastOriginatingChangeTime};Width=20},
        @{Label='LocalChangeUsn';Expression={$_.LocalChangeUsn};Width=14},
        @{Label='Version';Expression={$_.Version};Width=7},
        @{Label='Explanation';Expression={$_.Explanation};Width=[int](($Host.UI.RawUI.WindowSize.Width - 77)/5)},
        @{Label='ObjectGUID';Expression={$_.ObjectGUID};Width=36} -Wrap 
    return 
    } ## if ($DisplayXML)
## Import module ActiveDirectory, if it does not import yet
if (!(Get-Module | Where-Object {$_.Name -eq "ActiveDirectory"})) {import-module ActiveDirectory}
## Collected data storage
$USNDataWH = @()
$CliXLMDataWH = @()
## If we need, we set domain credentials
if ($Credentials) {
    $DomainCreds = Get-Credential
    } ## if ($Credentials)
## Domain Controller ip 
$DCIp = (Resolve-DnsName $DC).IPAddress
## If we need, we dump all objects with all properties. 
## This is very loud, high network use and time consuming.
## But this this the sacrifice you are willing to make...
$DumpedAD = $null
if ($DumpAllObjects) {
    Write-Host "Dumping all Active Directory objects... This can take a lot of time."
    $DumpedAD = Get-ADObject -Filter * -Properties * -Server $DC
    Write-Host "Done!"
    }
## Get first DC usn value
if (!$USN) {
    if ($Credentials) {
        $DCInvID = (Get-ADDomainController $DC -Server $DC -Credential $DomainCreds).InvocationID.Guid
        $DCStartReplUTDV = Get-ADReplicationUpToDatenessVectorTable $DC -EnumerationServer $DCIp -Credential $DomainCreds | where-object {$_.PartnerInvocationId.Guid -eq $DCInvID}
        } ## if ($Credentials)
    else {
        $DomainDN = (Get-ADDomain -Server $DC).DistinguishedName
        $DCInvID = (Get-ADDomainController $DC -Server $DC).InvocationID.Guid
        $DCStartReplUTDV = Get-ADReplicationUpToDatenessVectorTable $DC -EnumerationServer $DCIp | where-object {$_.PartnerInvocationId.Guid -eq $DCInvID}   
        } ## else
    $DCOldUSN = $DCStartReplUTDV.USNFilter
    } ## if (!$USN)
elseif ($USN) {
    $DCOldUSN = $USN
    } ## esleif ($USN)
"Spider on AD Web now..."
if ($Output) {
    "Output will be save in $Output"
    } ## if ($Output)
## Main loop
:main for (;;) {
    start-sleep -Seconds $Sleep
    if ($Credentials) {
        $DCReplUTDV = Get-ADReplicationUpToDatenessVectorTable $DC -EnumerationServer $DCIp -Credential $DomainCreds | where-object {$_.PartnerInvocationId.Guid -eq $DCInvID}
        } ## if ($Credentials)
    else {
        $DCReplUTDV = Get-ADReplicationUpToDatenessVectorTable $DC -EnumerationServer $DCIp | where-object {$_.PartnerInvocationId.Guid -eq $DCInvID}
        } ## else
    ## If new USN value greater than old, than we got some changes
    if ($DCReplUTDV.USNFilter -gt $DCOldUSN) {
        ## Save new USN value
        $DCChangedUSN = $DCReplUTDV.USNFilter
        ## Get all objects from current DC, where ChangeUSN value greater than new USN
        if ($Credentials) {
            $ChangedObjects = Get-ADObject -LDAPFilter "(&(objectClass=*)(usnchanged>=$DCOldUSN))" -Server $DC -Credential $DomainCreds -IncludeDeletedObjects
            } ## if ($Credentials)
        else {
            $ChangedObjects = Get-ADObject -LDAPFilter "(&(objectClass=*)(usnchanged>=$DCOldUSN))" -Server $DC -IncludeDeletedObjects
            Write-Debug "Gotted changed objects"
            } ## else
        :changed_objects foreach ($Object in $ChangedObjects) {
            ## Check if object in ExcludeObject
            ## If object in Exclude list, just ignore it :)
            if ($ExcludeObjectGUID -contains $Object.ObjectGUID.Guid) {
                continue changed_objects
                } ## if Exclude
            if ($Credentials) {            
                $Props = Get-ADReplicationAttributeMetadata $Object.DistinguishedName -Server $DC -Credential $DomainCreds -IncludeDeletedObjects -ShowAllLinkedValues
                } ## if ($Credentials)
            else {
                $Props = Get-ADReplicationAttributeMetadata $Object.ObjectGUID.Guid -Server $DC -IncludeDeletedObjects -ShowAllLinkedValues
                } ## else
            $ChangedProps = $Props | Where-Object {$_.LocalChangeUsn -gt $DCOldUSN} | 
                Select-Object Object,AttributeName,AttributeValue,LastOriginatingChangeTime,LocalChangeUsn,Version
            ############################################# 
            ##
            ## Working with single property
            ##
            #############################################
            :props foreach ($Prop in $ChangedProps) {
                ## Adding new property for explanation about changes
                $Prop | Add-Member -MemberType NoteProperty -Name Explanation -Value $Null
                ## Adding new property for ObjectGUID
                $Prop | Add-Member -MemberType NoteProperty -Name ObjectGUID -Value $Object.ObjectGUID.Guid
                ## Add some human readable information
                switch ($Prop.AttributeName) {
                    ## convert number of userAccountControl to human format
                    "userAccountControl" {
                        $Prop.Explanation = Convert-UAC $Prop.AttributeValue
                        } ## "userAccountControl"
                    ## add or delete member from group
                    "member" {
                        if ($Prop.Version%2 -eq 1) {
                            $Prop.Explanation = "Added to group"
                            } ## if ($Prop.Version%2 -eq 0)
                        else {
                            $Prop.Explanation = "Deleted from group"
                            } ## else
                        } ## "member"
                    ## convert date & time to human format
                    {($_ -eq "lastLogonTimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lockoutTime") -or ($_ -eq "ms-Mcs-AdmPwdExpirationTime")} {
                        $Prop.Explanation = [DateTime]::FromFileTime($Prop.AttributeValue)
                        } ## "accountExpires", "pwdlastset"...
                    ## Expires Account convert to human readable format
                    {($_ -eq "accountExpires")} {
                        if (($Prop.AttributeValue -eq 0) -or ($Prop.AttributeValue -gt [DateTime]::MaxValue.Ticks)) {$Prop.Explanation = "Never Expired"}
                        else {
                            $AEDate = [datetime]$Prop.AttributeValue
                            $Prop.Explanation = $AEDate.AddYears(1600).ToLocalTime()
                            } ## else
                        } ## $_ -eq "accountExpires"
                    } ## switch
                } ## :props foreach ($Prop in $ChangedProps)
            ## Exclude lastLogonTimestamp events
            if ($ExcludelastLogonTimestamp) {
                $ChangedProps = $ChangedProps | Where-Object {$_.AttributeName -ne "lastLogonTimestamp"}
                }
            ############################################# 
            ##
            ## Checking for changes 
            ## Надо пройтись по каждой строчке и поискать в $USNDataWH строчки с ObjectGUID и AttributeName. Если такие строчки нашлись, мы берем строчку с самым высоким USN.
            ##
            #############################################
            ## Colorize output (for PowerShell 5.1)
            $esc = [char]27; # escape character
            $red = $esc + '[31m'
            $green = $esc + '[32m'
            $yellow = $esc + '[33m'
            $reset = $esc + '[0m'
            ## Output variable
            $OutputData = @()
            :history foreach ($HistoryProp in $ChangedProps) {
                ## Expressions for new value
                $AttrNew = $HistoryProp.AttributeValue
                #$Exp_New = {$("{0}$AttrNew{1}" -f $green, $reset)}
                #$OutputData += $HistoryProp | Select-Object Object,AttributeName,@{Label="AttributeValue";Expression=$Exp_New},LastOriginatingChangeTime,LocalChangeUsn,Version,Explanation,ObjectGUID
                $OutputData += $HistoryProp | Select-Object Object,AttributeName,@{Label="AttributeValue";Expression={$green + $AttrNew + $reset}},LastOriginatingChangeTime,LocalChangeUsn,Version,Explanation,ObjectGUID
                if ($HistoryProp.AttributeName -eq "member") {continue history}
                $OldRecords = $null
                $RecentChange = $null
                $OldRecords = $USNDataWH | Where-Object {$_.ObjectGUID -eq $HistoryProp.ObjectGUID -AND $_.Attributename -eq $HistoryProp.Attributename}
                Write-Debug "Got old records from USNDataWH"
                ## If no old values but we dump all AD before - we search this value in dump
                if (!$OldRecords -AND $DumpedAD) {
                    $DumpedObject = $DumpedAD | Where-Object {$_.ObjectGUID.GUID -eq $HistoryProp.ObjectGUID}
                    $DumpExplanation = "-"
                    $ValueFromDump = $DumpedObject.($HistoryProp.AttributeName)
                    switch ($HistoryProp.AttributeName) {
                        ## convert number of userAccountControl to human format
                        "userAccountControl" {
                            $DumpExplanation = Convert-UAC $ValueFromDump
                            } ## "userAccountControl"
                        ## convert date & time to human format
                        {($_ -eq "lastLogonTimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lockoutTime") -or ($_ -eq "ms-Mcs-AdmPwdExpirationTime")} {
                            $DumpExplanation = [DateTime]::FromFileTime($ValueFromDump)
                            } ## "accountExpires", "pwdlastset"...
                        ## Expires Account convert to human readable format
                        {($_ -eq "accountExpires")} {
                            if (($HistoryProp.AttributeName -eq 0) -or ($HistoryProp.AttributeName -gt [DateTime]::MaxValue.Ticks)) {$DumpExplanation = "Never Expired"}
                            else {
                                $AEDate = [datetime]$ValueFromDump
                                $DumpExplanation = $AEDate.AddYears(1600).ToLocalTime()
                                } ## else
                            } ## $_ -eq "accountExpires"
                        } ## switch
                    #$Exp_Dump = {$("{0}$ValueFromDump{1}" -f $red, $reset)}
                    #$OutputData += $DumpedObject | Select-Object @{n="Object";e={$_.DistinguishedName}},@{n="AttributeName";e={$HistoryProp.AttributeName}},
                    #    @{n="AttributeValue";e=$Exp_Dump},@{n="LastOriginatingChangeTime";e={"-"}},@{n="LocalChangeUsn";e={"-"}},@{n="Version";e={"-"}},@{n="Explanation";e={$DumpExplanation}},@{n="ObjectGUID";e={$_.ObjectGUID.GUID}}
                    $OutputData += $DumpedObject | Select-Object @{n="Object";e={$_.DistinguishedName}},@{n="AttributeName";e={$HistoryProp.AttributeName}},
                        @{n="AttributeValue";e={$red + $ValueFromDump + $reset}},@{n="LastOriginatingChangeTime";e={"-"}},@{n="LocalChangeUsn";e={"-"}},@{n="Version";e={"-"}},@{n="Explanation";e={$DumpExplanation}},@{n="ObjectGUID";e={$_.ObjectGUID.GUID}}
                    continue history
                    }
                ## If no old values - we continue foreach with next property
                if (!$OldRecords) {continue history}
                ## If we have old values, we get previous version (by USN) and place it in output
                ## Expressions for old value
                $RecentChange = ($OldRecords | Sort-Object -Property LocalChangeUsn -Descending)[0]
                $AttrOld = $RecentChange.AttributeValue
                #$Exp_Old = {$("{0}$AttrOld{1}" -f $yellow, $reset)}
                Write-Debug "Before OutputData write (history, no DampedAD)"
                #$OutputData += $RecentChange | Select-Object Object,AttributeName,@{n="AttributeValue";e=$Exp_old},LastOriginatingChangeTime,LocalChangeUsn,Version,Explanation,ObjectGUID
                $OutputData += $RecentChange | Select-Object Object,AttributeName,@{n="AttributeValue";e={$yellow + $AttrOld + $reset}},LastOriginatingChangeTime,LocalChangeUsn,Version,Explanation,ObjectGUID
                } ## history foreach ($HistoryProp in $ChangedProps)
            ############################################# 
            ##
            ## Collecting History
            ##
            #############################################            
            $USNDataWH += $ChangedProps
            if ($Output) {
                $CliXLMDataWH += $OutputData
                $CliXLMDataWH | Export-Clixml -Depth 5 -Path $Output -Force
                }
            ############################################# 
            ##
            ## Output
            ##
            #############################################
            ## Short output
            Write-Debug "Gotted all data. Output will be next"
            if ($Short) {
                $OutputData | format-table -Property @{Label='Object';Expression={$_.Object.TrimEnd($DomainDN)};Width=[int]($Host.UI.RawUI.WindowSize.Width/5)},
                    @{Label='AttributeName';Expression={$_.AttributeName};Width=[int]($Host.UI.RawUI.WindowSize.Width/5)},
                    @{Label='AttributeValue';Expression={$_.AttributeValue};Width=[int]($Host.UI.RawUI.WindowSize.Width/5)},
                    @{Label='LastOriginChangeTime';Expression={$_.LastOriginatingChangeTime};Width=[int]($Host.UI.RawUI.WindowSize.Width/5)},
                    @{Label='Explanation';Expression={$_.Explanation};Width=[int]($Host.UI.RawUI.WindowSize.Width/5)} -Wrap
                } ## if ($Shorts)
            ## Change out format
            elseif ($FormatList -AND !$Short) {
                $OutputData | format-list
                } ## if ($FormatList)
            else {
                $OutputData | format-table -Property @{Label='Object';Expression={$_.Object.TrimEnd($DomainDN)};Width=[int](($Host.UI.RawUI.WindowSize.Width - 77)/4)},
                    @{Label='AttributeName';Expression={$_.AttributeName};Width=[int](($Host.UI.RawUI.WindowSize.Width - 77)/5)},
                    @{Label='AttributeValue';Expression={$_.AttributeValue};Width=[int](($Host.UI.RawUI.WindowSize.Width - 77)/4)},
                    @{Label='LastOriginChangeTime';Expression={$_.LastOriginatingChangeTime};Width=20},
                    @{Label='LocalChangeUsn';Expression={$_.LocalChangeUsn};Width=14},
                    @{Label='Version';Expression={$_.Version};Width=7},
                    @{Label='Explanation';Expression={$_.Explanation};Width=[int](($Host.UI.RawUI.WindowSize.Width - 77)/5)},
                    @{Label='ObjectGUID';Expression={$_.ObjectGUID};Width=36} -Wrap
                } ## else
            } ## :changed_objects foreach 
        $DCOldUSN = $DCChangedUSN
        $DCChangedUSN = $null
        } ## if ($DCReplUTDV.USNFilter -gt $DCStartUSN)
    } ## :main for (;;)
} ## Invoke-ADSpider
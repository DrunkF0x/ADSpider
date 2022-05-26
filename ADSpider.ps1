###################################################################
###################################################################
Function Invoke-ADSpider(
[parameter(Mandatory=$true)][string]$DC,
[switch]$Credentials = $false,
[switch]$FormatList = $false,
[switch]$ExcludelastLogonTimestamp = $false,
[int]$Sleep = 20
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
      
       d8888 8888888b.   .d8888b.           d8b      888                  
      d88888 888  "Y88b d88P  Y88b          Y8P      888                  
     d88P888 888    888 Y88b.                        888                  
    d88P 888 888    888  "Y888b.   88888b.  888  .d88888  .d88b.  888d888 
   d88P  888 888    888     "Y88b. 888 "88b 888 d88" 888 d8P  Y8b 888P"   
  d88P   888 888    888       "888 888  888 888 888  888 88888888 888     
 d8888888888 888  .d88P Y88b  d88P 888 d88P 888 Y88b 888 Y8b.     888     
d88P     888 8888888P"   "Y8888P"  88888P"  888  "Y88888  "Y8888  888     
                                   888                                    
                                   888                                    
                                   888                                    

                                                             By DrunkF0x.
'
## Import module ActiveDirectory, if it does not import yet
if (!(Get-Module | Where-Object {$_.Name -eq "ActiveDirectory"})) {import-module ActiveDirectory}
## If we need, we set domain credentials
if ($Credentials) {
    $DomainCreds = Get-Credential
    } ## if ($Credentials)
## Domain Controller ip 
$DCIp = (Resolve-DnsName $DC).IPAddress
## Get first DC usn value
if ($Credentials) {
    $DCInvID = (Get-ADDomainController $DC -Server $DC -Credential $DomainCreds).InvocationID.Guid
    $DCStartReplUTDV = Get-ADReplicationUpToDatenessVectorTable $DC -EnumerationServer $DCIp -Credential $DomainCreds | where-object {$_.PartnerInvocationId.Guid -eq $DCInvID}
    } ## if ($Credentials)
else {
    $DCInvID = (Get-ADDomainController $DC -Server $DC).InvocationID.Guid
    $DCStartReplUTDV = Get-ADReplicationUpToDatenessVectorTable $DC -EnumerationServer $DCIp | where-object {$_.PartnerInvocationId.Guid -eq $DCInvID}   
    } ## else
$DCOldUSN = $DCStartReplUTDV.USNFilter
"Spider on AD Web now..."
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
            $ChangedObjects = Get-ADObject -Filter {usnchanged -gt $DCOldUSN} -Server $DC -Credential $DomainCreds
            } ## if ($Credentials)
        else {
            $ChangedObjects = Get-ADObject -Filter {usnchanged -gt $DCOldUSN} -Server $DC
            } ## else
        :changed_objects foreach ($Object in $ChangedObjects) {
            if ($Credentials) {            
                $Props = Get-ADReplicationAttributeMetadata $Object.DistinguishedName -Server $DC -Credential $DomainCreds -IncludeDeletedObjects -ShowAllLinkedValues
                } ## if ($Credentials)
            else {
                $Props = Get-ADReplicationAttributeMetadata $Object.DistinguishedName -Server $DC -IncludeDeletedObjects -ShowAllLinkedValues
                } ## else
            $ChangedProps = $Props | Where-Object {$_.LocalChangeUsn -gt $DCOldUSN} | 
                Select-Object Object,AttributeName,AttributeValue,LastOriginatingChangeTime,LocalChangeUsn,Version
            :props foreach ($Prop in $ChangedProps) {
                ## Adding new property for explaination about changes
                $Prop | Add-Member -MemberType NoteProperty -Name Explaination -Value $Null
                ## Add some human readable information
                switch ($Prop.AttributeName) {
                    ## convert number of userAccountControl to human format
                    "userAccountControl" {
                        $Prop.Explaination = Convert-UAC $Prop.AttributeValue
                        } ## "userAccountControl"
                    ## add or delete member from group
                    "member" {
                        if ($Prop.Version%2 -eq 1) {
                            $Prop.Explaination = "Added to group"
                            } ## if ($Prop.Version%2 -eq 0)
                        else {
                            $Prop.Explaination = "Deleted from group"
                            } ## else
                        } ## "member"
                    ## convert date & time to human format
                    {($_ -eq "lastLogonTimestamp") -or ($_ -eq "accountExpires") -or ($_ -eq "pwdlastset") -or ($_ -eq "lockoutTime") -or ($_ -eq "ms-Mcs-AdmPwdExpirationTime")} {
                        $Prop.Explaination = [DateTime]::FromFileTime($Prop.AttributeValue)
                        } ## "accountExpires", "pwdlastset"...
                    } ## switch
                } ## :props foreach ($Prop in $ChangedProps)
            ## Exclude lastLogonTimestamp events
            if ($ExcludelastLogonTimestamp) {
                $ChangedProps = $ChangedProps | Where-Object {$_.AttributeName -ne "lastLogonTimestamp"}
                }
            ## Change out format
            if (!$FormatList) {
                $ChangedProps | format-table -Wrap
                } ## if ($FormatList)
            else {
                $ChangedProps | format-list
                } ## else
            } ## :changed_objects foreach 
        $DCOldUSN = $DCChangedUSN
        $DCChangedUSN = $null
        } ## if ($DCReplUTDV.USNFilter -gt $DCStartUSN)
    } ## :main for (;;)
} ## Invoke-ADSpider
#Requires -RunAsAdministrator
<#
=======================================================================
       OnLife Post AD Script v1.0

          created by: Richard B. Hibbs
          created on: December 6th, 2018

    Purpose of this script is to:

   1.  Enable Bitlocker and save Recovery Password to a server
      location.

   2.  Install Local Administrator Password Software.

   3.  Install LogMeIn Unattended Install (backup purposes only).

   4.  Set Wallpaper and Lockscreens to OnLife Health backgrounds.

   5.  Log the PCs MAC address and save them to a server location.

   6.  Log the Dell Service Tag #s to a server location.

   7.  Set powersettings

   8.  Install the SCCM Client

   9.  Update the Task Schedule to run UserItems script

   This script is to be ran with admin privlages and is designed
 to run from task scheduler.  This script is to only run once per
 pc then the task scheduler is to be updated to run the user items
 script.

   Items still to be done in this file:

   >   Fix LAPS Quiet mode installation.

   >   Stored Credentials for full automation. (SCCM Install)

   >   Self Updating script. (requires working stored creds)


-----------------------------------------------------------------------

  Notes:  To be ran with Administrative Privlages

=======================================================================



-----------------------------------------------------------------------
                 Global Variables
-----------------------------------------------------------------------
Log Variable and function for entire script
it keeps a running log through out the script to out put to file
after script is done
#>
$logme =  @()

function logme {
Param (
        [string] $message
)
    $script:logme += $message
    Write-Host $message
}

Function Get-DellExpressServiceCode{
    <#
        .NOTES
        Author: John Tyndall (iTyndall.com)
        Version: 1.0.0.0
        .SYNOPSIS
        Gets a Dell Express Service Code from a Dell Service Tag.
        .DESCRIPTION
        The Get-DellExpressServiceCode cmdlet gets the Dell Express Service Code derived from a Dell Service Tag.
        A Dell Express Service Code is normally a 10-digit numeric number (i.e., a Base 10 numeral system), which is derived from a Dell Service Tag, which is normally a 5- to 7-digit alphanumeric number (i.e., a Base 36 numeral system). 
        .PARAMETER ServiceTag
        A Dell Service Tag (e.g., ABC1234).
        If this parameter is not provided, the Service Tag for the local system is used.
        .PARAMETER SkipSystemCheck
        The Get-DellExpressServiceCode is designed to get an Express Service Code from a Service Tag on Dell systems and checks the system manufacturer to ensure that it is a Dell.
        To bypass this system check, use the SkipSystemCheck switch.
        .INPUTS
        System.String. You can pipe one or more strings.
        .OUTPUTS
        System.Int64. This cmdlet returns a (long) integer. 
        .EXAMPLE
        Get-DellExpressServiceCode
        This commands gets the Express Service Code from the local system's Service Tag.
        .EXAMPLE
        Get-DellExpressServiceCode -SkipSystemCheck
        This command bypasses the system check (to see if the system is manufactured by Dell) and gets the Base 10 representation of the local system's serial number.
        If multiple Service Tags are passed, this system check is automatically bypassed.
        .EXAMPLE
        Get-DellExpressServiceCode ABC1234
        This commands gets the Express Service Code from a specified Service Tag (e.g., ABC1234): 22453156048
        .EXAMPLE
        "ABC1234", "XYZ5678" | Get-DellExpressServiceCode
        This command gets the Express Service Codes from an array of specified Service Tags (e.g., ABC1234, XYZ5678): 22453156048, 73948694948
        .LINK
        "Convert Dell Service Tag to Express Service Code" http://iTyndall.com/scripting/convert-dell-service-tag-to-express-service-code
    #>
    
    param(
        [Parameter(Mandatory=$False, Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, HelpMessage="A Dell Service Tag (e.g., ABC1234).")][System.String]$ServiceTag=(Get-WmiObject Win32_Bios).SerialNumber,
        [switch]$SkipSystemCheck
    )
    
        Begin{
            If($ServiceTag.Count > 1) {$SkipSystemCheck = $True}
        }
    
        Process{
    
            If([System.String]::IsNullOrEmpty($ServiceTag)) { Throw [System.Exception] "Could not retrieve system serial number." }
    
            If(-not $SkipSystemCheck){
                If((Get-WmiObject Win32_ComputerSystem).Manufacturer.ToLower() -notlike "*dell*") { Throw [System.Exception] "Dude, you don't have a Dell: $((Get-WmiObject Win32_ComputerSystem).Manufacturer)" }
            }
    
            $Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            $ca = $ServiceTag.ToUpper().ToCharArray()
            [System.Array]::Reverse($ca)
            [System.Int64]$ExpressServiceCode=0
        
            $i=0
            foreach($c in $ca){
                $ExpressServiceCode += $Alphabet.IndexOf($c) * [System.Int64][System.Math]::Pow(36,$i)
                $i+=1
            }
    
            $ExpressServiceCode
        }
    
        End{}
        
    }

#Get Current Computer Name
$thisComputer = hostname
#Get Current User Name
$thisUser = $env:username
#Set variable for date
$myDate = (Get-Date -Format 'yyyy-MM-dd')
#Set Script File (used to make sure this only runs once)
$scriptlog = "C:\temp\$thisComputer"
$scriptlog += "_$myDate"
$scriptlog += "_olh_postad_script_log.txt"

$logserver = "\\smartdeploy\deployments\pslogs\"

logme("PostAD Script")
logme("for $thisComputer")
logme("script ran on $myDate")
logme("$scriptlog")
logme("script ran by $thisUser")

$file = (Get-ChildItem -Path "C:\temp\*olh_postad_script_log*.txt" | Select Length).Length
if ($file -gt 0) {
    Write-Host "Script already ran for this computer, exiting..."
    Exit
}
else {
    Write-Host "Not completed for this computer, proceding..."
}


<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                 Script Self Updater
-----------------------------------------------------------------------
this part is not functional yet
this is too update the script file to what is centraly stored on 
the deployment servers
#>

<#
$LocalPreAd = "C:\temp\OLH_NewPCScripts_PreAD_v1.ps1"
$LocalPostAd = "C:\temp\OLH_NewPCScripts_PostAD_v1.ps1"
$LocalNewUser = "C:\temp\OLH_NewPCScripts_NewUser_v1.ps1"

$ServerPreAd = "\\smartdeploy\deployments\psfiles\OLH_NewPCScripts_PreAD_v1.ps1"
$ServerPostAd = "\\smartdeploy\deployments\psfiles\OLH_NewPCScripts_PostAD_v1.ps1"
$ServerNewUser = "\\smartdeploy\deployments\psfiles\OLH_NewPCScripts_NewUser_v1.ps1"

function Update-Script
{
    param
    (
        [string]$ServerPath,
        [string]$LocalPath
    )
    #check that the destination file exists
    if (Test-Path $ServerPath)
    {
    #The path of THIS script
        if (!($ServerPath -eq $LocalPath))
        {
            if ($(Get-Item $ServerPath).LastWriteTimeUtc -gt $(Get-Item $LocalPath).LastWriteTimeUtc)
            {
                write-host "Updating..."
                Copy-Item $ServerPath $LocalPath 
                #If the script was updated, run it with orginal parameters
                Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Unrestricted -File $localPath'
                #&$LocalPath
                exit
            }
        }
    }
    write-host "No update required"
}

#Update-Script $ServerPostAd $LocalPostAd
#Exit

#>
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
             Recall / Get Credentials
-----------------------------------------------------------------------
#>
<#
#sets key variable for auto creds
function Set-Key {
    param([string]$string)
    $length = $string.length
    $pad = 32-$length
    if (($length -lt 16) -or ($length -gt 32)) {Throw "String must be between 16 and 32 characters"}
    $encoding = New-Object System.Text.ASCIIEncoding
    $bytes = $encoding.GetBytes($string + "0" * $pad)
    return $bytes
}

$Key = Set-Key (Get-Content "C:\temp\key.txt")

function Test-Cred {
           
    [CmdletBinding()]
    [OutputType([String])] 
       
    Param ( 
        [Parameter( 
            Mandatory = $false, 
            ValueFromPipeLine = $true, 
            ValueFromPipelineByPropertyName = $true
        )] 
        [Alias( 
            'PSCredential'
        )] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()] 
        $Credentials
    )
    $Domain = $null
    $Root = $null
    $Username = $null
    $Password = $null
      
    If($Credentials -eq $null)
    {
        Try
        {
            $Credentials = Get-Credential "domain\$env:username" -ErrorAction Stop
        }
        Catch
        {
            $ErrorMsg = $_.Exception.Message
            Write-Warning "Failed to validate credentials: $ErrorMsg "
            Pause
            Break
        }
    }
      
    # Checking module
    Try
    {
        # Split username and password
        $Username = $credentials.username
        $Password = $credentials.GetNetworkCredential().password
  
        # Get Domain
        $Root = "LDAP://" + ([ADSI]'').distinguishedName
        $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
    }
    Catch
    {
        $_.Exception.Message
        Continue
    }
  
    If(!$domain)
    {
        Write-Warning "Something went wrong"
    }
    Else
    {
        If ($domain.name -ne $null)
        {
            return "Authenticated"
        }
        Else
        {
            return "Not authenticated"
        }
    }
}
#>
<#
use the following code to store the creds using the above key
 (works on same pc same user) 

$password = read-host -assecurestring | convertfrom-securestring -Key $Key | out-file "C:\temp\useme.txt" #- DOES NOT WORK
$autopass = Get-Content "C:\temp\useme.txt" | ConvertTo-SecureString -Key $Key
$autoCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "ghs\rhibbs_admin", $autopass
#>
<#
#store creds
$screds = Get-Credential ghs\rhibbs_admin
$exportObject = New-Object psobject -Property @{
    UserName = $screds.UserName
    Password = ConvertFrom-SecureString -SecureString $screds.Password -Key $key
}
$exportObject | Export-Clixml -Path "C:\temp\useme.xml"

#recall creds
$importObject = Import-Clixml -Path "C:\temp\useme.xml"
$secureString = ConvertTo-SecureString -String $importObject.Password -Key $key
$autocreds = New-Object System.Management.Automation.PSCredential($importObject.UserName, $secureString)

#Cred check
$autoCheck = $autoCreds | Test-Cred
$autoCheck
#>
$creds = Get-Credential olh\richard_hibbs
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Enable BitLocker and Output Recovery Key
-----------------------------------------------------------------------
The purpose for the following script is to enable TMP, start the
BitLocker process with TMP, and save the recovery password to a server
location

   TESTED: WORKS:  DO NOT ALTER

#>
logme("")
logme("Starting BitLocker in 10 seconds!")

Sleep -Seconds 10

$TPM = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | where {$_.IsEnabled().Isenabled -eq 'True'} -ErrorAction SilentlyContinue
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

 
#If all of the above prequisites are met, then create the key protectors, then enable BitLocker and backup the Recovery key to AD.
if ($WindowsVer -and $TPM -and $BitLockerReadyDrive) {
 
    #Creating the recovery key
    logme("Created the recovery key")
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector
 
    #Adding TPM key
    logme("adding tpm key")
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector
    sleep -Seconds 15 #This is to give sufficient time for the protectors to fully take effect.
 
    #Enabling Encryption
    logme("enabling encryption")
    Start-Process 'manage-bde.exe' -ArgumentList " -on $env:SystemDrive" -Verb runas -Wait
 
    #Getting Recovery Key GUID
    logme("saving recovery key")
    $RecoveryKeyGUID = (Get-BitLockerVolume -MountPoint $env:SystemDrive).keyprotector | where {$_.Keyprotectortype -eq 'RecoveryPassword'} | Select-Object -ExpandProperty KeyProtectorID
    $putBitLockerKeyHere = "\\corp-file.ghs\is$\Helpdesk Documentation\Bit Locker keys\" + $thisComputer + "-" + $myDate + "-BitLocker_Recovery_Key.txt"
    logme("saving file to $putBitLockerKeyHere")
    $Recoverykey = (Get-BitLockerVolume -MountPoint $env:SystemDrive).keyprotector.RecoveryPassword
    $Recoverykey | Out-File $putBitLockerKeyHere

    #Backing up the Recovery to AD.
    logme("backing up recovery key to AD")
    manage-bde.exe -protectors -adbackup $env:SystemDrive -id $RecoveryKeyGUID
}
else {
    logme("failed to start bitlocker, find out why...")
}

Sleep -Seconds 2
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Install Laps
-----------------------------------------------------------------------
The purpose for the following script is to install Local Admin Password
Solution on pc.

   TESTED: no longer installs quietly

#>
logme("")
logme("Installing LAPS")

$lapsFile = "\\smartdeploy\deployments\installme\LAPS.x64.msi"

try {
    if (Test-Path($lapsFile)) {
        msiexec /q /i $lapsFile
        #Start-Process $lapsFile /qn -Wait    Commented out to test the line above
        logme("Installed LAPS")
    }
    else {
        logme("could not find installer file")
    }
}
catch
{
    logme("Failed to install LAPS")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}
Sleep -Seconds 2
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Install Rescue Assist
-----------------------------------------------------------------------
The purpose for the following script is to install the Rescue Assist
client as backup to remote into machine

   TESTED: WORKS:  DO NOT ALTER

#>
logme("")
logme("Installing LogMeIn RescueAssist")

$raFile = "\\smartdeploy\deployments\installme\LogMeIn_RescueAssist_Unattended.msi"

try {
    if (Test-Path($raFile)) {
        Start-Process $raFile /qn -Wait
        logme("Installed LogMeIn RescueAssist")
    }
    else {
        logme("could not find installer file")
    }
}
catch
{
    logme("Failed to install LogMeIn RescueAssist")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}
Sleep -Seconds 2
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Setting Wallpaper and Lockscreen
-----------------------------------------------------------------------
The purpose for the following script is to set the users wallpaper and
lockscreen to OnLife Health default to start the user out.

   TESTED: WORKS:  DO NOT ALTER

#>
logme("")

#Variables
$localjpg = "C:\Users\Public\Pictures\onlife-latitude_1280x800wallpaper.jpg"
$serverjpg = "\\smartdeploy\deployments\installme\onlife-latitude_1280x800wallpaper.jpg"
$wpreg = "HKCU:\Control Panel\Desktop\"
$lsreg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"

#Test if jpg file exists (to be added later)
Try
{
    If(!(Test-Path $localjpg))
    {
        logme("no local jpg, going to server...")
        #Copies from netlogon if exists
        If((Test-Path $serverjpg))
        {
            logme("getting jpg from server...")
            Copy-Item $serverjpg -Destination $localjpg
            Sleep -Seconds 2
        }
    }
    Else
    {
        logme("local jpg found, setting...")
    }
}
Catch
{
    logme("Error coping jpg")
}

#Sets wallpaper
Try
{
    logme("setting wallpaper...")
    Set-ItemProperty -Path $wpreg -name wallpaper -value $localjpg
    rundll32.exe user32.dll, UpdatePerUserSystemParameters
}
Catch
{
    logme("Error setting Wallpaper")
    Exit    
}

logme("Setting Wallpaper Completed!")
Sleep -Seconds 2
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Outputing Mac IDs
-----------------------------------------------------------------------
The purpose for the following script is to record and save the MAC IDs
to a server location.

   TESTED: WORKS:  DO NOT ALTER

#>
logme("")
logme("Getting Mac Address for this computer...")

#Set variable for output file
$putMacIDsHere = "\\corp-file\is$\Helpdesk Documentation\MacAddresses\" + $thisComputer + "_" + $myDate + "_MAC_List.txt"
#Write-Host $putMacIDsHere
#Sleep -Seconds 10
#Output the Mac IDs
logme("sending file to $putMacIDsHere")
Get-NetAdapter | select InterfaceDescription,MacAddress | ForEach-Object {$_ -Replace "-",":"} | ForEach-Object {$_ -Replace "@",""} | ForEach-Object {$_ -Replace "{",""} | ForEach-Object {$_ -Replace "}",""} | ForEach-Object {$_ -Replace "InterfaceDescription=",""} | Out-File $putMacIDsHere
logme("Getting Mac Address Completed!")
Sleep -Seconds 2
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Outputing Dell Service Tags
-----------------------------------------------------------------------
The purpose for the following script is to record and save the Dell
Service Tags to a server location.

   TESTED: WORKS:  DO NOT ALTER

#>
logme("")
logme("Getting Dell Service Tags for this computer...")

#Set variable for output file
$putDSTHere = "\\corp-file\is$\Helpdesk Documentation\DellServiceTags\" + $thisComputer + "_" + $myDate + "_Dell_Server_Tags.txt"
#Output the Service Tags
logme("sending file to $putDSTHere")
$dellServiceTag = (Get-WmiObject Win32_BIOS | select serialnumber).Serialnumber
$dellExpressServiceTag = Get-DellExpressServiceCode $dellServiceTag
$dellTags = "Service Tag: $dellServiceTag"
$dellTags += ""
$dellTags += "Express Service Tag: $dellExpressServiceTag"
$dellTags | Out-File $putDSTHere

logme("Getting Dell Service Tags Completed!")
Sleep -Seconds 2
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Setting the Power Settings (Lid Close)
-----------------------------------------------------------------------
The purpose for the following script is to set the users power settings
to sleep when buttons pressed and stay on with lid closed.

   TESTED: WORKS:  DO NOT ALTER

#>
logme("")
logme("Setting Power Settings")

#On Battery / When I press the power button: to sleep
try
{
    logme("Setting On Battery Power Button Press to Sleep")
    powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 1
    logme("On Battery Power Button Press to Sleep Set")
    Sleep -Seconds 3
}
catch
{
    logme("Failed to set On Battery Power Button Press to Sleep")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}

#Plugged in / When I press the power button: to sleep
try
{
    logme("Setting Plugged In Power Button Press to Sleep")
    powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 1
    logme("Plugged In Power Button Press to Sleep Set")
    Sleep -Seconds 3
}
catch
{
    logme("Failed to set Plugged In Power Button Press to Sleep")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}

#On Battery / When I press the sleep button: to sleep
try
{
    logme("Setting On Battery Sleep Button Press to Sleep")
    powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 1
    logme("On Battery Sleep Button Press to Sleep Set")
    Sleep -Seconds 3
}
catch
{
    logme("Failed to set On Battery Sleep Button Press to Sleep")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}

#Plugged in / When I press the sleep button: to sleep
try
{
    logme("Setting Plugged In Sleep Button Press to Sleep")
    powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 1
    logme("Plugged In Sleep Button Press to Sleep Set")
    Sleep -Seconds 3
}
catch
{
    logme("Failed to set Plugged In Sleep Button Press to Sleep")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}

#On battery / When I Close the lid: to do nothing
try
{
    logme("Setting On Battery Close the lid to do nothing")
    powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    logme("On Battery Close the lid to do nothing Set")
    Sleep -Seconds 3
}
catch
{
    logme("Failed to set On Battery Close the lid to do nothing")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}

#Plugged In / When I Close the lid: to do nothing
try
{
    logme("Setting Plugged In Close the lid to do nothing")
    powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    logme("Plugged In Close the lid to do nothing Set")
    Sleep -Seconds 3
}
catch
{
    logme("Failed to set Plugged In Close the lid to do nothing")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Installing SCCM
-----------------------------------------------------------------------
The purpose for the following script is to trigger the SCCM Client
installation

   TESTED: WORKS:  DO NOT ALTER

#>
logme("")
logme("Installing SCCM")

#Set variable for output file
$siteID = "S01"

    Invoke-Command -ComputerName "cabrw-sccm01.olh.local" -Credential $creds -ScriptBlock {
        $thisComputer = $using:thisComputer
        $siteID = $using:siteID
        Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'
        Set-Location 'S01:' 
        Install-CMClient -DeviceName $thisComputer -SiteCode $siteID -AlwaysInstallClient $true -ForceReinstall $true -Verbose
        }

<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Make changes to Scheduled Task
-----------------------------------------------------------------------
#purpose of this part is to update the scheduled task that ran this
#script to run the next script (PostAD)
#>
logme("")
Logme("Making changes to Scheduled Task")

#Scheduled Task Items
#Add Post AD task
# The Task Action command
$newE = "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
# The PowerShell script to be executed
$TaskScript = "C:\temp\OLH_NewPCScripts_UserItems_v1.ps1 -WindowStyle Hidden"
# The Task Action command argument
$newA = "$TaskScript"

try {
    logme("Setting Scheduled Task new arguments")
    $newAction = New-ScheduledTaskAction -Execute $newE -Argument $newA
}
catch {
    logme("Setting Scheduled Task new arguments failed")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}

try {
    logme("Updating task schedule to run User Items script")
    Set-ScheduledTask -TaskName "PreAd" -Action $newAction
}
catch {
    logme("Setting Scheduled Task new arguments failed")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}

<#
-----------------------------------------------------------------------
#>

logme("")
logme("Cleaning up")
logme("coping pre ad log to $logserver")
$preadlogfile = "C:\temp\*olh_pread_script_log*"
Copy-Item -Path $preadlogfile -Destination $logserver

#logme("removing pre ad script file")
#if (Test-Path(C:\temp\OLH_NewPCScripts_PreAD_v1.ps1)) {
#    Remove-Item C:\temp\OLH_NewPCScripts_PreAD_v1.ps1 -Force
#}


logme("Computer will reboot in ~30 seconds!")
logme("Post AD script completed $myDate")

$logme | Out-File $scriptlog
Sleep -Seconds 5

if (Test-Path($scriptlog)) {
    Copy-Item -Path $scriptlog -Destination $logserver
}

Sleep -Seconds 5

#if (Test-Path(C:\temp\OLH_NewPCScripts_PostAD_v1.ps1)) {
#    Remove-Item C:\temp\OLH_NewPCScripts_PostAD_v1.ps1 -Force
#}

Sleep -Seconds 20

Restart-Computer -Force
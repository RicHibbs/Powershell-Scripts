<#
=======================================================================
       OnLife New User Profile PC Script v1.0

          created by: Richard B. Hibbs
          created on: December 6th, 2018

    Purpose of this script is to:

   1.  Set users wallpaper and lockscreen.

   2.  Set users power settings.

   3.  Activate office for user (not required for office365).

   4.  Install Corp-Uniflow Printer.

   5.  Remove unused Windows 10 software and pin items to taskbar.

   6.  Open outlook to setup users profile.

   This script is to be ran with admin privlages and is designed
 to run from task scheduler.  This script is to only run once per
 pc then the task scheduler is to be updated to run the user items
 script.

   Items still to be done in this file:

   >   Stored Credentials

   >   Saving User Log file to server (requires working stored creds)

   >   Self Updating script. (requires working stored creds)


-----------------------------------------------------------------------

  Notes:  To be ran as user

=======================================================================



-----------------------------------------------------------------------
                 Global Variables
-----------------------------------------------------------------------

#>
#Log Variable
$logme =  @()

function logme {
Param (
        [string] $message
)

    $script:logme += $message
    Write-Host $message

}

#Get Current Computer Name
$thisComputer = hostname
#Get Current User Name
$thisUser = $env:username
#Set variable for date
$myDate = (Get-Date -Format 'yyyy-MM-dd')
#Set Script File (used to make sure this only runs once)
$scriptlog = "C:\temp\$thisUser"
$scriptlog += "_$myDate"
$scriptlog += "_$thisComputer"
$scriptlog += "_olh_user_script_log.txt"

logme("New User Script")
logme("for $thisUser on $thisComputer")
logme("script ran on $myDate")
logme("$scriptlog")

$logserver = "\\smartdeploy\deployments\pslogs\"

$file = (Get-ChildItem -Path "C:\temp\*$thisUser*olh_user_script_log*.txt" | Select Length).Length
if ($file -gt 0) {
    Write-Host "Script already ran for this user, exiting..."
    Exit
}
else {
    Write-Host "Not completed for this user, proceding..."
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

#Update-Script $ServerNewUser
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Copy Default Bookmarks
-----------------------------------------------------------------------
#>
#logme("")
#logme("Coping default internet bookmarks to Google Chrome")

#$bmfile = "Bookmarks.bak"
#$default_bmloc = ""
#$user_bmloc = "C:\Users\$thisUser\AppData\Local\Google\Chrome\UserData\Default\"


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
logme("Setting Wallpaper and Lockscreen")
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
        Write-Host "no local jpg, going to server..."
        #Copies from netlogon if exists
        If((Test-Path $serverjpg))
        {
            Write-Hose "getting jpg from server..."
            Copy-Item $serverjpg -Destination $localjpg
            Start-Sleep -Seconds 2
        }
    }
    Else
    {
        Write-Host "local jpg found, setting..."
    }
}
Catch
{
    Write-Host "Error coping jpg"
    Exit
}

#Sets wallpaper
Try
{
    Write-Host "setting wallpaper..."
    Set-ItemProperty -Path $wpreg -name wallpaper -value $localjpg
    rundll32.exe user32.dll, UpdatePerUserSystemParameters
}
Catch
{
    logme("Error setting Wallpaper")
    Exit    
}

logme("Setting Wallpaper Completed!")
Start-Sleep -Seconds 2
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

#Variables
#Set-Variable -Name currentPowercfg -Value "4f971e89-eebd-4455-a8de-9e59040e7347"
#Set-Variable -Name powerButtonID -Value "7648efa3-dd9c-4e3e-b566-50f929386280"
#Set-Variable -Name sleepButtonID -Value "96996bc0-ad50-47ec-923b-6f41874dd9eb"
#Set-Variable -Name lidID -Value "5ca83367-6e45-459f-a27b-476b1d01c936"

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
           Checking Office Activation Status, Activate if not
-----------------------------------------------------------------------
#>
logme("")
logme("Checking Office Activation Status...")
$okey = "8VXMN-TTYFG-YCXDC-PKC4Q-49CQy"
$ostatus = "unknown"

$ostatus = cscript "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /dstatus | Where-Object {$_ -match 'LICENSE STATUS:'} | ForEach-Object {$_ -replace 'LICENSE STATUS:  ',''} | ForEach-Object {$_ -replace '-',''}

try {
    #if(!($ostatus="LICENSED"))
    #{
        logme("Office Is Not Activate, Installing Key and Activating...")
        cscript /b "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /inpkey:$okey
        cscript /b "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /actype:2
        cscript /b "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /act
    #}
    #Else
    #{
    #    Write-Host "Office is Activated..."
    #}
}
catch 
{
    logme("Office Activation Errored...")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3

    #cscript "C:\Program Files\Microsoft Office\Office16\ospp.vbs" /ddescr:0x80072EE7
}
Sleep -Seconds 3
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Install Uniflow Printer
-----------------------------------------------------------------------
#>
logme("")
logme("Setting up Corp Uniflow Printer")

#Get-PrinterDriver | Format-Table -AutoSize
#Get-Printer | Format-Table -AutoSize
#Remove-PrinterDriver -Name $pdname

$pname = "\\CORP-UNIFLOW.ghs\Universal Secure Print"
#$pcname = "CORP-UNIFLOW.ghs"
#$pdname = "Canon iR-ADV C5250/5255 PCL5c"
#$pdloc = "C:\temp\Uniflow_Driver\UFRII_V30.30_Set-up_x64\Driver"

#Add-PrinterDriver -Name $pdname -InfPath $pdloc
#$printer = $false
#$printer = Get-Printer -Name $pname
#$printer

try {
    logme("Adding Corp-Uniflow Printer")
    Add-Printer -ConnectionName $pname -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
    logme("Printer added")
}
catch
{
    logme("Added Corp Uniflow Printer Errored...")
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    logme($ErrorMessage)
    logme($FailedItem)
    Sleep -Seconds 3
}
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Pin/Unpin Applications to the Taskbar
-----------------------------------------------------------------------
#>
logme("")
logme("Setting up Taskbar")

logme("Removing Windows Store")
Get-AppxPackage *windowsstore* | Remove-AppxPackage -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
Sleep -Seconds 5

logme("Removing Windows Mail")
Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
Sleep -Seconds 5

logme("Removing Windows Maps")
Get-AppxPackage *windowsmaps* | Remove-AppxPackage -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
Sleep -Seconds 5

logme("Removing Bing Finance")
Get-AppxPackage *bingfinance* | Remove-AppxPackage -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
Sleep -Seconds 5

logme("Removing Xbox Items (there will be errors here)")
Get-AppxPackage *xbox* | Remove-AppxPackage -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
Sleep -Seconds 5

logme("Removing Windows Alarms")
Get-AppxPackage *windowsalarms* | Remove-AppxPackage -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
Sleep -Seconds 5

logme("Removing Zune Items")
Get-AppxPackage *zune* | Remove-AppxPackage -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
Sleep -Seconds 5


function olh-pin {
param (
    [parameter(Mandatory=$True, HelpMessage="Target item to pin")]
    [ValidateNotNullOrEmpty()]
    [string] $Target
)
if (!(Test-Path $Target)) {
    logme("$Target does not exist")
    break
}

$KeyPath1  = "HKCU:\SOFTWARE\Classes"
$KeyPath2  = "*"
$KeyPath3  = "shell"
$KeyPath4  = "{:}"
$ValueName = "ExplorerCommandHandler"
$ValueData =
    (Get-ItemProperty `
        ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\" + `
            "CommandStore\shell\Windows.taskbarpin")
    ).ExplorerCommandHandler

$Key2 = (Get-Item $KeyPath1).OpenSubKey($KeyPath2, $true)
$Key3 = $Key2.CreateSubKey($KeyPath3, $true)
$Key4 = $Key3.CreateSubKey($KeyPath4, $true)
$Key4.SetValue($ValueName, $ValueData)

$Shell = New-Object -ComObject "Shell.Application"
$Folder = $Shell.Namespace((Get-Item $Target).DirectoryName)
$Item = $Folder.ParseName((Get-Item $Target).Name)
$Item.InvokeVerb("{:}")

$Key3.DeleteSubKey($KeyPath4)
if ($Key3.SubKeyCount -eq 0 -and $Key3.ValueCount -eq 0) {
    $Key2.DeleteSubKey($KeyPath3)
}
}

logme("Adding Cisco AnyConnect")
olh-pin -Target "C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"
Sleep -Seconds 1

logme("Adding Google Chrome")
olh-pin -Target "C:\Program Files (x86)\Google\Chrome\Application\Chrome.exe"
Sleep -Seconds 1

logme("Adding MS Outlook 2016")
olh-pin -Target "C:\Program Files\Microsoft Office\Office16\OUTLOOK.exe"
Sleep -Seconds 1

logme("Adding PureCloud")
olh-pin -Target "C:\Program Files (x86)\Interactive Intelligence\PureCloud\PureCloud.exe"
Sleep -Seconds 1

$isAdmin = ((new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Domain Admins") -or (new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("AD Limited Admins"))

if ($isAdmin) {

    #The following part forces control panel into the classic view
    $RegKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies"
    If(Test-Path ($RegKey + "\Explorer")) {
        $RegKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        ##Enabled
        New-ItemProperty -path $RegKey -name ForceClassicControlPanel -value 1 -PropertyType DWord -Force
        ##Disabled
        ##New-ItemProperty -path $RegKey -name ForceClassicControlPanel -value 0 -PropertyType DWord -Force
    }
    else {
        New-Item -path $RegKey -name Explorer
        RegKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        ##Enabled
        New-ItemProperty -path $RegKey -name ForceClassicControlPanel -value 1 -PropertyType DWord
        ##Disabled
        ##New-ItemProperty -path $RegKey -name ForceClassicControlPanel -value 0 -PropertyType DWord
    }

    logme("Adding Control Panel")
    olh-pin -Target "C:\Windows\System32\control.exe"
    Sleep -Seconds 1

    logme("Adding Software Center")
    olh-pin -Target "C:\WINDOWS\CCM\ClientUX\SCClient.exe"
    Sleep -Seconds 1

    logme("Adding Task Scheduler")
    olh-pin -Target "C:\Windows\System32\taskschd.msc"
    Sleep -Seconds 1

    logme("Adding Powershell ISE")
    olh-pin -Target "c:\windows\system32\WindowsPowerShell\v1.0\powershell_ise.exe"
    Sleep -Seconds 1
}
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Open Outlook to setup
-----------------------------------------------------------------------
#>
$outlook = "C:\Program Files\Microsoft Office\Office16\OUTLOOK.EXE"
if (!($isAdmin)) { Start-Process -FilePath $outlook }
<#
-----------------------------------------------------------------------
#>

logme("New user script completed $myDate")

$logme | Out-File $scriptlog
Sleep -Seconds 5

if (Test-Path($scriptlog)) {
    Copy-Item -Path $scriptlog -Destination $logserver
}

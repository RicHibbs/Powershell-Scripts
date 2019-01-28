#Requires -RunAsAdministrator
<#
=======================================================================
       OnLife PreAD Script v1.0

          created by: Richard B. Hibbs
          created on: December 6th, 2018

    Purpose of this script is to disable Cortana and join pc to
 the GHS domain and into the correct pc container.

   This script is to be ran with admin privlages and is designed
 to run from task scheduler.  This script is to only run once per
 pc then the task scheduler is to be updated to run the post ad
 script.

   Items still to be done in this file:

   >   Stored Credentials for full automation. (GHS Join Domain)

   >   Self Updating script (requires working stored creds)

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

#Get Current Computer Name
$thisComputer = hostname

if ($thisComputer -like "*IMAGE*") {
    Exit
}

#Get Current User Name
$thisUser = $env:username
#Set variable for date
$myDate = (Get-Date -Format 'yyyy-MM-dd')
#Set Script File (used to make sure this only runs once)
$scriptlog = "C:\temp\$thisComputer"
$scriptlog += "_$myDate"
$scriptlog += "_olh_pread_script_log.txt"

#start of logging (header)
logme("PreAD Script")
logme("for $thisComputer")
logme("script ran on $myDate")
logme("$scriptlog")

#this is to double check to make sure that this script only runs the once per computer
$file = (Get-ChildItem -Path "C:\temp\*olh_pread_script_log*.txt" | Select Length).Length
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

#Update-Script $ServerPreAd
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
$creds = Get-Credential ghs\rhibbs_admin
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Disable Cortana
-----------------------------------------------------------------------
purpose for this section is to disable cortana machine wide if not
already done so.

  TESTED: WORKS:  DO NOT ALTER

#>
logme("")
logme("Disabling Cortana")

$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"    
if(!(Test-Path -Path $path)) { 
    logme("creating registry key")
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Windows Search"
    Sleep -Seconds 2
} 

$cortana = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana"

if(!($cortana.AllowCortana -eq 0)) {
    logme("setting value to disable Cortana")
    Set-ItemProperty -Path $path -Name "AllowCortana" -Value 0
    Sleep -Seconds 2
    logme("starting explorer")
    Stop-Process -name explorer
    Sleep -Seconds 2
    logme("Cortana disabled")
}
else {
    logme("Cortana was already disabled!")
}

Sleep -Seconds 2
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Join GHS Domain and move to correct ou
-----------------------------------------------------------------------
purpose for this section is to test if computer is not apart of a
domain to verify and/or change pc name, join GHS and put in the 
correct OH for all new computers.

  TESTED: WORKS:  DO NOT ALTER

#>

logme("")
Logme("Joining computer to GHS Domain")

#Variables
$targetOU = "OU=USB Storage Block GP,OU=MBAM,OU=PCs,DC=ghs"

#Check Computer Name with Scrip runner
$defaultV = $thisComputer
$prompt = Read-Host "Press Enter to use [$($defaultV)] or enter new name:"
$prompt = ($defaultV,$prompt)[[bool]$prompt]

logme("Using $prompt for computer name")

#changing computer name if different and then joining domain
if(!($prompt -eq $thiscomputer)) {
    $oldname = $thisComputer
    $thisComputer = $prompt
    logme("updated computer name to $prompt")
    $scriptlog = "C:\temp\$thisComputer"
    $scriptlog += "_$myDate"
    $scriptlog += "_olh_pread_script_log.txt"

    try {
        if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $false) {
            Add-Computer -DomainName "ghs" -ComputerName $oldname -NewName $prompt -OUPath $targetOU -Credential $creds
            logme("Joined domain success")
        }
        else {
            logme("computer already on domain")
        }
    }
    catch {
        logme("Joined failed")
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        logme($ErrorMessage)
        logme($FailedItem)
        Sleep -Seconds 3
    }    

}
else {
    try {
        if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $false) {
            Add-Computer -DomainName "ghs" -OUPath $targetOU -Credential $creds
            logme("Joined domain success")
        }
        else {
            logme("computer already on domain")
        }
    }
    catch {
        logme("Joined failed")
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        logme($ErrorMessage)
        logme($FailedItem)
        Sleep -Seconds 3
    }    
}


Sleep -Seconds 2
<#
-----------------------------------------------------------------------



-----------------------------------------------------------------------
                Make changes to Scheduled Task
-----------------------------------------------------------------------
purpose of this part is to update the scheduled task that ran this
script to run the next script (PostAD)

Scheduled Task Items
Add Post AD task

   TESTED: WORKS:  DO NOT ALTER

#>

logme("")
Logme("Making changes to Scheduled Task")

# The Task Action command
$newE = "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
# The PowerShell script to be executed
$TaskScript = "C:\temp\OLH_NewPCScripts_PostAD_v1.ps1"
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
    logme("Updating task schedule to run PostAD script")
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


logme("PreAD script completed $myDate")

#output the script wide log file
$logme | Out-File $scriptlog

Sleep -Seconds 30
#restarts the computer for pc name change and domain join to take effect
Restart-Computer -Force
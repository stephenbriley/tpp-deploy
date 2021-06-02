<#
//
// Copyright (c) 2019 Venafi, Inc.  All rights reserved.
//
// Venafi, Inc. hereby grants you limited permission to use and modify this software during only the period in which you
// hold a valid license from Venafi, Inc. to use the Venafi Trust Protection Platform, on condition that (a) such use or
// modification is for your sole internal business use, and (b) you hereby assign to Venafi, Inc. all rights in any
// modifications of this software that you may create (and agree to take all such actions as may be necessary and desirable
// to perfect such assignment), except that you (i) shall retain any Background Intellectual Property that you may
// incorporate into any such modifications and (ii) hereby agree to grant Venafi, Inc., a perpetual, worldwide, royalty
// free license to use, copy, modify, reproduce, distribute such modifications, including, without limitation, any
// Background Intellectual Property incorporated into such modifications. For the purposes of this paragraph, “Background
// Intellectual Property” means any intellectual property developed by you independently of this software (or any
// modifications thereof). You may not copy, reproduce or distribute this software (or any modifications thereof) without
// the prior written consent of Venafi, Inc. (which may be by email). Without limiting the foregoing, the above copyright
// notice, this paragraph and the following paragraph must appear in all copies, modifications, reproductions, and
// distributions of this software.
// IN NO EVENT SHALL VENAFI, INC., ITS DIRECTORS, OFFICERS, EMPLOYEES, AGENTS, OR AFFILIATES BE LIABLE TO ANY PARTY FOR
// DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS
// SOFTWARE OR ITS DOCUMENTATION, IF ANY, EVEN IF VENAFI, INC. HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
// VENAFI, INC. SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, ANY IMPLIED WARRANTIES OF
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. THIS SOFTWARE, ALONG WITH ITS DOCUMENTATION, IF ANY, IS PROVIDED
// "AS IS". VENAFI, INC. HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, OR UPDATES FOR THE SOFTWARE OR ITS
// DOCUMENTATION, IF ANY.
//
Author: Chris Lyttle (Chris.Lyttle@venafi.com)
Venafi Professional Services
Version 3.1

.SYNOPSIS
   Script to check if the Venafi Platform Prerequisites are installed
.DESCRIPTION
   This script is designed to check for the following prerequisites before installing
   the Venafi Platform;
   a) Microsoft Windows Server 2012 R2, 2016 or 2019
   b) .NET Framework 4.6.1 (TPP17.x), or 4.6.2 (TPP18.x), or 4.7.2 (TPP19.x,TPP20.x) and .NET 3.5 (Required)
   c) Universal C Runtime Update only on 2012R2
   d) TPP Required Server Roles & Features
   e) Microsoft URL Rewrite Module 2.1
   f) Powershell version is <= 5.0
   g) Connect to SQL server with DBO Account to gather infomation about Venafi DB, roles and availability groups
   h) If server requires a reboot.

   There is an optional parameter 'Install' that will install the following;
   a) Missing Roles and Features
   b) If .NET is missing or insufficient version, .NET 4.7.2
   c) URL Rewrite Module for IIS v2.1
   d) Remove IIS 'Default Web Site'
   e) If no Internet connection is available, will prompt for the location of the above files
   f) If Roles or Features were removed, will download from Windows Update

   With no parameters, the script will not check the SQL connection.
   There is also an optional parameter to only do the SQL checks.
   All SQL checks require downloading and installing DBA Tools module from the PSGallery. If there is no
   internet connection, please preinstall manually to use this.
   SQL Checks do _NOT_ require sysadmin on SQL, only the db_owner role.

   NOTE that this does not install the Universal C Runtime update on Windows Server 2012 R2 as that is
   delivered via Windows Update. Also 2012 R2 is required to update to PowerShell 5.0 or better to run this.

.PARAMETER SQLOnly
   (Optional) Only run SQL checks. Installs DBA tools.
.PARAMETER SQL
   (Optional) Run the SQL checks after checking other items. Installs DBA tools.
.PARAMETER SQLserver
   (Required) Computer name of the SQL server. Required if -SQL or -SQLOnly is used.
.PARAMETER Database
   (Required) Database name on the SQL server. Required if -SQL or -SQLOnly is used.
.PARAMETER Install
   (Optional) If feature is not installed, install it and all applicable management tools.
   Will also download & install items if missing locally (or removed).
.PARAMETER NonIIS
   (Optional) Only install non-IIS features required by the Venafi installer. Allows for a box without IIS.
   Can be combined with the install switch. If used 'Default Web Site' is not removed.
.EXAMPLE
PS C:\> .\Venafi-PreReq-Check.ps1 -SQLOnly -SQLserver harley -Database TrustForce
Install DBA Tools
Checking SQL requires installing the DBA Tools package, enter Yes to agree or no to abort installation
[Y] Yes - Agree  [N] No - Abort  [?] Help (default is "Y"):
Installing NuGet
Installing DBA Tools modules
==========================SQL Server Information=================================

SQL Server FQDN: harley.pki-warrior.com
SQL Instance:  HARLEY\SQLEXPRESS
SQL Version: SQL 2016
Edition: Express Edition (64-bit)
SQL Product Level: SP1
SQL Server OS: Microsoft Windows Server 2019 Standard
SQL Server Processors: 2
SQL Server Logical Processors: 2
SQL Server Memory: 16.00 GB
SQL Server Availability Group: Availability Group not configured
SQL Server Availability Group Listener: No Availability Group Listeners

=================================================================================

=======================SQL Database User Information=============================

UserName       :  PKI-WARRIOR\venafi-sqluser
Login          :  PKI-WARRIOR\venafi-sqluser
Login Type     :  WindowsUser
Database Name  :  TrustForce
Server Role    :  db_datareader

UserName       :  PKI-WARRIOR\venafi-sqluser
Login          :  PKI-WARRIOR\venafi-sqluser
Login Type     :  WindowsUser
Database Name  :  TrustForce
Server Role    :  db_datawriter

UserName       :  dbo
Login          :  PKI-WARRIOR\venafi-sql
Login Type     :  WindowsUser
Database Name  :  TrustForce
Server Role    :  db_owner

=================================================================================
.EXAMPLE
PS C:\Users\clyttle\Desktop> .\Venafi-PreReq-Check.ps1
Checking ANISSA for 64-bit PowerShell
You are running 64-bit PowerShell

Checking ANISSA for Server OS version
Windows Server 2019 is compatible but not supported yet

TPP Version
Select which TPP Version you are installing
[1] 1 - 17.x  [2] 2 - 18.x  [3] 3 - 19.x  [4] 4 - 20.x  [?] Help (default is "4"):

Windows Edition
Select which Windows Edition you are installing
[1] 1 - Standard  [2] 2 - Datacenter  [?] Help (default is "1"):
Checking ANISSA for required .Net Frameworks
Cannot find .Net Framework version 3.5, please install using the -Install switch
You have .NET Framework version 4.7.2 Installed on Microsoft Windows Server 2019 Standard
You have the correct .NET Framework to install the Venafi Platform

Checking ANISSA for Universal C Runtime Update
Universal C Runtime Update is installed

Checking ANISSA for required Roles and Features
Checking All Roles Installed
Importing Server Manager
Feature .NET Framework 3.5 (includes .NET 2.0 and 3.0) was removed from server ANISSA
Feature .NET Framework 4.7 is installed on server ANISSA
Feature .NET Framework 4.7 Features is installed on server ANISSA
Feature TCP Port Sharing is installed on server ANISSA
Feature WCF Services is installed on server ANISSA
...
Feature Web Server not installed on server ANISSA
Feature Web Server (IIS) not installed on server ANISSA

Checking ANISSA for ReWrite Module
IIS not installed on ANISSA

Checking to see if a reboot is required

Computer RebootPending
-------- -------------
ANISSA           False
#>
# ----------------------------------------
# 	PARAMETERS FOR SCRIPT (DO NOT EDIT)
# ----------------------------------------
[CmdletBinding(DefaultParameterSetName = "NoSQL")]
	param(
		[Parameter(HelpMessage="Only run SQL check",ParameterSetName="SQL")]
		[switch]$SQLOnly,
		[Parameter(HelpMessage="SQL check",ParameterSetName="SQL")]
		[switch]$SQL,
		[Parameter(Mandatory,HelpMessage="Computer name of SQL server",ParameterSetName="SQL")]
		[string]$SQLserver,
		[Parameter(Mandatory,HelpMessage="Database name on SQL server",ParameterSetName="SQL")]
		[string]$Database,
		[Parameter(HelpMessage="Install missing packages")]
		[switch]$Install,
		[Parameter(HelpMessage="Non-IIS Server Role")]
		[switch]$NonIIS
		)
# ----------------------------------------
# 	VARIABLES FOR SCRIPT (DO NOT EDIT)
# ----------------------------------------

$dotNet35Registry  = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5'
$dotNet4Registry = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
$ServerOS = Get-CimInstance Win32_OperatingSystem -Filter "caption like '%Windows Server%'"
$Server = [System.Environment]::MachineName
$root = [System.Environment]::GetEnvironmentVariable("systemroot")
$temp = [System.Environment]::GetEnvironmentVariable("temp")
$sysfiles=(Join-Path -Path (Get-Item $root) -ChildPath system32)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ----------------------------------------
# 		CHECK POWERSHELL SESSION
# ----------------------------------------
#These two handy statements check if using PS5.0 and running in an Administrative session
#requires -version 5.0
#requires -RunAsAdministrator
function Get-PS64 {
	#Check if running 64-bit PowerShell
	Write-Host "Checking $Server for 64-bit PowerShell" -ForegroundColor Cyan
		If ( [IntPtr]::size * 8 -eq 64 ) {
		Write-Host "You are running 64-bit PowerShell `n" -ForegroundColor Green
		} else {
		Write-Error "Please run 64-bit Powershell `n"  -Category 'NotImplemented'
		Throw "Not using 64-bit Powershell"
		}
}

# ----------------------------------------
# 		END OF POWERSHELL CHECK
# ----------------------------------------
# ----------------------------------------
# 		CHECK IF SUPPORTED OS
# ----------------------------------------

function Get-OSSupported {
		Write-Host "Checking $Server for Server OS version" -ForegroundColor Cyan
		if ($ServerOS.Caption -match '2019') {
		Write-Host "Windows Server 2019 is compatible but not supported yet `n" -ForegroundColor Yellow
		} elseif ($ServerOS.Caption -match "2012 R2") {
		Write-Host "Microsoft Windows Server 2012 R2 is supported `n" -ForegroundColor Green
		} elseif ($ServerOS.Caption -match "2016") {
		Write-Host "Microsoft Windows Server 2016 is supported `n" -ForegroundColor Green
		} else {
		throw Write-Host "Unsupported server. This script must be run on a supported server `n"  -ForegroundColor Red
		}
    }

# ----------------------------------------
#       END OF OS CHECK
# ----------------------------------------
# ----------------------------------------
# 		CHECK FEATURE FUNCTIONS
# ----------------------------------------

function Find-Folders {
  [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
  [System.Windows.Forms.Application]::EnableVisualStyles()
  $browse = New-Object System.Windows.Forms.FolderBrowserDialog
  $browse.SelectedPath = "C:\"
  $browse.ShowNewFolderButton = $false
  $browse.Description = "Select a directory"

  $loop = $true
  while($loop)
  {
      if ($browse.ShowDialog() -eq "OK")
      {
      $loop = $false

  #Insert your script here

      } else
      {
          $res = [System.Windows.Forms.MessageBox]::Show("You clicked Cancel. Would you like to try again or exit?", "Select a location", [System.Windows.Forms.MessageBoxButtons]::RetryCancel)
          if($res -eq "Cancel")
          {
              #Ends script
              return
          }
      }
  }
  $browse.SelectedPath
  $browse.Dispose()
}
function Get-Features {
    [CmdletBinding()]
    Param (
    [Parameter(Position=0, HelpMessage="Non-IIS Server Role")] [switch] $NonIIS,
    [Parameter(Position=1, HelpMessage="Install IIS Server Features")] [switch] $Install
    )

    Write-Host "Checking $Server for required Roles and Features" -ForegroundColor Cyan
    if ($NonIIS) {
        Write-Host "Checking Non-IIS Roles Installed" -ForegroundColor Green
        $RequiredFeature = @(
            'NET-Framework-Features', 'NET-Framework-Core', 'NET-Framework-45-Features', 'NET-Framework-45-Core',
            'NET-WCF-Services45', 'NET-WCF-TCP-PortSharing45'
        )
    } else {
        Write-Host "Checking All Roles Installed" -ForegroundColor Green
        $RequiredFeature = @(
            'Web-Server', 'Web-WebServer', 'Web-Common-Http', 'Web-Default-Doc', 'Web-Dir-Browsing', 'Web-Http-Errors',
            'Web-Static-Content', 'Web-Health', 'Web-Http-Logging', 'Web-Log-Libraries', 'Web-Request-Monitor',
            'Web-Http-Tracing', 'Web-Performance', 'Web-Stat-Compression', 'Web-Security', 'Web-Filtering', 'Web-App-Dev',
            'Web-Net-Ext', 'Web-Net-Ext45', 'Web-ASP', 'Web-Asp-Net', 'Web-Asp-Net45', 'Web-ISAPI-Ext', 'Web-ISAPI-Filter',
            'Web-Mgmt-Tools', 'Web-Mgmt-Console',
            'NET-Framework-Features', 'NET-Framework-Core', 'NET-Framework-45-Features', 'NET-Framework-45-Core',
            'NET-Framework-45-ASPNET', 'NET-WCF-Services45', 'NET-WCF-TCP-PortSharing45'
        )
    }
    Write-Host 'Importing Server Manager' -ForegroundColor Green
    Import-Module ServerManager
    if ($Install) {
      # check registry to make sure Windows update isn't disabled
      $AUProperties = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
      $WUProperties = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
      if ($AUProperties.NoAutoUpdate) {
        $AUEnabled = $AUProperties.NoAutoUpdate
      } else {
        $AUEnabled = 0
      }
      switch ($AUEnabled) {
        1 {$AUEnabled = 'Disabled'}
        0 {$AUEnabled = 'Enabled'}
      }
      Write-Host "Automatic Update - $($AUEnabled)" -ForegroundColor Green
      if ($AUProperties.UseWUServer) {
        $WUEnabled = $AUProperties.UseWUServer
      } else {
        $WUEnabled = 0
      }
      switch ($WUEnabled) {
        1 {$WUEnabled = 'WSUS'}
        0 {$WUEnabled = 'Windows Update'}
      }
      Write-Host "WSUS Server Configured to - $($WUEnabled)" -ForegroundColor Green
      if ($WUProperties.DisableWindowsUpdateAccess) {
        $UAEnabled = $WUProperties.DisableWindowsUpdateAccess
      } else {
        $UAEnabled = 0
      }
      switch ($UAEnabled) {
        1 {$UAEnabled = 'Disabled'}
        0 {$UAEnabled = 'Enabled'}
      }
      Write-Host "Access to Windows Update - $($UAEnabled)" -ForegroundColor Green
      if (!$connectcheck) {
        $connectcheck = (Test-NetConnection -ComputerName "download.microsoft.com").PingSucceeded
      }
      if ($connectcheck -eq $true) {
        Write-Host "Microsoft connection verified" -ForegroundColor Yellow -BackgroundColor Black
        if (($WUEnabled -eq 'Windows Update') -and ($AUEnabled -eq 'Enabled') -and ($UAEnabled -eq 'Enabled')) {
        Write-Host "This will take a while if downloading the packages from Windows Update" -ForegroundColor Yellow -BackgroundColor Black
        } else {
            Write-Host "This host is set to use WSUS, installing packages may fail" -ForegroundColor Yellow -BackgroundColor Black
        }
    } else {
        Write-Host "No external connection to Microsoft, please enter Windows Source location (e.g. Z:\sources\)" -ForegroundColor Red -BackgroundColor Black
        $WinSource = Find-Folders
      }
    }
    $InstallResult = @()
    # Run Feature checks
    foreach ($FeatureObj in $RequiredFeature) {
        # Get individual feature status
        $Check = (Get-WindowsFeature -Name $FeatureObj)
        # Create an object to store the properties we want from the feature
        $CheckObj = New-Object PSObject
            Add-Member -InputObject $CheckObj -MemberType NoteProperty -Name "Name" -Value $($Check.Name)
            Add-Member -InputObject $CheckObj -MemberType NoteProperty -Name "DisplayName" -Value $($Check.DisplayName)
            Add-Member -InputObject $CheckObj -MemberType NoteProperty -Name "InstallState" -Value $($Check.InstallState)
            # Store the results in an array outside of the loop to preserve the information collected
        $InstallResult += $CheckObj
    }
    #Display which Features are installed or missing
    $FeatureStatus = (Write-Output $InstallResult | Sort-Object -Property @{Expression="InstallState";Descending=$true}, `
    @{Expression="DisplayName";Descending=$false})
    foreach ($Feature in $FeatureStatus) {
        $FeatureName = $Feature.DisplayName
        $State = $Feature.InstallState
        if ($State -eq "Installed") {
            Write-Host "Feature $FeatureName is installed on server $Server" -ForegroundColor Green
          } elseif ($State -eq "Removed") {
            if ($Install -and $WinSource) {
              if ($Feature.Name -eq "NET-Framework-Core") {
                Write-Host "Installing $FeatureName on server $Server from external source" -ForegroundColor Magenta
                Write-Host "Source is $($WinSource + '\sxs')"
                Install-WindowsFeature $Feature.Name -Source ($WinSource + '\sxs') | Out-Null
            } else {
              Write-Host "Installing $FeatureName on server $Server from external source" -ForegroundColor Magenta
              if ($WinInstallEdition -eq "Datacenter") {
                $wimed = 4
              } else {
                $wimed = 2
              }
              Write-Host "Source is $('wim:' + $WinSource + '\install.wim:' + $wimed)"
              Install-WindowsFeature $Feature.Name -Source ('wim:' + $WinSource + '\install.wim:' + $wimed) | Out-Null
            }
          } elseif ($Install) {
              Write-Host "Installing $FeatureName on server $Server from external source" -ForegroundColor Magenta
              Install-WindowsFeature $Feature.Name | Out-Null
            } else {
            Write-Host "Feature $FeatureName was removed from server $Server" -ForegroundColor Yellow
            }
          } else {
              #Available
            if ($Install) {
                Write-Host "Installing $FeatureName on server $Server" -ForegroundColor Magenta
                Install-WindowsFeature $Feature.Name | Out-Null
            } else {
            Write-Host "Feature $FeatureName not installed on server $Server" -ForegroundColor Red
            }
		}
	}
	Write-Host "`n"
}
function Get-Rewrite {
	try {
		$errorActionPreference = "Stop"
		Write-Host "Checking $Server for ReWrite Module" -ForegroundColor Cyan
		#Check if IIS is installed
		$check = Get-WindowsFeature -Name Web-Server
			if ($NonIIS) {
				Write-Host "ReWrite module not needed `n" -ForegroundColor Magenta
				} elseif ($check.Installed -ne 'True') {
				Write-Host "IIS not installed on $Server `n" -ForegroundColor Red
				Throw
			} else {
			# Check if ReWrite Module is installed
            $RWcheck = Get-WebGlobalModule "ReWriteModule"
            if ($RWcheck.name -match 'RewriteModule') {
                #Making sure that we can get the correct file version info
                Write-Verbose "Update file version info to get the correct version info"
                Update-TypeData -TypeName System.IO.FileInfo -MemberType ScriptProperty -MemberName PSFileVersion -ErrorAction SilentlyContinue -Value {
                    if ($this.VersionInfo.FileVersion) {
                        [version] ("{0}.{1}.{2}.{3}" -f $this.VersionInfo.FileMajorPart,
                            $this.VersionInfo.FileMinorPart,
                            $this.VersionInfo.FileBuildPart,
                            $this.VersionInfo.FilePrivatePart)
                    }
                }
                #Check if the correct version is installed by looking at rewrite.dll version
                $RWInstalled = (Get-Item "$sysfiles\inetsrv\rewrite.dll" -ErrorAction SilentlyContinue).PSFileVersion -ge "7.1.1980.0"
            }
            if (!$Install -and $RWInstalled -eq $false) {
                Write-Host "Correct ReWrite version not installed on server $Server `n" -ForegroundColor Red
            } elseif (!$Install -and $RWcheck.name -notmatch 'RewriteModule') {
				Write-Host "IIS ReWrite module not installed on server $Server `n" -ForegroundColor Red
			} elseif ($Install -and ($RWcheck.name -notmatch 'RewriteModule') -or ($RWInstalled -eq $false)) {
				Write-Host "Installing required Rewrite Module 2.1 on $Server" -ForegroundColor Magenta
				$msi = 'rewrite_amd64_en-US.msi'
        if (!$connectcheck) {
          $connectcheck = (Test-NetConnection -ComputerName "download.microsoft.com").PingSucceeded
        }
				if ($connectcheck -eq $false) {
					Write-Host "No network connection to Microsoft, please enter local filename:" -ForegroundColor Red -BackgroundColor Black
          Add-Type -AssemblyName System.Windows.Forms
          $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Multiselect = $false
            Filter = "MSI (*.msi)| *.msi"
          }
          [void]$FileBrowser.ShowDialog()
          $inputfile = $FileBrowser.FileName;
          If($FileBrowser.FileNames -like "*\*") {
            # Do something
            Write-Host "$($FileBrowser.FileName) is being installed, please wait." -ForegroundColor Magenta
          }
          else {
              Write-Host "Cancelled by user"
          }
					Copy-Item $inputfile -Destination "$temp\$msi"
				} else {
				# Download & install Rewrite Module 2.1
					$rewriteurl = 'https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi'
					Invoke-WebRequest -Uri $rewriteurl -OutFile "$temp\$msi"
				}
				#Check the file to make sure it's hash is correct
				$rewritehash = (Get-FileHash "$temp\$msi" -Algorithm SHA1).Hash
				$testhash = "8F41A67FA49110155969DCCFF265B8623A66448F"
				if ($testhash -eq $rewritehash) {
					Start-Process -FilePath "$root\system32\msiexec.exe" -ArgumentList "/i $temp\$msi /qn /norestart" -Wait -WorkingDirectory $pwd
					Write-Host "IIS ReWrite module is now installed `n" -ForegroundColor Green
				} else {
					Write-Host "File hash is inconsistent! Cannot install `n" -ForegroundColor Red
				}
			} else {
				Write-Host "IIS ReWrite module is installed `n" -ForegroundColor Green
				}
			}
		} catch {
		return
	}
}

function Get-UCRTUpdate {
	Write-Host "Checking $Server for Universal C Runtime Update" -ForegroundColor Cyan
	if ($ServerOS.Caption -match ('2016' -or '2019')) {
	Write-Host "Universal C Runtime Update not needed on 2016 and 2019 `n" -ForegroundColor Green
	} else {
		#Making sure that we can get the correct file version info
		Write-Verbose "Update file version info to get the correct version info"
		Update-TypeData -TypeName System.IO.FileInfo -MemberType ScriptProperty -MemberName PSFileVersion -ErrorAction SilentlyContinue -Value {
			if ($this.VersionInfo.FileVersion) {
				[version] ("{0}.{1}.{2}.{3}" -f $this.VersionInfo.FileMajorPart,
					$this.VersionInfo.FileMinorPart,
					$this.VersionInfo.FileBuildPart,
					$this.VersionInfo.FilePrivatePart)
			}
		}
		#Check if UCRT Update KB is installed by looking at ucrtbase.dll version
		$KBInstalled = (Get-Item "$sysfiles\ucrtbase.dll" -ErrorAction SilentlyContinue).PSFileVersion -gt "10.0.10240.16389"
		if ($KBInstalled -eq $false) {
			Write-Host "Universal C Runtime Update not installed on server $Server." -ForegroundColor Red
			Write-Host 'Windows Update must be run to retrieve Universal C Runtime Update. `n' -ForegroundColor Red
			}
			else {
			Write-Host "Universal C Runtime Update is installed `n" -ForegroundColor Green
		}
	}
}
# ----------------------------------------
#       END OF FEATURE CHECK FUNCTIONS
# ----------------------------------------
# ----------------------------------------
# 		CHECK FOR .NET FRAMEWORK
# ----------------------------------------

function Get-dotNET {
    $v17x = New-Object System.Management.Automation.Host.ChoiceDescription '&1 - 17.x', 'TPP Version: 17.x'
    $v18x = New-Object System.Management.Automation.Host.ChoiceDescription '&2 - 18.x', 'TPP Version: 18.x'
    $v19x = New-Object System.Management.Automation.Host.ChoiceDescription '&3 - 19.x', 'TPP Version: 19.x'
    $v20x = New-Object System.Management.Automation.Host.ChoiceDescription '&4 - 20.x', 'TPP Version: 20.x'
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($v17x, $v18x, $v19x, $v20x)
    $title = 'TPP Version'
    $message = 'Select which TPP Version you are installing'
    #$TPPVersion = $host.ui.PromptForChoice($title, $message, $options, 3)
    $TPPVersion = "20.x"
	switch($TPPVersion){
		0 {$TPPInstallVersion = "17.x"}
		1 {$TPPInstallVersion = "18.x"}
		2 {$TPPInstallVersion = "19.x"}
		3 {$TPPInstallVersion = "20.x"}
  }
    $Standard = New-Object System.Management.Automation.Host.ChoiceDescription  '&1 - Standard'
    $Datacenter = New-Object System.Management.Automation.Host.ChoiceDescription '&2 - Datacenter'
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($Standard, $Datacenter)
    $title = 'Windows Edition'
    $message = 'Select which Windows Edition you are installing'
    #$WinEdition = $host.ui.PromptForChoice($title, $message, $options, 0)
    $WinEdition = "Datacenter"
  Switch($WinEdition){
    0 {$global:WinInstallEdition = "Standard"}
    1 {$global:WinInstallEdition = "Datacenter"}
  }

    Write-Host "Checking $Server for required .Net Frameworks" -ForegroundColor Cyan
	$Net35RegKey = (Get-Childitem $dotNet35Registry -ErrorAction SilentlyContinue)
	if ($null -ne $Net35RegKey) {
		$Version = $Net35RegKey.GetValue("Version")
		if ($Version -ge "3.5.30729") {
                #"$computer has .NET v3.5"
				Write-Host "You have .NET Framework version 3.5 Installed" -ForegroundColor Green
			}
        } elseif ($Install -and !$Net35RegKey) {
            Write-Host ".Net Framework version 3.5 is being installed" -ForegroundColor Magenta
		} else {
            Write-Host "Cannot find .Net Framework version 3.5, please install using the -Install switch" -ForegroundColor Red
            Throw "Incorrect .NET Installed"
		}
    $OS = $ServerOS.Caption
    $Net4RegKey = Get-Childitem $dotNet4Registry
    $Release = $Net4RegKey.GetValue("Release")
    if ($Release) {
                #Check which .Net version is installed here
                Switch ($Release) {
                    378389 {$NetFrameworkVersion = "4.5"}
                    378675 {$NetFrameworkVersion = "4.5.1"}
                    378758 {$NetFrameworkVersion = "4.5.1"}
                    379893 {$NetFrameworkVersion = "4.5.2"}
                    393295 {$NetFrameworkVersion = "4.6"}
                    393297 {$NetFrameworkVersion = "4.6"}
                    394254 {$NetFrameworkVersion = "4.6.1"}
                    394271 {$NetFrameworkVersion = "4.6.1"}
                    394802 {$NetFrameworkVersion = "4.6.2"}
                    394806 {$NetFrameworkVersion = "4.6.2"}
                    460798 {$NetFrameworkVersion = "4.7"}
                    460805 {$NetFrameworkVersion = "4.7"}
                    461308 {$NetFrameworkVersion = "4.7.1"}
                    461310 {$NetFrameworkVersion = "4.7.1"}
                    461808 {$NetFrameworkVersion = "4.7.2"}
                    461814 {$NetFrameworkVersion = "4.7.2"}
                    528040 {$NetFrameworkVersion = "4.8"}
                    528049 {$NetFrameworkVersion = "4.8"}
                    Default {$NetFrameworkVersion = "Not installed"}
                 }
                if ($NetFrameworkVersion -ne "Not installed") {
                Write-Host "You have .NET Framework version $($NetFrameworkVersion) Installed on $($OS)" -ForegroundColor Green
                if (($TPPInstallVersion -eq "17.x") -and ($NetFrameworkVersion -ge "4.6.1")) {
                    Write-Host "You have the correct .NET Framework to install the Venafi Platform `n" -ForegroundColor Green
                } elseif (($TPPInstallVersion -eq "18.x") -and ($NetFrameworkVersion -ge "4.6.2")) {
                    Write-Host "You have the correct .NET Framework to install the Venafi Platform `n" -ForegroundColor Green
                } elseif (($TPPInstallVersion -eq "19.x") -and ($NetFrameworkVersion -ge "4.7.2")) {
                    Write-Host "You have the correct .NET Framework to install the Venafi Platform `n" -ForegroundColor Green
                } elseif (($TPPInstallVersion -eq "20.x") -and ($NetFrameworkVersion -ge "4.7.2")) {
                    Write-Host "You have the correct .NET Framework to install the Venafi Platform `n" -ForegroundColor Green
            } elseif ($Install) {
                Write-Host "Installing .Net Framework version 4.7.2" -ForegroundColor Magenta
                $exe = 'NDP472-KB4054530-x86-x64-AllOS-ENU.exe'
                if (!$connectcheck) {
                  $connectcheck = (Test-NetConnection -ComputerName "download.microsoft.com").PingSucceeded
                }
                if ($connectcheck -eq $false) {
                  Write-Host "No network connection to Microsoft, please enter local filename:" -ForegroundColor Red -BackgroundColor Black
                  Add-Type -AssemblyName System.Windows.Forms
                  $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                    Multiselect = $false
                    Filter = "EXE (*.exe)| *.exe"
                  }
                  [void]$FileBrowser.ShowDialog()
                  $inputfile = $FileBrowser.FileName;
                  If($FileBrowser.FileNames -like "*\*") {
                    # Do something
                    Write-Host "$($FileBrowser.FileName) is being installed, please wait." -ForegroundColor Magenta
                  }
                  else {
                      Write-Host "Cancelled by user"
                  }
                  Copy-Item $inputfile -Destination "$temp\$exe"
                } else {
                # Download & install .Net 4.7.2
                  $neturl = 'http://go.microsoft.com/fwlink/?linkid=863265'
                  Invoke-WebRequest -Uri $neturl -OutFile "$temp\$exe"
                }
                #Check the file to make sure it's hash is correct
                $nethash = (Get-FileHash "$temp\$exe" -Algorithm SHA1).Hash
                $testhash = "31FC0D305A6F651C9E892C98EB10997AE885EB1E"
                if ($testhash -eq $nethash) {
                  Start-Process -FilePath "$temp\$exe" -ArgumentList "/norestart","/q" -Wait -WorkingDirectory $pwd
                  Write-Host ".Net Framework version 4.7.2 is now installed `n" -ForegroundColor Green
                } else {
                  Write-Host "File hash is inconsistent! Cannot install `n" -ForegroundColor Red
                }
              } else {
                Write-Host "Please upgrade .Net Framework to version 4.7.2 or above" -ForegroundColor Red
              }
            } else {
                Write-Host "You either do not have the .NET Framework installed or a not-sufficient version"
                Throw "Incorrect .NET Installed"
            }
        }
}

# ----------------------------------------
#       END OF .NET FRAMEWORK CHECK
# ----------------------------------------
# ----------------------------------------
# 		CHECK PENDING REBOOT FUNCTION
# ----------------------------------------

#Check to see if there are any pending reboots required

function Get-PendingReboot {
    $result = @{
        CBSRebootPending = $false
        WindowsUpdateRebootRequired = $false
        FileRenamePending = $false
        SCCMRebootPending = $false
    }

	#Get Local Machine Name
	$WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ErrorAction Stop

    #Check CBS Registry
    $key = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
    if ($null -ne $key)
    {
        $result.CBSRebootPending = $true
    }

    #Check Windows Update
    $key = Get-Item "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore
    if($null -ne $key)
    {
        $result.WindowsUpdateRebootRequired = $true
    }

    #Check PendingFileRenameOperations
    $prop = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Ignore
    if($null -ne $prop)
    {
        $result.FileRenamePending = $true
    }

    #Check SCCM Client
    try
    {
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if(($null -ne $status) -and $status.RebootPending){
            $result.SCCMRebootPending = $true
			}
    }catch{}

    #Return Reboot required
    ## Creating Custom PSObject and Select-Object Splat
	    $SelectSplat = @{
	        Property=(
	            'Computer',
	            'CBServicing',
	            'WindowsUpdate',
	            'CCMClientUtil',
	            'PendFileRename',
	            'RebootPending'
	        )}
	    New-Object -TypeName PSObject -Property @{
	        Computer=$WMI_OS.CSName
	        CBServicing=$result.CBSRebootPending
	        WindowsUpdate=$result.WindowsUpdateRebootRequired
	        CCMClientUtil=$result.SCCMRebootPending
	        PendFileRename=$result.FileRenamePending
	        RebootPending=($result.CBSRebootPending -or $result.WindowsUpdateRebootRequired -or $result.SCCMRebootPending -or $result.FileRenamePending)
	    } | Select-Object @SelectSplat
}

# ----------------------------------------
#       END OF PENDING REBOOT FUNCTION
# ----------------------------------------
# ----------------------------------------
# 		RUN TESTS
# ----------------------------------------
if (!$SQLOnly) {
  Get-PS64
  Get-OSSupported
  Get-dotNET
  Get-UCRTUpdate
	if (($NonIIS.IsPresent) -and ($Install.IsPresent)) {
    Get-Features -NonIIS -Install
  } elseif ($Install.IsPresent) {
    Get-Features -Install
  } elseif ($NonIIS.IsPresent) {
    Get-Features -NonIIS
  } else {
    Get-Features
  }
  Get-Rewrite
  # Remove IIS Default Web Site
if ($Install.IsPresent) {
  if ($NonIIs.IsPresent) {
    Write-Host "Not installing IIS sites."
  } elseif ($ServerOS.Caption -match "2012 R2") {
    Import-Module WebAdministration
    $WebAdminModule = Get-Module WebAdministration
    if ($WebAdminModule) {
      Write-Host "Stopping all IIS Sites"
      Get-WebSite | Stop-WebSite
      Write-Host "Removing Default Web Site"
      Remove-WebSite -Name 'Default Web Site' -Confirm:$false
    } else {
      Write-Host "Cannot access WebAdministration modules to remove site, please remove manually."
    }
  } else {
    Import-Module IISAdministration
    $IISAdminModule = Get-Module IISAdministration
    if ($IISAdminModule) {
      Write-Host "Stopping all IIS Sites"
      Get-IISSite | Stop-IISSite -Confirm:$false
      Write-Host "Removing Default Web Site"
      Remove-IISSite -Name 'Default Web Site' -Confirm:$false
    } else {
      Write-Host "Cannot access IISAdministration modules to remove site, please remove manually."
    }
  }
}
  # Check-Reboot
	Write-host "Checking to see if a reboot is required" -ForegroundColor Cyan
	Get-PendingReboot | Select-Object Computer,RebootPending | Format-Table -AutoSize
}
# Check-SQL
if ($SQL -or $SQLOnly) {
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription  '&Yes - Agree'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No - Abort'
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $title = 'Install DBA Tools'
    $message = 'Checking SQL requires installing the DBA Tools package, enter Yes to agree or no to abort installation'
    $InstallTools = $host.ui.PromptForChoice($title, $message, $options, 0)
  Switch($InstallTools){
    0 {$global:InstallDBATools = "Yes"}
    1 {$global:InstallDBATools = "No"}
  }
  if ($InstallDBATools -eq "Yes") {
    if ((Get-PackageProvider).Name -eq 'NuGet') {
      Write-Host "NuGet Installed"
    } else {
      Write-Host "Installing NuGet"
      Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction silentlycontinue | Out-Null
    }
    Import-PackageProvider -Name NuGet
    Set-PSRepository -InstallationPolicy Trusted -Name PSGallery
    If ((Get-InstalledModule).Name -eq 'dbatools') {
      Write-Host "DBA Tools Installed"
    } else {
      Write-Host "Installing DBA Tools modules"
      Install-Module dbatools -Confirm:$False -Force -ErrorAction silentlycontinue
    }
    Import-Module dbatools
    $toolsloaded = Get-Module dbatools
    if ($toolsloaded) {
      $cred = Get-Credential -Message 'Enter SQL Server username / password. This can be a Windows (Domain\user) or SQL Server account.'
      $SQLRoleInfo = Get-DBADbRoleMember -SqlInstance $SQLserver -Database $Database -SqlCredential $cred -IncludeSystemUser
      $svrSQLComp = Get-DbaComputerSystem -ComputerName $SQLserver
      $svrSQLOS = Get-DbaOperatingSystem -ComputerName $SQLserver
      $svrSQLBuild = Get-DbaBuildReference -SqlInstance $SQLserver
    try {
      $svrSQLAg = Get-DbaAvailabilityGroup -SqlInstance $SQLserver -EnableException
    } catch {
      $svrSQLAg = New-Object Object
      $svrSQLAg | Add-Member  -MemberType NoteProperty -Name "AvailabilityDatabases" -Value "Availability Group not configured"
      $svrSQLAg | Add-Member  -MemberType NoteProperty -Name "AvailabilityGroupListeners" -Value "No Availability Group Listeners"
    }
      $svrSQLDbInstance = Connect-DbaInstance -SqlInstance $SQLserver | Select-Object ProductLevel, Edition, #<look at script
      @{Name="SQLVersion";Expression={ if ($_.VersionMajor -eq "11") {"SQL 2012"} elseif ($_.VersionMajor -eq "12") {"SQL 2014"} elseif ($_.VersionMajor -eq "13") {"SQL 2016"}
      elseif ($_.VersionMajor -eq "14") {"SQL 2017"} elseif ($_.VersionMajor -eq "15") {"SQL 2019"} elseif ($_.VersionMajor -lt "11") {"SQL 2008R2 or older"} else {"unknown"}}}

    write-host "==========================SQL Server Information================================="
    write-host ""
    Write-Host "SQL Server FQDN:" $svrSQLOS.ComputerName
    write-host "SQL Instance: " $svrSQLBuild.SqlInstance
    write-host "SQL Version:" $svrSQLDbInstance.SQLVersion
    write-host "Edition:" $svrSQLDbInstance.Edition
    write-host "SQL Product Level:" $svrSQLDbInstance.ProductLevel
    Write-Host "SQL Server OS:" $svrSQLOS.OSVersion
    Write-Host "SQL Server Processors:" $svrSQLComp.NumberProcessors
    Write-Host "SQL Server Logical Processors:" $svrSQLComp.NumberLogicalProcessors
    Write-Host "SQL Server Memory:" $svrSQLComp.TotalPhysicalMemory
    write-host "SQL Server Availability Group Databases:" $svrSQLAg.AvailabilityDatabases
    write-host "SQL Server Availability Group Listeners:" $svrSQLAg.AvailabilityGroupListeners
    write-host ""
    write-host "================================================================================="
    if ($SQLRoleInfo) {
      write-host ""
      write-host "=======================SQL Database User Information============================="
      write-host ""
      foreach ($RoleInfo in $SQLRoleInfo) {
        write-host    "UserName       :  $($RoleInfo.UserName)"
        write-host    "Login          :  $($RoleInfo.Login)"
        write-host    "Login Type     :  $($RoleInfo.LoginType)"
        write-host    "Database Name  :  $($RoleInfo.Database)"
          if ($RoleInfo.Role -eq "db_owner") {
            Write-Host    "Server Role    :  $($RoleInfo.Role)" -ForegroundColor Red
          } else {
            Write-Host    "Server Role    :  $($RoleInfo.Role)"
          }
          write-host ""
        }
      write-host "================================================================================="
      }
    }
	} else {
    Write-Host "SQL Checks aborted as DBA Tools installation is required to perform them"
  }
}
# ----------------------------------------
#       END OF RUN TESTS
# ----------------------------------------



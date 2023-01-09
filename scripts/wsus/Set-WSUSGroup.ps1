<#
.Synopsis
    This script will allow a non-domain joined computer talk to WSUS
.DESCRIPTION
    This script will apply WSUS Registry Settings and add said computer to the provided group in WSUS.
.NOTES
    Author - Zack Flowers
.PARAMETER WSUSServer
    The FQDN of your WSUS Server (e.g., wsus01.yourcompany.com)
.PARAMETER Group
    The group this computer will be applied to in WSUS and what Registry Settings it was receive.
.EXAMPLE
    .\Set-WSUSGroup.ps1 -WSUSServer wsus01.mycompany.com -Group "Workstations"
    
    This will add the WSUS Server 'wsus01.mycompany.com' to the computer's registry and apply the WSUS Group 'Workstations' and its
    affiliated Registry Settings dictated in this script.
#>
[cmdletbinding()]
param (
    [parameter(Mandatory=$false)]
    [ValidateSet("Test - Workstations", "Workstations", "Servers")]
	[string]$Group = "Test - Workstations",
    [parameter(Mandatory=$false)]
	[string]$WSUSServer = "FQDN.mydomain.com"
)

# WSUS Server and Port Number
$WSUSServer = "https://$WSUSServer:8531"

 
# END OF VARIABLE CHANGING!!
 
# Create an empty array to hold a hash table
$ArrayOfRegValues = @{}
 
# Fill the Array with info based on group selection
switch ($Group) {
    'Test - Workstations' {
        $ArrayOfRegValues = @(
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "ActiveHoursEnd"; RegType = "DWORD"; RegValue = "20"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "ActiveHoursStart"; RegType = "DWORD"; RegValue = "6"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "AutoRestartDeadlinePeriodInDays"; RegType = "DWORD"; RegValue = "7"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "SetActiveHours"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "SetAutoRestartDeadline"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "TargetGroup"; RegType = "STRING"; RegValue = $Group}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "TargetGroupEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "WUServer"; RegType = "STRING"; RegValue = $WSUSServer}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "WUStatusServer"; RegType = "STRING"; RegValue = $WSUSServer}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AllowMUUpdateService"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AUOptions"; RegType = "DWORD"; RegValue = "4"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AutoInstallMinorUpdates"; RegType = "DWORD"; RegValue = "DELETE"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AutomaticMaintenanceEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "DetectionFrequency"; RegType = "DWORD"; RegValue = "20"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "DetectionFrequencyEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "NoAutoRebootWithLoggedOnUsers"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "NoAutoUpdate"; RegType = "DWORD"; RegValue = "0"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "ScheduledInstallDay"; RegType = "DWORD"; RegValue = "7"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "ScheduledInstallTime"; RegType = "DWORD"; RegValue = "3"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "UseWUServer"; RegType = "DWORD"; RegValue = "1"}
        )
    }
    'Workstations' {
        $ArrayOfRegValues = @(
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "ActiveHoursEnd"; RegType = "DWORD"; RegValue = "20"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "ActiveHoursStart"; RegType = "DWORD"; RegValue = "6"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "AutoRestartDeadlinePeriodInDays"; RegType = "DWORD"; RegValue = "7"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "SetActiveHours"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "SetAutoRestartDeadline"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "TargetGroup"; RegType = "STRING"; RegValue = $Group}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "TargetGroupEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "WUServer"; RegType = "STRING"; RegValue = $WSUSServer}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "WUStatusServer"; RegType = "STRING"; RegValue = $WSUSServer}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AllowMUUpdateService"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AUOptions"; RegType = "DWORD"; RegValue = "4"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AutoInstallMinorUpdates"; RegType = "DWORD"; RegValue = "DELETE"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AutomaticMaintenanceEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "DetectionFrequency"; RegType = "DWORD"; RegValue = "20"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "DetectionFrequencyEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "NoAutoRebootWithLoggedOnUsers"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "NoAutoUpdate"; RegType = "DWORD"; RegValue = "0"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "ScheduledInstallDay"; RegType = "DWORD"; RegValue = "7"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "ScheduledInstallTime"; RegType = "DWORD"; RegValue = "3"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "UseWUServer"; RegType = "DWORD"; RegValue = "1"}
        )
    }
    'Servers' {
        $ArrayOfRegValues = @(
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "ActiveHoursEnd"; RegType = "DWORD"; RegValue = "20"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "ActiveHoursStart"; RegType = "DWORD"; RegValue = "6"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "AutoRestartDeadlinePeriodInDays"; RegType = "DWORD"; RegValue = "7"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "SetActiveHours"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "SetAutoRestartDeadline"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "TargetGroup"; RegType = "STRING"; RegValue = $Group}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "TargetGroupEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "WUServer"; RegType = "STRING"; RegValue = $WSUSServer}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; RegValueName = "WUStatusServer"; RegType = "STRING"; RegValue = $WSUSServer}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AllowMUUpdateService"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AUOptions"; RegType = "DWORD"; RegValue = "4"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AutoInstallMinorUpdates"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "AutomaticMaintenanceEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "DetectionFrequency"; RegType = "DWORD"; RegValue = "20"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "DetectionFrequencyEnabled"; RegType = "DWORD"; RegValue = "1"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "NoAutoRebootWithLoggedOnUsers"; RegType = "DWORD"; RegValue = "DELETE"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "NoAutoUpdate"; RegType = "DWORD"; RegValue = "0"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "ScheduledInstallDay"; RegType = "DWORD"; RegValue = "6"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "ScheduledInstallTime"; RegType = "DWORD"; RegValue = "3"}
            @{RegKeyLoc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; RegValueName = "UseWUServer"; RegType = "DWORD"; RegValue = "1"}
        )
    }
}
 
# Set get value of property to null
$GetValueOfProperty = $null

# On non-domain computers, these paths will not exist, so we may need to create them. 
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate"

    if (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate") {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU"
    }
}
 
# Iterate through the array to set or delete every registry item if needed
for($i = 0; $i -lt $ArrayOfRegValues.count; $i++) {
     
    # Make sure it exists
    if (Get-ItemProperty -Path $ArrayOfRegValues.RegKeyLoc[$i] -Name $ArrayOfRegValues.RegValueName[$i] -ErrorAction SilentlyContinue) {
        $GetValueOfProperty = Get-ItemProperty -Path $ArrayOfRegValues.RegKeyLoc[$i] -Name $ArrayOfRegValues.RegValueName[$i] -ErrorAction SilentlyContinue | Select -ExpandProperty $ArrayOfRegValues.RegValueName[$i]
    } else {
        $GetValueOfProperty = $null
    }
 
    # Check if the registry item matches the value in the array/hash
    if (($GetValueOfProperty) -eq $ArrayOfRegValues.RegValue[$i]) {
        Write-Output "Already Set: $($ArrayOfRegValues.RegValueName[$i]) is already set in the Registry."
    # The value doesn't match, does the hash table say delete and does the value exist in the registry?
    } elseif (($ArrayOfRegValues.RegValue[$i] -eq "DELETE") -and $GetValueOfProperty) {
         
        # Delete registry key
        Write-Output "Delete: Deleting Registry Key $($ArrayOfRegValues.RegValueName[$i])"
        Remove-ItemProperty -Path $ArrayOfRegValues.RegKeyLoc[$i] -Name $ArrayOfRegValues.RegValueName[$i]
    } else {
        # If the registry in the hash table doesn't have 'DELETE' in its value, create the registry item
        if ($ArrayOfRegValues.RegValue[$i] -ne "DELETE") {
            
            # Set Registry Value
            Write-Output "Set: Setting Registry Key $($ArrayOfRegValues.RegValueName[$i])"

            # If a value exists, we just need to update it, otherwise create the new item
            if ($GetValueOfProperty) {
                Set-ItemProperty -Path $ArrayOfRegValues.RegKeyLoc[$i] -Name $ArrayOfRegValues.RegValueName[$i] -Value $ArrayOfRegValues.RegValue[$i]
            } else {
                New-ItemProperty -Path $ArrayOfRegValues.RegKeyLoc[$i] -Name $ArrayOfRegValues.RegValueName[$i] -PropertyType $ArrayOfRegValues.RegType[$i] -Value $ArrayOfRegValues.RegValue[$i]
            }
        }
    }
}

Write-Host -ForegroundColor Yellow "Restarting Windows Update Service..."
Restart-Service -Name wuauserv -ErrorAction SilentlyContinue

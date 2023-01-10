<#
.Synopsis
    This script installs any Windows Feature, Windows Optional Feature, or Windows Capability Feature.

.DESCRIPTION
    This script will disable/enable WSUS and install the provided features. Once installed, the script will enable WSUS if necessary.

.NOTES
    Author - Zack F

.PARAMETER WindowsFeature
    The name of the Windows Feature that you wish to install. 

.EXAMPLE
    ./Install-AnyWindowsFeature.ps1 -WindowsFeature "*Hyper-V*"
    
    The above will install any related Windows Feature, Optional Feature, or Capability Feature involving Hyper-V.

.EXAMPLE
    ./Install-AnyWindowsFeature.ps1 -WindowsFeature (Get-WindowsOptionalFeature -Online | Where-Object FeatureName -like "*Hyper-V*")
    
    The above will install any Hyper-V related Windows Optional Feature

.EXAMPLE
    ./Install-AnyWindowsFeature.ps1 -WindowsFeature "SNMP*", "*ActiveDirectory*"
    
    The above would install the SNMP client Capability Feature and the RSAT Active Directory Capability Feature.

.LINK
https://github.com/ZacksHomeLab
#>
[cmdletbinding(SupportsShouldProcess)]
param (
    [parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [object[]]$WindowsFeature
)

begin {

    #Requires -RunAsAdministrator

    # Retrieve the OS Name (e.g., if it contains Server, Pro, etc.)
    # If we're using a Windows OS, retrieve the Windows Feature names, optional feature names, and capability feature names.
    Write-Verbose "Retrieving all of the potential feature names within Windows..."
    $ComputerInformation = Get-ComputerInfo -Property OsName | Select-Object -ExpandProperty OsName
    if ($ComputerInformation -like "*server*") {
        $WindowsFeatureNames = Get-WindowsFeature -online -FeatureName | Select-Object -ExpandProperty FeatureName
    } elseif ($ComputerInformation -like "*Windows*") {
        $WindowsOptionalFeatureNames = Get-WindowsOptionalFeature -Online | Select-Object -ExpandProperty FeatureName
    } else {
        Throw "This is not a Windows Operating System, stopping."
    }

    # Windows Server and Non-Server variants should have Capability Features
    $WindowsCapabilityNames = Get-WindowsCapability -Online | Select-Object -ExpandProperty Name

    $WindowsFeatureStatuses = $null
    $WindowsOptionalFeatureStatuses = $null
    $WindowsCapabilityStatuses = $null

    function Get-WSUSStatus {
        [cmdletbinding()]
        param()

        begin {
            $UseWUServer = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UseWUServer
            $WSUSStatus = $false
        }

        process {
            if ($UseWUServer -eq 1) {
                Write-Verbose "Get-WSUSStatus: WSUS is Active."
                $WSUSStatus = $true
            } elseif ($UseWUServer -eq 0) {
                Write-Verbose "Get-WSUSStatus: WSUS is Not Active."
                $WSUSStatus = $false
            } else {
                Write-Verbose "Get-WSUSStatus: WSUS isn't configured on this machine."
                $WSUSStatus = $null
            }

        }
        end {
            return $WSUSStatus
        }
    }

    function Disable-WSUS {
        [cmdletbinding(SupportsShouldProcess)]
        param (
        )
        process {
            try {
                Write-Verbose "Disable-WSUS: Setting UseWUServer to value 0 and Restarting Service wuauserv."
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 0 -ErrorAction Stop -WhatIf:$WhatIfPreference
                Restart-Service wuauserv -ErrorAction Stop -WhatIf:$WhatIfPreference
            } catch {
                Throw "Disable-WSUS: Failed to set Registry Key UseWUServer to value 0."
            }
        }
    }

    function Enable-WSUS {
        [cmdletbinding(SupportsShouldProcess)]
        param (
        )
        process {
            try {
                Write-Verbose "Enable-WSUS: Setting UseWUServer to value 0 and Restarting Service wuauserv."
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1 -ErrorAction Stop -WhatIf:$WhatIfPreference
                Restart-Service wuauserv -ErrorAction Stop -WhatIf:$WhatIfPreference
            } catch {
                Throw "Enable-WSUS: Failed to set Registry Key UseWUServer to value 1."
            }
        }
    }

    function Install-AnyWindowsFeature {
        [cmdletbinding(SupportsShouldProcess)]
        param (
            [parameter(Mandatory,
                Position=0)]
            [ValidateNotNullOrEmpty()]
            [string[]]$FeatureName,

            [parameter(Mandatory,
                ParameterSetName="WindowsFeature",
                Position=1)]
            [switch]$WindowsFeature,

            [parameter(Mandatory,
                ParameterSetName="WindowsOptionalFeature",
                Position=1)]
            [switch]$WindowsOptionalFeature,

            [parameter(Mandatory,
                ParameterSetName="WindowsCapability",
                Position=1)]
            [switch]$WindowsCapability
        )

        begin {
            if ($null -eq $PSCmdlet.ParameterSetName) {
                Throw "Install-AnyWindowsFeature: A switch wasn't given to install feature $FeatureName, stopping."
            }
        }

        process {
            
            foreach ($Feature in $FeatureName) {

                switch ($PSCmdlet.ParameterSetName) {
                    "WindowsFeature" {
                        if ($PSCmdlet.ShouldProcess($Feature)) {
                            Install-WindowsFeature -Name $Feature -IncludeAllSubFeature -NoRestart -ErrorAction Stop
                        }
                    }
                    "WindowsOptionalFeature" {
                        if ($PSCmdlet.ShouldProcess($Feature)) {
                            Enable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -ErrorAction Stop
                        }
                    }

                    "WindowsCapability" {
                        if ($PSCmdlet.ShouldProcess($Feature)) {
                            Add-WindowsCapability -Online -Name $Feature -ErrorAction Stop
                        }
                    }
                }
            }
        }
    }
}

process {
    foreach ($Feature in $WindowsFeature) {

        # Retrieve the name of the feature if an object type other than String was given (e.g., user passed (Get-WindowsOptionalFeature -Online | Where FeatureName -like "Hyper-V*"))
        # The purpose of this is to convert the given feature into a string while retrieving the name of said feature
        switch ($Feature.GetType()) {
            "Microsoft.Dism.Commands.BasicCapabilityObject" {
                $Feature = $Feature.Name
            }

            "Microsoft.Dism.Commands.BasicFeatureObject" {
                $Feature = $Feature.FeatureName
            }

            "Microsoft.Windows.ServerManager.Commands.Feature" {
                $Feature = $Feature.Name
            }
        }

        # Remove quotes from the string if given (This was probably only needed for testing within VSCode)
        if ($Feature[0] -match '"' -or $Feature[-1] -match '"') {
            Write-Verbose "Feature $Feature contains quotation marks, removing."
            $Feature = $Feature.Trim('"')
        } elseif ($Feature[0] -match "'" -or $Feature[-1] -match "'") {
            Write-Verbose "Feature $Feature contains single quotation marks, removing."
            $Feature = $Feature.Trim("'")
        }

        switch ($Feature) {
            {($_ -in $WindowsFeatureNames) -or ($WindowsFeatureNames -like $_)} {
                # Check if the feature was installed already
                $WindowsFeatureStatuses = Get-WindowsFeature -Name $Feature -ErrorAction SilentlyContinue

                if ($null -ne $WindowsFeatureStatuses) {

                    foreach ($WindowsFeatureStatus in $WindowsFeatureStatuses) {
                        if ($WindowsFeatureStatus.InstallState -ne 'Available') {
                            $WSUSStatus = Get-WSUSStatus
    
                            if ($WSUSStatus) {
                                try {
                                    Disable-WSUS -ErrorAction Stop -WhatIf:$WhatIfPreference
                                } catch {
                                    Throw "Failed to disable WSUS, stopping."
                                }
                            }
                            # Install Windows Feature
                            try {
                                Write-Host -ForegroundColor Yellow "Attempting to install Windows Feature $($WindowsFeatureStatus.Name)..."
                                Install-AnyWindowsFeature -FeatureName $($WindowsFeatureStatus.Name) -WindowsFeature -ErrorAction Stop -WhatIf:$WhatIfPreference
                            } catch {
                                Throw "Failed to install Windows Feature $($WindowsFeatureStatus.Name), stopping."
                            }
                        } else {
                            Write-Host -ForegroundColor Green "Windows Feature $($WindowsFeatureStatus.Name) was already installed!"
                        }
                    }
                }
            }
            {($_ -in $WindowsOptionalFeatureNames) -or ($WindowsOptionalFeatureNames -like $_)} {
                # Check if the feature was installed already
                $WindowsOptionalFeatureStatuses = Get-WindowsOptionalFeature -Online -FeatureName $Feature -ErrorAction SilentlyContinue

                if ($null -ne $WindowsOptionalFeatureStatuses) {
                    
                    foreach ($WindowsOptionalFeatureStatus in $WindowsOptionalFeatureStatuses) {
                        if ($WindowsOptionalFeatureStatus.State -ne 'Enabled') {
                            $WSUSStatus = Get-WSUSStatus
    
                            if ($WSUSStatus) {
                                try {
                                    Disable-WSUS -ErrorAction Stop -WhatIf:$WhatIfPreference
                                } catch {
                                    Throw "Failed to disable WSUS, stopping."
                                }
                            }
                            # Install Windows Optional  Feature
                            try {
                                Write-Host -ForegroundColor Yellow "Attempting to install Windows Optional Feature $($WindowsOptionalFeatureStatus.FeatureName)..."
                                Install-AnyWindowsFeature -FeatureName $($WindowsOptionalFeatureStatus.FeatureName) -WindowsOptionalFeature -ErrorAction Stop -WhatIf:$WhatIfPreference
                            } catch {
                                Throw "Failed to install Windows Optional Feature $($WindowsOptionalFeatureStatus.FeatureName), stopping."
                            }
                        } else {
                            Write-Host -ForegroundColor Green "Windows Optional Feature $($WindowsOptionalFeatureStatus.FeatureName) was already installed!"
                        }
                    }
                }
            }
            {($_ -in $WindowsCapabilityNames) -or ($WindowsCapabilityNames -like $_)} {
                # Check if the feature was installed already
                $WindowsCapabilityStatuses = Get-WindowsCapability -Online -Name $Feature -ErrorAction SilentlyContinue

                if ($null -ne $WindowsCapabilityStatuses) {

                    foreach ($WindowsCapabilityStatus in $WindowsCapabilityStatuses) {
                        if ($WindowsCapabilityStatus.State -ne "Installed") {

                            # Check if WSUS is active, if so, disable it
                            $WSUSStatus = Get-WSUSStatus
    
                            if ($WSUSStatus) {
                                try {
                                    Disable-WSUS -ErrorAction Stop -WhatIf:$WhatIfPreference
                                } catch {
                                    Throw "Failed to disable WSUS, stopping."
                                }
                            }
                            # WSUS should be disabled at this point
                            # Install Capability Feature
                            try {
                                Write-Host -ForegroundColor Yellow "Attempting to install Windows Capability Feature $($WindowsCapabilityStatus.Name)..."
                                Install-AnyWindowsFeature -FeatureName $($WindowsCapabilityStatus.Name) -WindowsCapability -ErrorAction Stop -WhatIf:$WhatIfPreference
                            } catch {
                                Throw "Failed to install Windows Capability Feature $($WindowsCapabilityStatus.Name), stopping."
                            }
                        } else {
                            Write-Host -ForegroundColor Green "Windows Capability Feature $($WindowsCapabilityStatus.Name) was already installed!"
                        }
                    }
                }
            }
            default {
                Write-Warning "Could not find a Windows Feature, Optional Feature, or Capability feature with the given Feature Name: $Feature."
            }
        }
    }
}

end {
    # Get WSUS Status before stopping
    $EndingWSUSStatus = Get-WSUSStatus
    if ($EndingWSUSStatus -eq $false) {
        write-host -foregroundcolor yellow "Before we end, we must enable WSUS, attempting to Enable WSUS now..."
        Enable-WSUS -ErrorAction Stop -WhatIf:$WhatIfPreference

        $EndingWSUSStatus = Get-WSUSStatus
        if ($EndingWSUSStatus) {
            Write-Host -ForegroundColor Green "WSUS has been Enabled!"
        }
    } elseif ($null -eq $EndingWSUSStatus) {
        Write-Host -ForegroundColor Green "WSUS wasn't configured on this machine, no need to Enable it."
    } else {
        Write-Host -ForegroundColor Green "WSUS was already enabled."
    }
}

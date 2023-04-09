<#
.Synopsis
    This script will create an Automation Account in the provided Resource Group within Azure.
.DESCRIPTION
    This script will create an Automation Account in the provided Resource Group within Azure.
.PARAMETER SubscriptionID
    The Subscription ID within your tenant that will house said Automation Account.
.PARAMETER SubscriptionName
    The Subscription Name within your tenant that will house said Automation Account.
.PARAMETER Name
    The name of the Automation Account.
.PARAMETER ResourceGroupName
    The name of the resource group that the Automation Account will reside in.
.PARAMETER Location
    If you want to override the Location of the provided Resource Group, set the location with this variable.
.PARAMETER AzCreds
    The credentials used to connect to Azure.
.PARAMETER Tags
    A hashtable containing key:value tags attached to the automation account (e.g., @{key0="value"; key1="value2"}
.PARAMETER Plan
    Specifies the plan for the Automation account. Valid values are: Basic, Free
.PARAMETER AssignUserIdentity
    Use this parameter to Enable User Identity while providing the identities to said Automation Account.
.PARAMETER TenantID
    If you have access to multiple tenants, input the TenantID that will house said Service Principal.
.PARAMETER DisablePublicNetworkAccess
    Whether to disable traffic on the non-ARM endpoints
.EXAMPLE
    ./New-ZHLAzAutomationAccount.ps1 -SubscriptionName "ZacksHomeLab" -Name "ZHLAutoAccount" -ResourceGroupName "ZHL" -AzCreds (Get-Credential) -tags @{'zhl-resource'='zhl-automation-account'}

    The above will create an Automation Account named 'ZHLAutoAccount' within Resource Group 'ZHL' and apply tags 'zhl-resource:zhl-automation-account' onto said account.
.EXAMPLE
    ./New-ZHLAzAutomationAccount.ps1 -SubscriptionName "ZacksHomeLab" -Name "ZHLAutoAccount" -ResourceGroupName "ZHL" -AzCreds (Get-Credential) -tags @{'zhl-resource'='zhl-automation-account'} -DisablePublicNetworkAccess
    
    The above will create an Automation Account named 'ZHLAutoAccount' within Resource Group 'ZHL' and apply tags 'zhl-resource:zhl-automation-account' onto said account.
    Once created, we'll update the Automation Account to disable public access.
.NOTES
    Author - Zack
.LINK
    GitHub - https://github.com/ZacksHomeLab
#>
[cmdletbinding()]
param (
    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName="SubscriptionID",
        Position=0)]
        [ValidateScript({if ($null -ne $_) {
            $_ -match "^[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}$"
        }})]
    [string]$SubscriptionID,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName="SubscriptionName",
        Position=0)]
        [ValidateNotNullOrEmpty()]
    [string]$SubscriptionName,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        Position=1)]
        [ValidateNotNullOrEmpty()]
    [string]$Name,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        Position=2)]
        [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [parameter(Mandatory=$false,
        Position=3,
        ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
    [string]$Location,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
    [System.Management.Automation.PSCredential]$AzCreds,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName)]
        [ValidateScript({$_ -is [hashtable] -and $null -ne $_})]
    [hashtable]$Tags,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName)]
        [ValidateSet("Basic", "Free")]
    [string]$Plan,

    [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
    [string[]]$AssignUserIdentity,

    [parameter(Mandatory=$false,
        helpMessage="What is your Tenant ID?")]
        [ValidateScript({if ($null -ne $_) {
            $_ -match "^[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}$"
        }})]
    [string]$TenantID,

    [parameter(Mandatory=$false)]
    [switch]$DisablePublicNetworkAccess
)

#region Variables
$connectParams = @{}
$autoParams = @{}
#endregion

#region Functions
function Import-AZ {
    [cmdletbinding()]
    param (
        [string[]]$Module = 'AZ'
    )

    Process {
        if (-not (Get-Module -Name AZ)) {
            Write-Verbose "`Import-AZ: Checking if we need to install/import AZ..."

            # Install/Import AZ if not installed already
            if (-not (Get-InstalledModule -Name 'AZ' -ErrorAction SilentlyContinue)) {
    
                # Set to TLS 1.2 if it has to go out and download something
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                write-verbose "Import-AZ: Module AZ isn't installed, installing now."
                
                # Install the module
                Install-Module -Name Az -Repository PSGallery -Force -Scope AllUsers

                if (Get-InstalledModule -Name 'Az' -ErrorAction SilentlyContinue) {
                    Write-Verbose "Import-AZ: AZ was sucessfully installed!"
                } else {
                    Throw "Import-AZ: Error installing AZ due to error $_."
                }
                foreach ($Mod in $Module) {
                    # Once Installed, import the module
                    if (-not (Get-Module -Name $Mod -ErrorAction SilentlyContinue)) {
                        Write-Verbose "Import-AZ: Importing Module, this will take some time."
                        Import-Module -name $Mod -ErrorAction SilentlyContinue

                        if (Get-Module -Name $Mod) {
                            Write-Verbose "Import-AZ: Module $Mod was sucessfully imported!"
                        } else {
                            Throw "Import-AZ: Error importing Module $Mod due to error $_."
                        }
                    }
                }
            } else {
                # Module is installed, try to import it
                foreach ($Mod in $Module) {
                    if (-not (Get-Module -Name $Mod -ErrorAction SilentlyContinue)) {
                        Write-Verbose "Import-AZ: Module $Mod was already installed, importing now."
                        Import-Module -name $Mod -ErrorAction SilentlyContinue
    
                        if (Get-Module -Name $Mod) {
                            Write-Verbose "Import-AZ: Module $Mod was sucessfully imported!"
                        } else {
                            Throw "Import-AZ: Error importing Module $Mod"
                        }
                    } else {
                        Write-Verbose "Import-AZ: Module $Mod was already imported."
                    }
                }
            }
        } else {
            Write-Verbose "Import-AZ: Module 'Az' was already imported."
        }
    }
}
#endregion

#region ExitCodes
$exitCode_MissingPowerShellModule = 10
$exitCode_ErrorConnectingToAzure = 11
$exitCode_FailureCreateAutoAccount = 12
$exitCode_LocationDoesNotExist = 13
$exitCode_ResourceGroupNotExist = 14
$exitCode_ResourceGroupAndLocationNotExist = 15
$exitCode_FailureUpdatingAutoAccount = 16
#endregion

#region Connect to Azure Application
try {
    Write-Verbose "Attempting to import Module AZ.Accounts..."
    if (Test-Path -Path "C:\Program Files\WindowsPowerShell\Modules\Az.Accounts") {
        Import-Module 'C:\Program Files\WindowsPowerShell\Modules\Az.Accounts' -ErrorAction SilentlyContinue
    } else {
        Import-AZ -Module 'AZ.Accounts', "AZ.Automation", "AZ.Resources" -ErrorAction Stop
    }
} catch {
    Write-Warning "Failed to Import Module 'AZ.Accounts', 'AZ.Automation', and 'AZ.Resources' due to error $_."
    exit $exitCode_MissingPowerShellModule
}

#region Connect to Azure
try {
    
    # Add Subscription ID or Subscription Name to Connect-AzAccount
    if ($PScmdlet.ParameterSetName -eq 'SubscriptionID') {
        $connectParams.Add('Subscription', $SubscriptionID)
    } elseif ($PSCmdlet.ParameterSetName -eq 'SubscriptionName') {
        $connectParams.Add('Subscription', $SubscriptionName)
    }

    # Add AZ Creds if provided
    if ($PSBoundParameters.ContainsKey('AzCreds')) {
        $connectParams.Add('Credential', $AzCreds)
    }

    if ($PSBoundParameters.ContainsKey('TenantID')) {
        $connectParams.Add('Tenant', $TenantID)
    }

    Connect-AzAccount @connectParams -ErrorAction Stop
    
} catch {
    Write-Warning "Failed to connect to Azure due to error $_."
    exit $exitCode_ErrorConnectingToAzure
}
#endregion

#region Verify the provided region is valid
if ($PSBoundParameters.ContainsKey('Location')) {
    if (-not (Get-AzLocation | Where-Object {$_.DisplayName -eq $Location -or $_.Location -eq $Location})) {
        Write-Warning "Location $Location does not exist within Azure. Verify the location exists using Get-AZLocation."
        exit $exitCode_LocationDoesNotExist
    } else {
        # If the display name were given, set the 'Location' as the Location rather than the DisplayName
        if ($Location -match "\s") {
            $Location = Get-AzLocation | Where-Object DisplayName -eq $Location | Select-Object -ExpandProperty Location
        }
    }
}
#endregion

#region Populate $Location variable if it doesn't exist. Else, verify the resource exists
if ($null -eq $Location -or $Location -eq "") {
    try {
        Write-Verbose "Retrieving Location of Resource Group $ResourceGroupName..."
        $Location = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop | Select-Object -ExpandProperty Location
    } catch {
        Write-Warning "The provided Resource Group Name ($ResourceGroupName) does not exist in Azure."
        exit $exitCode_ResourceGroupNotExist
    }
} else {
    Write-Verbose "Validating if Resource Group $ResourceGroupName and Location $Location exist in Azure..."
    if (-not (Get-AZResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue)) {
        Write-Warning "The provided Resource Group Name ($ResourceGroupName) and Location ($Location) does not exist in Azure."
        exit $exitCode_ResourceGroupAndLocationNotExist
    }
}
#endregion


#region Create Automation Account
try {

    $autoParams.Add('Name', $Name)
    $autoParams.Add('ResourceGroupName', $ResourceGroupName)
    $autoParams.Add('Location', $Location)

    if ($PSBoundParameters.ContainsKey('Plan')) {
        $autoParams.Add('Plan', $Plan)
    }
    if ($PSBoundParameters.ContainsKey('Tags')) {
        $autoParams.Add('Tags', $Tags)
    }

    $autoParams.Add('ErrorAction', 'Stop')

    Write-Verbose "Attempting to create Azure Automation Account $Name in Resource Group $ResourceGroupName"
    New-AzAutomationAccount @autoParams

} catch {
    Write-Warning "Failure creating Automation Account $Name due to error $_."
    exit $exitCode_FailureCreateAutoAccount
}
#endregion

#region Update Automation Account with additional settings provided by user
if ($PSBoundParameters.ContainsKey('AssignUserIdentity') -or $PSBoundParameters.ContainsKey('DisablePublicNetworkAccess')) {
    $updateAccountParams = @{}

    if ($PSBoundParameters.ContainsKey('AssignUserIdentity')) {
        $updateAccountParams.Add('AssignUserIdentity', $AssignUserIdentity)
    }

    if ($PSBoundParameters.ContainsKey('DisablePublicNetworkAccess')) {
        $updateAccountParams.Add('DisablePublicNetworkAccess', $DisablePublicNetworkAccess)
    }

    $updateAccountParams.Add('ResourceGroupName', $ResourceGroupName)
    $updateAccountParams.Add('Name', $Name)
    $updateAccountParams.Add('AssignSystemIdentity', $true)
    if ($PSBoundParameters.ContainsKey('Tags')) {
        $updateAccountParams.Add('Tags', $Tags)
    }
    if ($PSBoundParameters.ContainsKey('Plan')) {
        $updateAccountParams.Add('Plan', $Plan)
    }
    $updateAccountParams.Add('ErrorAction', 'Stop')

    try {
        Write-Verbose "Updating Automation Account $Name with additional provided settings..."
        Set-AzAutomationAccount @updateAccountParams
    } catch {
        Write-Warning "Failed updating Automation Account $Name in Resource Group $ResourceGroupName"
        exit $exitCode_FailureUpdatingAutoAccount
    }
    
}
#endregion
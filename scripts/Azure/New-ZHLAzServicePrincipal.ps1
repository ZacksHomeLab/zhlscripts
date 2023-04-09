<#
.Synopsis
    This script will create an Active Directory Service Principal in your Azure Tenant.
.DESCRIPTION
    This script will connect to Azure and create a new Active Directory Service Principal.
.PARAMETER SubscriptionID
    The Subscription ID within your tenant that will house said Service Principal.
.PARAMETER SubscriptionName
    The Subscription Name within your tenant that will house said Service Principal.
.PARAMETER Name
    The name of the Service Principal OR Applicaiton Name if -CreateApp is present.
.PARAMETER TenantID
    If you have access to multiple tenants, input the TenantID that will house said Service Principal.
.PARAMETER AzCreds
    The credentials used to connect to Azure.
.PARAMETER CreateApp
    Pass this switch if you want to create an Azure Application with your Service Principal and assign the App to said Principal.
.PARAMETER AppName
    The name of the Azure Application you wish to create. If a name is not given, $Name will take its place.
.PARAMETER Tags
    A hashtable containing key:value tags attached to the service principal or application (e.g., @{'key'='value'; 'key2'='value2'}
.EXAMPLE
    ./New-ZHLAzServicePrincipal -SubscriptionName "ZacksHomeLab" -Name "Test SP" -AzCreds (Get-Credential) -tags @{'test'='value'}

    The above will create a Service Principal named "Test SP" within Subscription "ZacksHomeLab".
.EXAMPLE
    ./New-ZHLAzServicePrincipal.ps1 -SubscriptionName "ZacksHomeLab" -AzCreds $AzCreds -Name "ZHLKeyVault" -CreateApp -Tag @{'zhl-resource'='zhl-app-keyvault'}
    
    The above will create an Application within Subscription "ZacksHomeLab", creates a Service Principal from the new Applications, and adds the necessary tags.
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
        Position=1)]
        [ValidateNotNullOrEmpty()]
    [string]$Name,

    [parameter(Mandatory=$false,
        Position=2,
        helpMessage="What is your Tenant ID?")]
        [ValidateScript({if ($null -ne $_) {
            $_ -match "^[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}$"
        }})]
    [string]$TenantID,

    [parameter(Mandatory=$false,
        Position=3)]
        [ValidateNotNullorEmpty()]
    [System.Management.Automation.PSCredential]$AzCreds,

    [parameter(Mandatory=$false,
        Position=4)]
    [switch]$CreateApp,

    [parameter(Mandatory=$false,
        Position=5)]
        [ValidateScript({$_ -is [hashtable] -and $null -ne $_})]
    [hashtable]$Tags
)

#region Variables
$connectParams = @{}
$spParams = @{}

if ($PSBoundParameters.ContainsKey('CreateApp')) {
    $AppID = $null
    $appParams = @{}
}
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
$exitCode_FailureCreateSP = 12
$exitCode_FailureCreateApp = 13
#endregion

#region Connect to Azure Application
try {
    Write-Verbose "Attempting to import Module AZ.Accounts..."
    if (Test-Path -Path "C:\Program Files\WindowsPowerShell\Modules\Az.Accounts") {
        Import-Module 'C:\Program Files\WindowsPowerShell\Modules\Az.Accounts' -ErrorAction SilentlyContinue
    } else {
        Import-AZ -Module 'AZ.Accounts', "AZ.Resources" -ErrorAction Stop
    }
} catch {
    Write-Warning "Failed to Import Module 'AZ.Accounts' and 'AZ.Resources' due to error $_."
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

#region Create Azure Application
if ($PSBoundParameters.ContainsKey('CreateApp')) {

    $appParams.Add('DisplayName', $Name)
    if ($PSBoundParameters.ContainsKey('Tags')) {
        # For some stupid reason, most Azure Cmdlets allow hash tables but not these
        $null = $tagsAsString

        [string[]]$tagsAsString = foreach ($key in $Tags.Keys) {
            "$key`:$($Tags[$key])"
        } 
        $appParams.Add('Tag', $TagsAsString)
    }
    $appParams.Add('ErrorAction', 'Stop')

    try {
        if (-not (Get-AzAdApplication -DisplayNameStartWith $Name -ErrorAction SilentlyContinue)) {
            Write-Verbose "Attempting to create Azure Application $Name..."
            New-AzadApplication @appParams
        } else {
            Write-Verbose "Aplication $Name already exists in Azure, skipping."
        }
    } catch {
        Write-Warning "Failure creating Azure Application $Name due to error $_."
        exit $exitCode_FailureCreateApp
    }
    # Retrieve the Application ID of our new app
    $AppID = Get-AzADApplication -DisplayNameStartWith $Name | Select-Object -ExpandProperty AppId
}
#endregion

#region Create Service Principal
try {

    if ($null -ne $AppID) {
        $spParams.Add('ApplicationId', $AppID)
    } else {
        $spParams.Add('DisplayName', $Name)
    }

    if ($PSBoundParameters.ContainsKey('Tags')) {
        $null = $tagsAsString

        [string[]]$tagsAsString = foreach ($key in $Tags.Keys) {
            "$key`:$($Tags[$key])"
        } 
        $spParams.Add('Tag', $tagsAsString)
    }
    $spParams.Add('ErrorAction', 'Stop')

    Write-Verbose "Attempting to create Azure Service Principal $Name..."
    New-AzADServicePrincipal @spParams

} catch {
    Write-Warning "Failure creating Service Principal due to error $_."
    exit $exitCode_FailureCreateSP
}
#endregion
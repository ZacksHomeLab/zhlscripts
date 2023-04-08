<#
.Synopsis
    This script will create an Active Directory Service Principal in your Azure Tenant.
.DESCRIPTION
    This script will connect to Azure and create a new Active Directory Service Principal.
.PARAMETER SubscriptionID
    The Subscription ID within your tenant that will house said Service Principal.
.PARAMETER SubscriptionName
    The Subscription Name within your tenant that will house said Service Principal.
.PARAMETER SPName
    The name of the Service Principal. You may use a display name that already exists within Azure.
.PARAMETER TenantID
    If you have access to multiple tenants, input the TenantID that will house said Service Principal.
.PARAMETER AzCreds
    The credentials used to connect to Azure.
.PARAMETER CreateApp
    Pass this switch if you want to create an Azure Application with your Service Principal and assign the App to said Principal.
.PARAMETER AppName
    The name of the Azure Application you wish to create. If a name is not given, $SPName will take its place.
.EXAMPLE
    ./New-AzServicePrincipal -SubscriptionName "ZacksHomeLab" -SPName "Test SP" -AzCreds (Get-Credential)

    The above will create a Service Principal named "Test SP" within Subscription "ZacksHomeLab".
.EXAMPLE
    ./New-AzServicePrincipal -SubscriptionID "12341234-1234-1234-123412341234" -CreateApp -AppName "TestApp"
    
    The above will create a Service Principal named "Test SP", create an Azure App named 'TestApp' and assign said app to our new Service Principal.
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
        Position=1,
        helpMessage="What do you want to name your Service Principal?")]
        [ValidateNotNullOrEmpty()]
    [string]$SPName,

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
        Position=5,
        HelpMessage="Enter the name of your Azure Application")]
        [ValidateNotNullOrEmpty()]
    [string]$AppName
)

#region Variables
$connectParams = @{}
$newSPParams = @{}

if ($PSBoundParameters.ContainsKey('CreateApp')) {
    if ($null -eq $AppName -or $AppName -eq "") {
        # Set AppName to SPName if an App Name wasn't provided
        $AppName = $SPName
    }

    $AppID = $null
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

    try {
        if (-not (Get-AzAdApplication -DisplayNameStartWith $AppName -ErrorAction SilentlyContinue)) {
            Write-Verbose "Attempting to create Azure Application $AppName..."
            New-AzadApplication -DisplayName $AppName -ErrorAction Stop
        } else {
            Write-Verbose "Aplication $AppName already exists in Azure, skipping."
        }
    } catch {
        Write-Warning "Failure creating Azure Application $AppName due to error $_."
        exit $exitCode_FailureCreateApp
    }
    # Retrieve the Application ID of our new app
    $AppID = Get-AzADApplication -DisplayNameStartWith $AppName | Select-Object -ExpandProperty AppId
}
#endregion

#region Create Service Principal
try {
    if ($null -ne $AppID) {
        Write-Verbose "Attempting to create Azure Service Principal with existing application $AppName"
        New-AzADServicePrincipal -ApplicationId $AppID -ErrorAction Stop
    } else {
        Write-Verbose "Attempting to create Azure Service Principal $SPName..."
        New-AzADServicePrincipal -DisplayName $SPName
    }
} catch {
    Write-Warning "Failure creating Service Principal due to error $_."
    Disconnect-AzAccount
    exit $exitCode_FailureCreateSP
}
#endregion

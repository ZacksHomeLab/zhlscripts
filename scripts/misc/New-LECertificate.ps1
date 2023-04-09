<#
.Synopsis
    This script creates a New Let's Encrypt SSL Certificate using CloudFlare as the DNS Resolver.
.DESCRIPTION
    This script creates a New Let's Encrypt SSL Certificate using CloudFlare as the DNS Resolver. This script also has the option for accessing CloudFlare details
    within Azure Key Vault.
.PARAMETER Email
    The Email address to be notified with Let's Encrypt renewal notices.
.PARAMETER Hostname
    The FQDN/Subject of the SSL Certificate.
.PARAMETER SANs
    Comma separated FQDN list of additional SANs for your SSL Certificate.
.PARAMETER CFToken
    The CloudFlare token to authorize said API calls.
.PARAMETER CFEmail
    If your CloudFlare Email Address is different than $Email, provide it here.
.PARAMETER AzCreds
    The credentials used to connect to Azure.
.PARAMETER KeyVaultName
    The name of your Key Vault in Azure.
.PARAMETER KeyVaultItem
    The name of the key vault item that holds your CloudFlare API Token
.PARAMETER CreateScheduleTask
    Pass this switch if you would like to create a scheduled task on your computer to renew the SSL Certificate.
.PARAMETER CreateCronTask
    Pass this switch if you would like to create a Cron job on your machine to renew the SSL Certificate.
.PARAMETER RenewSSL
    Pass this parameter if you are renewing the certificate rather than creating a new one.
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
        Position=0)]
        [ValidateScript({$_ -match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"})]
    [string]$Email,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        Position=1)]
        [ValidateScript({$_ -match "^(?=.{1,255}$)([a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"})]
    [string]$Hostname,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName,
        Position=2)]
        [ValidateScript({$_ | Foreach-Object { 
            $_ -match "^(?=.{1,255}$)([a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        }})]
    [string[]]$SANs,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName,
        ParameterSetName="CF",
        Position=3)]
    [string]$CFEmail,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName="CF",
        Position=4)]
    [System.Security.SecureString]$CFToken,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName="KeyVault",
        Position=3)]
        [ValidateNotNullOrEmpty()]
    [string]$KeyVaultName,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName="KeyVault",
        Position=4)]
        [ValidateNotNullOrEmpty()]
    [string]$KeyVaultItem,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName,
        ParameterSetName="KeyVault")]
        [ValidateNotNullOrEmpty()]
    [string]$KeyVaultItemVersion,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName)]
        [ValidateSet("CloudFlare")]
    [string]$DNSPlugin,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName,
        ParameterSetName="KeyVault")]
        [ValidateNotNullorEmpty()]
    [System.Management.Automation.PSCredential]$AzCreds
)

#region Variables
$leParams = @{}
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
$exitCode_FailureRetrievingSecret = 12
$exitcode_MissingCertbot = 13
$exitCode_MissingSnap = 14
#endregion

#region Verify Certbot exists
if ($null -eq (Get-Command -Name "certbot")) {
    Write-Warning "Certbot is not installed, stopping."
    exit $exitcode_MissingCertbot
}
#endregion

#region verify our DNS Plugin exists
if ($PSBoundParameters.ContainsKey('DNSPlugin')) {
    if ($null -eq (Get-Command -Name "snap" -ErrorAction SilentlyContinue)) {
        Write-Warning "Snap is not installed, stopping."
        exit $exitCode_MissingSnap
    }

    
}
#endregion

#region Connect to Azure Application
try {
    Write-Verbose "Attempting to import Module AZ.Accounts..."
    if (Test-Path -Path "C:\Program Files\WindowsPowerShell\Modules\Az.Accounts") {
        Import-Module 'C:\Program Files\WindowsPowerShell\Modules\Az.Accounts' -ErrorAction SilentlyContinue
    } else {
        Import-AZ -Module 'AZ.KeyVault', "AZ.Accounts" -ErrorAction Stop
    }
} catch {
    Write-Warning "Failed to Import Module 'AZ.Accounts' and 'AZ.KeyVault' due to error $_."
    exit $exitCode_MissingPowerShellModule
}

#region Connect to Azure
if ($PSCmdlet.ParameterSetName -eq 'KeyVault') {

    $connectParams = @{}
    $secretParams = @{}
    try {
        # Add AZ Creds if provided
        if ($PSBoundParameters.ContainsKey('AzCreds')) {
            $connectParams.Add('Credential', $AzCreds)
        }
        $connectParams.Add('ErrorAction', "Stop")
        Connect-AzAccount @connectParams
        
    } catch {
        Write-Warning "Failed to connect to Azure due to error $_."
        exit $exitCode_ErrorConnectingToAzure
    }

    # Retrieve key vault secret
    $secretParams.Add('VaultName', $KeyVaultName)
    $secretParams.Add('VaultName', $KeyVaultItem)
    if ($PSBoundParameters.ContainsKey('KeyVaultItemVersion')) {
        $secretParams.Add('Version', $KeyVaultItemVersion)
    }
    $secretParams.Add('ErrorAction', "Stop")

    try {
        Write-Verbose "Attempting to item $KeyVaultItem from vault $KeyVaultName..."
        $KeyVaultSecret = Get-AzKeyVaultSecret @secretParams
    } catch {
        Write-Warning "Failure retrieving secret from vault $KeyVaultName and item $KeyVaultItem due to error $_"
        exit $exitCode_FailureRetrievingSecret
    }
    
}
#endregion
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
.PARAMETER CFFile
    The path of the file that will store your DNS Plugin Credentials.
.PARAMETER KeyVaultName
    The name of your Key Vault in Azure.
.PARAMETER KeyVaultItem
    The name of the key vault item that holds your CloudFlare API Token
.PARAMETER KeyVaultItemVersion
    The specific version of your Key Vault Item to use.
.PARAMETER AzCreds
    The credentials used to connect to Azure.
.PARAMETER DNSPlugin
    The DNS Plugin certbot will use.
.PARAMETER DryRun
    Pass this switch to perform a test run without creating any certificates. 
.PARAMETER CreateRenewalTask
    Pass this switch if you would like to create a scheduled task on your machine to renew said SSL Certificate.
.EXAMPLE
    ./New-LECertificate.ps1 -Email 'zack@zackshomelab.com' -Hostname 'test.zackshomelab.com' -SANs 'test2.zackshomelab.com', 'test3.zackshomelab.com' `
        -CFToken (Read-Host -Prompt "Enter your CF Token" -AsSecureString) -CFFile "$($ENV:HOME)/.secrets/le_creds.json" -DNSPlugin CloudFlare `
        -CreateRenewalTask

    The above performs the following:
      * Creates a SSL Certificate with the hostname of test.zackshomelab.com
      * Adds two additional domains ('test2 & test3) to the certificate
      * Asks the user to input their CloudFlare Token for authorization
      * Uses Email 'zack@zackshomelab.com' as the notification email
      * Store the token at path $($ENV:HOME)/.secrets/le_creds.json (translates to /root/.secrets/le_creds.json)
      * Creates a scheduled task (cron job in my example as I'm running this on Linux) to renew said certificate
.NOTES
    Author - Zack
.LINK
    GitHub - https://github.com/ZacksHomeLab
#>
[cmdletbinding(DefaultParameterSetName="default")]
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
    [System.Security.SecureString]$CFToken,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName)]
    [String]$CFFile,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName="KeyVault",
        Position=3)]
        [ValidateNotNullOrEmpty()]
    [string]$KeyVaultName,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName="KeyVault")]
        [ValidateNotNullOrEmpty()]
    [string]$KeyVaultItem,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName,
        ParameterSetName="KeyVault")]
        [ValidateNotNullOrEmpty()]
    [string]$KeyVaultItemVersion,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName,
        ParameterSetName="KeyVault")]
        [ValidateNotNullorEmpty()]
    [System.Management.Automation.PSCredential]$AzCreds,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName)]
        [ValidateSet("CloudFlare")]
    [string]$DNSPlugin = "CloudFlare",

    [switch]$DryRun,
    [switch]$CreateRenewalTask
)

#region Variables
$leParams = @()
$leCommand = $null
$snapExists = $false
$pipExists = $false
$secret = $null
$existingToken = $null
$crontabFile = $null
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

function Start-Command {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$CommandPath,

        [parameter(Mandatory=$false,
            Position=1,
            ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
        [string]$CommandArguments,

        [parameter(Mandatory=$false,
            Position=2)]
            [ValidateNotNullOrEmpty()]
        [string]$CommandTitle = "Command"
    )

    begin {
        $commandInfo = New-Object System.Diagnostics.ProcessStartInfo
        $process = New-Object System.Diagnostics.Process
    }
    process {

        try {
            $commandInfo.FileName = $commandPath
            $commandInfo.RedirectStandardError = $true
            $commandInfo.RedirectStandardOutput = $true
            $commandInfo.UseShellExecute = $false
            if ($PSBoundParameters.ContainsKey('commandArguments')) {
                $commandInfo.Arguments = $commandArguments
            }
            
            $process.StartInfo = $commandInfo
            $process.Start() | Out-Null
            $process.WaitForExit()
            [pscustomobject]@{
                Title = $commandTitle
                Output = $process.StandardOutput.ReadToEnd()
                Error = $process.StandardError.ReadToEnd()
                ExitCode = $process.ExitCode
            }
        } catch {
            Throw "Start-Command: Failed running command $commandPath due to error $_"
        }
    }
}
#endregion

#region ExitCodes
$exitcode_NotRoot = 9
$exitCode_MissingPowerShellModule = 10
$exitCode_ErrorConnectingToAzure = 11
$exitCode_FailureRetrievingSecret = 12
$exitcode_MissingCertbot = 13
$exitCode_MissingSnapAndPip = 14
$exitCode_FailCreateCredsFile = 15
$exitCode_MissingPIPDNSPlugin = 16
$exitCode_MissingSnapDNSPlugin = 17
$exitCode_FailureCreateCert = 18
$exitCode_FailureCreateCrontabFile = 19
$exitCode_FailureCreateCronJob = 20
$exitCode_VaultItemEmpty = 21
#endregion

#Requires -RunAsAdministrator

#region Check if Admin
if ([System.Environment]::OSVersion.Platform -eq "Unix") {
    if ($(whoami) -ne "root") {
        Write-Warning "Main: You must run this script as root, stopping."
        exit $exitcode_NotRoot
    }
}
#endregion

#region Verify Certbot exists
if ($null -eq (Get-Command -Name "certbot")) {
    Write-Warning "Certbot is not installed, stopping."
    exit $exitcode_MissingCertbot
}
#endregion

#region verify our DNS Plugin exists
if ($PSBoundParameters.ContainsKey('DNSPlugin')) {
    $pipPlugin = $null
    $snapPlugin = $null

    if ($null -ne (Get-Command -Name "pip" -ErrorAction SilentlyContinue)) {
        $pipExists = $true
    } 
    if ($null -ne (Get-Command -Name "snap" -ErrorAction SilentlyContinue)) {
        $snapExists = $true
    } 
    if ($snapExists -eq $false -and $pipExists -eq $false) {
        Write-Warning "You need to have your DNS Plugin installed via 'snap' or 'pip' before proceeding."
        exit $exitCode_MissingSnapAndPip
    }

    # Check if Plugin exists
    if ($pipExists) {
        $pipPlugin = (Start-Command -CommandPath (Get-Command -Name 'pip').Source -CommandArguments "list" -CommandTitle "pip").Output
        
        if (-not ($pipPlugin -match "certbot-dns-$($DNSPlugin.ToLower())")) {
            if (-not $snapExists) {
                Write-Warning "Missing Certbot DNS Resolver plugin: 'certbot-dns-$($DNSPlugin.toLower())'. Run 'pip install certbot-dns-$($DNSPlugin.toLower())'"
                exit $exitCode_MissingPIPDNSPlugin
            } else {
                Write-Warning "Missing Certbot DNS Resolver plugin in 'pip'. Going to check if it exists via 'snap'..."
            }
            
        }
    }
    if ($snapExists) {
        $snapPlugin = Start-Command -CommandPath (Get-Command -Name 'snap').Source -CommandArguments "install certbot-dns-$($DNSPlugin.toLower())" -CommandTitle "snap"
        if ($snapPlugin.ExitCode -ne 0) {
            Write-Warning "Missing Certbot DNS Resolver plugin: 'certbot-dns-$($DNSPlugin.toLower())'. Run 'snap install certbot-dns-$($DNSPlugin.toLower())'"
            exit $exitCode_MissingSnapDNSPlugin
        }
    }
}
#endregion

#region Connect to Azure and retrieve KeyVaultItem
if ($PSCmdlet.ParameterSetName -eq 'KeyVault') {

    $connectParams = @{}
    $secretParams = @{}

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
    
    # Exit if user forgot to save their credentials in their vault item in Azure
    if ($null -eq $KeyVaultSecret -or $KeyVaultSecret -eq "") {
        Write-Warning "Successfully retrieved $KeyVaultItem from vault $KeyVault. However, there doesn't appear to be any credentials within said item."
        exit $exitCode_VaultItemEmpty
    }
}
#endregion

#region Store credentials for later usage if the token were provided
if ([System.Environment]::OSVersion.Platform -eq "Unix") {

    if ($PSCmdlet.ParameterSetName -eq 'CF') {
        $secret = $CFToken
    } elseif ($PSCmdlet.ParameterSetName -eq 'KeyVault') {
        $secret = $KeyVaultSecret
    }
   
    if (-not (Test-Path -Path $CFFile)) {
        if (-not (Test-Path -Path $(Split-Path -Path $CFFile -Parent))) {
            Write-Verbose "Creating directory $(Split-Path -Path $CFFile -Parent)..."
            New-Item -Path $(Split-Path -Path $CFFile -Parent) -ItemType Directory -Force | Out-Null
        }

        # Save token to $CFFile if $CFToken was provided
        try {
            Write-Verbose "Saving Secret to $CFFile..."
            Tee-Object -FilePath $CFFile -InputObject "dns_cloudflare_api_token=$($secret | ConvertFrom-SecureString -AsPlainText)" -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "Failure creating credential file at '$CFFile' due to error $_"
            exit $exitCode_FailCreateCredsFile
        }
        
        # Modify file permissions for le_creds.json
        Write-Verbose "Changing ownership and permissions for $CFFile.."
        Start-Command -CommandPath (Get-Command -Name 'chown').Source -CommandArguments "root:root $CFFile" -CommandTitle "chown"
        Start-Command -CommandPath (Get-Command -Name 'chmod').Source -CommandArguments "600 $CFFile" -CommandTitle "chown"

    } else {

        # Tokenfile exists, retrieve content

        Write-Verbose "Retrieving token from $CFFile (if it exists)"
        $existingToken = $((Select-String -Path $CFFile -Pattern '(?<=\=\s*)(.*)' -AllMatches -ErrorAction SilentlyContinue).Matches.Value.Trim()) | ConvertTo-SecureString -AsPlainText -ErrorAction SilentlyContinue

        # if existing token is null and user didn't provide a token, end script.
        if ($PSCmdlet.ParameterSetName -eq "Default" -and ($null -eq $existingToken -or $existingToken -eq "")) {
            Write-Warning "Secret file $CFFile is empty and you did not provide a CFToken nor KeyVaultItem, stopping."
            exit $exitCode_FailCreateCredsFile
        }

        # Check if the provided secret matches the existing secret
        if (($secret | ConvertFrom-SecureString -AsPlainText) -ne ($existingToken | ConvertFrom-SecureString -AsPlainText)) {
            try {
                Write-Verbose "The provided token is different than the saved token, overwriting..."
                Tee-Object -FilePath $CFFile -InputObject "dns_cloudflare_api_token=$($secret | ConvertFrom-SecureString -AsPlainText)" -ErrorAction Stop | Out-Null
            } catch {
                Write-Warning "Failure creating credential file at '$CFFile' due to error $_"
                exit $exitCode_FailCreateCredsFile
            }
        }
    }
} else {
    # Windows Stuff here
}
#endregion

#region Create SSL Certificate
try {
    #region Build Certbot command
    $leParams += "certonly"
    if ($PSBoundParameters.ContainsKey('DNSPlugin')) {
        $leParams += "--dns-$($DNSPlugin.toLower())"
        $leParams += "--dns-$($DNSPlugin.toLower())-propagation-seconds 30"
        $leParams += "--dns-$($DNSPlugin.toLower())-credentials $CFFile"
    }

    $leParams += "-d $($Hostname.toLower())"
    if ($PSBoundParameters.ContainsKey('SANs')) {
        foreach ($SAN in $SANs) {
            if ($null -ne $SAN -and $SAN -ne "") {
                $leParams += "-d $($SAN.toLower())"
            }
        }
    }
    $leParams += "--agree-tos"
    # Run non-interactively
    $leParams += "-n"
    $leParams += "-m $Email"

    if ($DryRun) {
        $leParams += "--dry-run"
    }
    #endregion
    
    # Create the Let's Encrypt Command
    $leCommand = $leParams -join ' '

    # Run the certificate
    Write-Verbose "Attempting to run 'certbot $leCommand..."
    $certCommand = Start-Command -CommandPath (Get-Command -Name 'certbot').Source -CommandArguments $leCommand -CommandTitle "Certbot"

    if ($certCommand.ExitCode -ne 0) {
        Write-Warning "Certbot failed with exit code $($certCommand.ExitCode) due to error $($certCommand.Error)"
        exit $exitCode_FailureCreateCert
    }
} catch {
    Write-Warning "Failure creating certificate due to error $_"
}
#endregion

#region Create Cron job
if ($CreateRenewalTask -and $DryRun -ne $true) {
    if ([System.Environment]::OSVersion.Platform -eq "Unix") {
        $crontabFile = "/var/spool/cron/crontabs/$(whoami)"
        Write-Verbose "Before creating the cron job, verify it doesn't exist"
        if (Test-Path -Path $crontabFile) {
            $crontabFileContent = $((Select-String -Path $crontabFile -Pattern "certbot renew --dns-$($DNSPlugin.toLower())-propagation-seconds 20$" `
                -AllMatches -ErrorAction SilentlyContinue).Matches.Value.Trim())
            if ($null -ne $crontabFileContent -and $crontabFileContent -ne "") {
                Write-Verbose "Cron job already exists"
                exit 0
            }
        } else {
            try {
                Write-Verbose "Crontab file doesn't exist, creating it now..."
                New-Item -Path $crontabFile -ItemType File -ErrorAction Stop
            } catch {
                Write-Warning "Failure creating crontab file $crontabFile due to error $_"
                exit $exitCode_FailureCreateCrontabFile
            }
        }

        try {
            Write-Verbose "Cron job doesn't exist, adding said job to file $crontabFile"
            Add-Content -Path $crontabFile -Value "0 0,12 * * * certbot renew --dns-$($DNSPlugin.toLower())-propagation-seconds 20" -ErrorAction Stop
        } catch {
            Write-Warning "Failure creating cron job in file $crontabFile due to error $_"
            exit $exitCode_FailureCreateCronJob
        }
    }
} else {
    if ($CreateRenewalTask -and $DryRun) {
        Write-Warning "You cannot create a scheduled renewal job while passing -DryRun."
        exit 0
    }
}
#endregion
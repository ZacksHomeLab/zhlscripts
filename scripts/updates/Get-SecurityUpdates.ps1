
<#
.Synopsis
    This script will install security updates in Windows.
.DESCRIPTION
    This script will do the following:
        * Install/import PowerShell module 'PSWindowsUpdate'
        * Retrieve and filter for security related updates
        * Install said updates (if applicable)
        * Send an email report (if provided said email settings)
        * Export said update data to a provided path (if provided)
.PARAMETER Path
    The path to the CSV that will hold said update data. 
.PARAMETER AutoReboot
    If an update requires a reboot, you can pass this switch to automatically reboot the machine if an update requires it.
.PARAMETER Install
    Pass this switch to install said found security updates.
.PARAMETER SendReport
    To send an email report of said update installations, pass this switch. You will need to provide -EmailSettings and -EmailCreds.
.PARAMETER EmailSettings
    Provide the hashtable of information for your email server, for example:
    $emailSettings = @{
        To = "your_email@company.com"
        From = "your_from_email@company.com"
        Subject + "$(Get-Date.toString('yyyy-MM-dd')): Update Status"
        Port = 25
        SmtpServer = "my.smtpserver.com"
    }
.PARAMETER -Credential
    If your email requires credentials to send said email, use this parameter with (Get-Credential).
.PARAMETER TestEmail
    Use this switch to validate your email settings.
.EXAMPLE
    $EmailSettings = @{
        From = "zack@zhl.info"
        To = "zack@zackshomelab.com"
        SmtpServer = "smtp.office365.com"
        Port = 587
        Subject = "Test Email"
        UseSSL = $true
    }

    $EmailCreds = (Get-Credential)

    .\Get-SecurityUpdates.ps1 -EmailSettings $EmailSettings -Credential $EmailCreds -TestEmail

    The above example verifies your provided email settings before running any updates. This will help
    validate your email settings before updating said system(s).
.EXAMPLE

    $EmailSettings = @{
        Port = 587
        To = "zack@zackshomelab.com"
        From = "zack@zhl.info"
        SmtpServer = "smtp.office365.com"
        Subject = "$((Get-Date).toString('yyyy-MM-dd')): Update Report"
        UseSSL = $true
    }

    $EmailCreds = (Get-Credential)

    ./Get-SecurityUpdates.ps1 -Path ".\Updates.csv" -AutoReboot -Install -SendReport -EmailSettings $EmailSettings -Credential $EmailCreds

    The above example will perform the following:
        - Install Security Updates and reboot if required
        - Export the update information to Updates.csv in the current directory
        - Email a report to my email address
.NOTES
    Author - Zack Flowers
.LINK
    GitHub - https://github.com/ZacksHomeLab
#>
[cmdletbinding()]
param (
    [parameter(Mandatory=$false,
        ValueFromPipeline,
        ValueFromPipelineByPropertyName)]
    [string]$Path,

    [parameter(Mandatory=$false)]
    [switch]$AutoReboot,

    [parameter(Mandatory=$false)]
    [switch]$Install,

    [parameter(Mandatory,
        ParameterSetName="SendReport")]
    [switch]$SendReport,

    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ValueFromRemainingArguments,
        ParameterSetName="SendReport")]
    [parameter(Mandatory,
        ValueFromPipelineByPropertyName,
        ValueFromRemainingArguments,
        ParameterSetName="TestEmail")]
    [ValidateScript({
        $_.Keys -contains "Port" -and
        $_.Keys -contains "To" -and
        $_.Keys -contains "From" -and
        $_.Keys -contains "SmtpServer" -and
        $_.Keys -contains "Subject"
    })]
    [hashtable]$EmailSettings,

    [parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName,
        ValueFromRemainingArguments)]
    [pscredential]$Credential,

    [parameter(Mandatory,
        ParameterSetName="TestEmail")]
    [switch]$TestEmail
)

function Import-PSWindowsUpdate {
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false)]
        [switch]$InstallModule
    )

    Begin {

        $module = "PSWindowsUpdate"
        # Exit if the module is already imported.
        if (Get-Module -Name $module -ErrorAction SilentlyContinue) {
            Write-Verbose "Import-PSWindowsUpdate: PowerShell Module $module already imported."
            return
        }
    }
    Process {
        # Import the module if it exists
        if (Get-InstalledModule -Name $module -ErrorAction SilentlyContinue) {
            Try {
                Import-Module -Name $module -ErrorAction Stop
            } catch {
                Throw "Import-PSWindowsUpdate: Failure importing PowerShell Module $module due to error $_."
            }

        }
        # If PowerShell Module 'PSWindowsUpdate' is not installed and the user did not pass -InstallModule, throw an error.
        if (-not ($InstallModule) -and (Get-InstalledModule -Name $module -ErrorAction SilentlyContinue)) {
            Write-Debug "Import-PSWindowsUpdate: PowerShell Module $module was not installed."
            Throw "Import-PSWindowsUpdate: PowerShell Module $module was not installed. `nImport-PSWindowsUpdate: Please install said module or pass switch '-installModule' and run the script again"
        }

        # Install the module
        try {
            Install-Module -Name $module -Force -ErrorAction Stop
        } catch {
            Throw "Import-PSWindowsUpdate: Failure installing PowerShell Module $module due to error $_."
        }
        

        # Import the module after install
        try {
            Write-Verbose "Import-PSWindowsUpdate: Importing PowerShell Module $module."
            Import-module -Name $module -Force -ErrorAction Stop
        } catch {
            Throw "Import-PSWindowsUpdate: Failure importing PowerShell Module $module due to error $_."
        }
    }
}

function Get-SUpdates {
    [cmdletbinding()]
    param (
    )

    Begin {
        # Filter Windows Update for these categories
        $categoryIds = @{
            "security_updates" = "0fa1201d-4330-4fa8-8ae9-b877473b6441"
            "microsoft_defender_updates" = "8c3fcc84-7410-4a95-8b89-a166a0190486"
            "definition_updates" = "e0789628-ce08-4437-be74-2495b842f43b"
            "critical_updates" = "e6cf1350-c01b-414d-a61f-263d14d133b4"
        }
        $updates = $null
    }

    Process {
        try {
            Write-Verbose "Get-SecurityUpdates: Gathering security updates..."
            $updates = Get-WindowsUpdate -CategoryIDs $($categoryIds.Values) -ErrorAction Stop

            return $updates
        } catch {
            Throw "Get-SecurityUpdates: Failure gathering Windows Updates due to error $_."
        }
    }
}

function Install-SecurityUpdates {
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false)]
        [switch]$AutoReboot,

        [parameter(Mandatory=$false)]
        [switch]$Install,

        [parameter(Mandatory,
            ParameterSetName="SendReport")]
        [switch]$SendReport,

        [parameter(Mandatory,
            ParameterSetName="SendReport")]
        [hashtable]$EmailSettings,

        [parameter(Mandatory=$false)]
        [pscredential]$EmailCreds
    )

    Begin {
        
        # If -AutoReboot was not provided, set it to false
        if (-not ($PSBoundParameters.ContainsKey('AutoReboot'))) {
            $AutoReboot = $false
        }

         # If -Install was not provided, set it to false
        if (-not ($PSBoundParameters.ContainsKey('Install'))) {
            $Install = $false
        }

        # Create a parameter splat for Get-WindowsUpdate
        $param = @{
            CategoryIDs = $($categoryIds.Values)
            Install = $Install
            Confirm = $false
            AutoReboot = $AutoReboot
            ErrorAction = "stop"
        }

        # Add Send Report to Get-WindowsUpdate if provided
        if ($PSCmdlet.ParameterSetName -eq "SendReport") {
            $param.Add("SendReport", $true)
            $param.Add('PSWUSettings', $EmailSettings)
            $param.Add('SendHistory', $true)
        }

        if ($PSBoundParameters.ContainsKey('EmailCreds')) {
            $param.Add('SmtpCredential', $EmailCreds)
        }
    }

    Process {
        try {
            Get-WindowsUpdate @param
        } catch {
            Throw "Install-SecurityUpdates: Failure installing security updates due to error $_"
        }
    }
}

function Export-Updates {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipeline)]
        [string]$Path,

        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
        [Object]$Updates
    )

    Begin {
        $date = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
    }
    Process {
        try {
            $Updates | 
                Select-Object @{Label="Date";Expression={$date}}, ComputerName, KB, Title, Description, `
                    @{Name="CategoryID";Expression={$_.categories.categoryid}} |
                Export-Csv -Path $Path -NoTypeInformation -Append -ErrorAction Stop

        } catch {
            Throw "Export-Updates: Failure exporting data to path $Path due to error $_"
        }
    }
}

#region Send a test email
if ($PSCmdlet.ParameterSetName -eq "TestEmail") {

    $emailParam = @{
        From = $($EmailSettings.From)
        To = $($EmailSettings.To)
        SmtpServer = $($EmailSettings.SmtpServer)
        Subject = $($EmailSettings.Subject)
        Port = $($EmailSettings.Port)
        ErrorAction = "Stop"
    }
    if ($PSBoundParameters.ContainsKey('Credential')) {
        $emailParam.Add('Credential', $Credential)
    }
    if ($EmailSettings.Keys -contains 'UseSSL') {
        $emailParam.Add('UseSSL', $EmailSettings.UseSSL)
    } else {
        $emailParam.Add('UseSSL', $false)
    }

    try {
        Write-Verbose "Get-SecurityUpdates: Attempting to send email..."
        Send-MailMessage @emailParam

    } catch {
        Write-Warning "Get-SecurityUpdates: Failure sending email due to error $_"
        break
    }
    break
}
#endregion

#region Load / Install PowerShell Module PSWindowsUpdate
try {
    Write-Verbose "Get-SecurityUpdates: Installing/Importing module PSWindowsUpdate"
    Import-PSWindowsUpdate -InstallModule -ErrorAction Stop
} catch {
    Throw "Failure loading PowerShell Module $module due to error $_."
}
#endregion

#region Gather security updates
try {
    Write-Verbose "Get-SecurityUpdates: Gathering security Updates..."
    $securityUpdates = Get-SUpdates -ErrorAction Stop
} catch {
    Throw "Get-SecurityUpdates: Failure gathering security updates due to error $_"
}
#endregion

# No updates found, stopping
if ($null -eq $securityUpdates) {
    Write-Warning "Get-SecurityUpdates: No updates were needed."
    exit 0
}
#region Install Security Updates
try {
    Write-Verbose "Get-SecurityUpdates: Installing security updates..."
    if ($null -eq $AutoReboot) {
        $AutoReboot = $false
    }

    if ($null -eq $Install) {
        $Install = $false
    }
    $installParams = @{
        AutoReboot = $AutoReboot
        Install = $Install
        ErrorAction = "Stop"
    }

    if ($PSCmdlet.ParameterSetName -eq 'SendReport') {
        $installParams.Add('SendReport', $true)
        $installParams.Add('EmailSettings', $EmailSettings)

        if ($PSBoundParameters.ContainsKey('EmailCreds')) {
            $installParams.Add('EmailCreds', $EmailCreds)
        }
    }

    Install-SecurityUpdates @installParams
} catch {
    Throw "Get-SecurityUpdates: Failure installing updates due to error $_"
}

#endregion

# Export updates to provided path
if ($PSBoundParameters.ContainsKey('Path')) {
    try {
        Write-Verbose "Get-SecurityUpdates: Saving update log to path $Path..."
        Export-Updates -Path $Path -Updates $securityUpdates -ErrorAction Stop
    } catch {
        Throw "Get-SecurityUpdates: Failure exporting update data to path $Path due to error $_"
    }
}

function Send-Email {
    [cmdletbinding()]
    param (
        [string]$Subject = "DHCP Backup",
        [string]$SMTPServer = "",
        [string]$From = "",
        [string]$To = "",
        [parameter(Mandatory)]
        [ValidateSet('Success', 'Fail')]
        [string]$Results,
        [string]$ErrorMessage
    )

    begin {
        $body = $null
    }

    process {
        $Body += "DHCP Backup Results: $Results"
        if ($PSBoundParameters.ContainsValue('ErrorMessage')) {
            $Body += "Error: $ErrorMessage"
        }
        Send-MailMessage -To $To -From $From -SmtpServer $SMTPServer -Subject $Subject -Body $Body -BodyAsHtml
    }
}

# Exit codes
$exitCode_FailureCreatingDirectory = 10
$exitCode_FailureRunningBackupFunction = 11
$exitCode_FailureFindingBackupFile = 12

try {
    $backuppath = "\\192.168.123.2\Backups\CCC-DC1\DHCP\DHCP-SCOPES-AUTO-BCKUP\dhcp-backup" + ([datetime]::now.ToString('yyyy-MM-dd-hh-mm'))
    Write-Output "Attempting to create Backup Path $BackupPath..."
    if (-not (Test-Path -Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -ErrorAction Stop
    }
} catch {
    $Message = $_ | Out-String
    Write-Error "Failed creating backup directory."
    Send-Email -Subject "DHCP Backup Error: Failure Creating Backup Directory" -ErrorMessage $Message -Results Fail
    exit $exitCode_FailureCreatingDirectory
}

try {
    Write-Output "Attempting to Backup DHCP remotely..."

    Invoke-Command -ComputerName "CCC-DC1" -ScriptBlock {
        Backup-DHCPServer -ComputerName "CCC-DC1" -Path $using:BackupPath -ErrorAction Stop
    } -ErrorAction Stop

} catch {
    $Message = $_ | Out-String
    Write-Error "Failure running Backup-DHCPServer."
    Send-Email -Subject "DHCP Backup Error: Failure running Backup-DHCPServer" -ErrorMessage $Message -Results Fail
    exit $exitCode_FailureRunningBackupFunction
}

if (Test-Path -Path $backuppath) {
    Write-Output "Attempting to send success email..."
    Send-Email -Subject "DHCP Backup Success" -Results Success
} else {
    $Message = "Backup-DHCPServer ran successfully but could not find Backup Item: $BackupPath."
    Write-Error $Message
    Send-Email -Subject "DHCP Backup Error: Failure running Backup-DHCPServer" -ErrorMessage $Message -Results Fail
    exit $exitCode_FailureFindingBackupFile
}

Read-Host -Prompt "Press Enter to exit"

<#
.Synopsis
    A simple automation script to configure my Linux Servers
.DESCRIPTION
    A simple automation script to configure my Linux Servers
.PARAMETER SSHSubnets
    The subnets (in CIDR notation) that will be allowed to SSH into this server. (e.g., 192.168.1.0/24, 192.168.2.0/24)
.PARAMETER Domain
    The Active Directory domain name (e.g., zackshomelab.com)
.PARAMETER NTPServer
    This FQDN of the NTP Server that I use for my own servers (e.g., time.zackshomelab.com) 
.PARAMETER SkipADJoin
    This switch will skip joining to Active Directory. The default is to not skip this step.
.PARAMETER ADUsername
    The username of the account that can add computer objects into said Active Directory Domain
.PARAMETER ADPassword
    The password of the account that can add computer objects into said Active Directory Domain (e.g., ('PASSWORD' | ConvertTo-SecureString -AsPlainText))
.PARAMETER SkipCustomSSHFile
    This switch will skip creating a custom SSH file. The default is to not skip this step.
.PARAMETER SSHADGroups
    The Active Directory Groups that can SSH into this server. (e.g., "Group 1", "Group_2")
.PARAMETER SkipMkhomedir
    This switch will skip configuring mkhomedir for Active Directory accounts. The default is to not skip this step.
.PARAMETER SSSDADGroups
    The Active Directory Groups that can log into said server via local connection. (e.g., "Group 1", "Group_2")
.PARAMETER SudoADGroups
    The Active Directory Groups that can have sudo permissions. (e.g., "Group 1", "Group_2")
.EXAMPLE
    ./Backup-Bitwarden.ps1 -SSHSubnets "192.168.1.0/24" -Domain "zackshomelab.com" -NTPServer "time.zackshomelab.com" -ADUsername "Zack" -ADPassword ('MY_PASSWORD' | ConvertTo-SecureSTring -AsPlainText) `
    -SSHADGroups "server_admins" -SudoADGroups "server_admins"
.NOTES
    Author - Zack
.LINK
    GitHub - https://github.com/ZacksHomeLab/ZacksHomeLab
#>
[cmdletbinding()]
param (
    [parameter(Mandatory,
        Position=0,
        HelpMessage="Enter the IP Range that can SSH into your server (e.g., 192.168.1.0/24)")]
    [ValidateScript({$_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'})]
    [string[]]$SSHSubnets,

    [parameter(Mandatory,
        Position=1)]
        [ValidateScript({$_ -match '^(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})$'})]
    [string]$Domain,

    [parameter(Mandatory=$false,
        Position=2,
        helpMessage="The FQDN of your NTP server (e.g., time.company.com)")]
        [ValidateScript({$_ -match '^(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})$'})]
    [string]$NTPServer,

    [parameter(Mandatory=$false,
        Position=3)]
    [switch]$SkipADJoin = $false,

    [parameter(Mandatory,
        Position=3,
        ParameterSetName="JoinDomain",
        HelpMessage="Enter the Active Directory username that can add computer objects to your Domain")]
        [ValidateNotNullOrEmpty()]
    [string]$ADUsername,

    [parameter(Mandatory,
        Position=4,
        ParameterSetName="JoinDomain",
        HelpMessage="Enter the Password for your AD Account (e.g., ('MY_PASS' | ConvertTo-SecureString -AsPlainText)")]
        [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]$ADPassword,

    [parameter(Mandatory=$false,
        Position=5)]
    [switch]$SkipCustomSSHFile = $false,

    [parameter(Mandatory=$false,
        Position=6,
        HelpMessage="Enter the Active Directory Groups that can SSH into your server, separated by commas")]
        [ValidateNotNullOrEmpty()]
    [string[]]$SSHADGroups,

    [parameter(Mandatory=$false,
        Position=7)]
    [switch]$SkipMkhomedir = $false,

    [parameter(Mandatory=$false,
        Position=8,
        HelpMessage="Enter the Active Directory Groups that can login to this server, separated by commas.")]
        [ValidateNotNullOrEmpty()]
    [string[]]$SSSDADGroups,

    [parameter(Mandatory=$false,
        Position=9,
        HelpMessage="Enter the Active Directory Groups that will have SUDO access, separated by commas.")]
    [string[]]$SudoADGroups
)

begin {
    $SSH_ENABLE_STATUS = $null
    $UFW_ENABLE_STATUS = $null
    $UBUNTU_VERSION = $null
    $UPDATE_NEEDRESTART = $false
    $NEEDRESTART_CONTENTS = $null
    $FOUND_LINE = $null
    $FOUND_LINE_NOWHITESPACE = $null
    $REPLACED_NEEDRESTART_VARIABLE = $false

    $HOSTNAME = hostname
    if ($PSBoundParameters.ContainsKey('Domain')) {
        $FQDN = $($hostname + '.' + $Domain)
    }
    $DEFAULT_PACKAGES = @("ntp realmd libnss-sss libpam-sss sssd sssd-tools adcli samba-common-bin oddjob oddjob-mkhomedir packagekit")

    $NTP_POOLS = $null
    $NTP_SERVERS = $null

    $SSH_AD_GROUPS = $null
    $CUSTOM_SSH_FILE_CONTENTS = $null

    $MKHOMEDIR_CONTENTS = $null

    $SSSD_AD_GROUPS = $null
    $SSSD_CONTENTS = $null
    $SSSD_CONF_PERMISSIONS = "-rw-------"
    $SSSD_CONF_CHECK = $null

    $SUDO_AD_GROUP = $null
    $SUDOER_CONF_CHECK = $null

    #region Config Files
    $UFW_FIREWALL_RULES_CONF = '/etc/ufw/user.rules'
    $NTP_CONF = '/etc/ntp.conf'
    $NEEDRESTART_CONF = '/etc/needrestart/needrestart.conf'
    $CUSTOM_SSH_FILE = "/etc/ssh/sshd_config.d/$DOMAIN.conf"
    $MKHOMEDIR_CONF = "/usr/share/pam-configs/mkhomedir"
    $SSSD_CONF = "/etc/sssd/conf.d/$Domain.conf"
    $SUDOER_CONF = "/etc/sudoers.d/99_ad_groups"
    #endregion

    #region exitcodes
    $exitcode_NotRoot = 9

    # Needrestart.conf exit codes
    $exitcode_NoUbuntuVersion = 10
    $exitcode_FailFindNeedRestartConf = 11
    $exitcode_FailReplaceNeedRestartVariable = 12
    $exitcode_FailAddNeedRestartVariable = 13

    # SSH Exit Codes
    $exitcode_FailEnableSSH = 14
    $exitcode_FailStartSSH = 15
    $exitcode_FailEnableUFW = 16
    $exitcode_FailAdddingSSHSubnet = 17
    $exitcode_FailRestartUFW = 18

    $exitcode_FailInstallDefaultPackages = 19
    $exitcode_FailSetHostName = 20

    # NTP Exit codes
    $exitcode_MissingNTPFile = 21
    $exitcode_FailRemoveNTPPools = 22
    $exitcode_FailRemoveNTPServers = 23
    $exitcode_FailSetNTPServer = 24
    $exitcode_FailFindNTPServer = 25
    $exitcode_FailRestartNTP = 26

    # Custom SSH File Exit Codes
    $exitcode_FailAdddingSSHCustomFileContent = 27
    $exitcode_FailRemoveExistingSSHFile = 28

    # Join Domain Exit Codes
    $exitcode_FailJoiningToDomain = 29
    $exitcode_WrongDomain = 30

    # MKHOMEDIR Contents
    $exitcode_FailReplaceMKHOMEDIRContents = 31
    $exitcode_FailEnableMKHOMEDIR = 32

    # SSSD Exit Codes
    $exitcode_FailRemoveExistingSSSDFile = 33
    $exitcode_FailCreateNewSSSDFile = 34
    $exitcode_FailChangeSSSDPermissions = 35
    $exitcode_FailStoppingSSSD = 36
    $exitcode_FailChangeSSSDDefaultConfigFile = 37
    $exitcode_FailSSSDConfigCheck = 38
    $exitcode_FailSSSDStartup = 39

    # Sudoer File Exit Codes
    $exitcode_FailAddingGroupsToSudoerFile = 40
    $exitcode_FailSudoerValidationCheck = 41
    #endregion
}

process {
    # Stop the script if the user isn't running as root
    if ($PSVersionTable.Platform -eq "Unix") {
        if ($(whoami) -ne "root") {
            Write-Log -EntryType Warning -Message "Main: You must run this script as root, stopping."
            exit $exitcode_NotRoot
        }
    }

    #region Modify needrestart.conf
    # Check what version of Ubuntu we're using
    $UBUNTU_VERSION = (lsb_release -a | Where-Object {$_ -match "Release"}).split(":")[-1].trim() -as [double]
    if ($null -eq $UBUNTU_VERSION) {
        Write-Warning "Main: Could not find the Ubuntu Release version of this server."
        exit $exitcode_NoUbuntuVersion
    } else {
        if ($UBUNTU_VERSION -ge 22.04) {
            $UPDATE_NEEDRESTART = $true
        }
    }

    # Modify /etc/needrestart/needrestart.conf if we're using Ubuntu 22.04
    if ($UPDATE_NEEDRESTART) {
        Write-Output "`nMain: We are at least using Ubuntu 22.04, which means we'll need to update our needrestart.conf file to automate application updates & upgrades."
        if (-not (Test-Path -Path $NEEDRESTART_CONF)) {
            Write-Warning "Main: Could not find needrestart's configuration file at $NEEDRESTART_CONF."
            exit $exitcode_FailFindNeedRestartConf
        }
        # Gather contents of Needrestart.conf
        Write-Output "Main: Gathering needrestart.conf's contents"
        $NEEDRESTART_CONTENTS = Get-Content -Path $NEEDRESTART_CONF
        $NEEDRESTART_RESTART_VARIABLE = $NEEDRESTART_CONTENTS | Where-Object {$_ -match "\$nrconf{restart}"}
        foreach ($FOUND_LINE in $NEEDRESTART_RESTART_VARIABLE) {
            if ($FOUND_LINE -match "^#") {
                Write-Output "Main: First line is commented-out, skipping"
                continue
            }

            #Remove White Space of non-commented out line
            $FOUND_LINE_NOWHITESPACE = $FOUND_LINE.replace(' ','')
            if ($FOUND_LINE_NOWHITESPACE -notmatch "\$nrconf{restart}='a';") {
                # Replace the 
                try {
                    Write-Output "Main: Replacing $FOUND_LINE with $("$" + "nrconf{restart} = 'a';")"
                    (Get-Content -Path $NEEDRESTART_CONF) -replace [regex]::Escape($FOUND_LINE), $("$" + "nrconf{restart} = 'a';") | Set-Content -Path $NEEDRESTART_CONF -Force -ErrorAction Stop
                    $REPLACED_NEEDRESTART_VARIABLE = $true
                } catch {
                    Write-Warning "Main: Failed replacing line $FOUND_LINE in needrestart's configuration file."
                    exit $exitcode_FailReplaceNeedRestartVariable
                }
            } else {
                Write-Output "Main: The variable is applied correctly, no need to investigate futher."
                $REPLACED_NEEDRESTART_VARIABLE = $true
                break
            }
        }
        # If this isn't true, we need to add our own variable in needrestart.conf
        if (-not $REPLACED_NEEDRESTART_VARIABLE) {
            try {
                Write-Output "Main: There wasn't any custom values in needrestart.conf, we'll need to add our own..."
                Add-Content -Path $NEEDRESTART_CONF -Value $("$" + "nrconf{restart} = 'a';") -Force -ErrorAction Stop
            } catch {
                Write-Warning "Main: Failed adding $("$" + "nrconf{restart} = 'a';") to $NEEDRESTART_CONF due to error $_"
                exit $exitcode_FailAddNeedRestartVariable
            }
            
        }
    }
    #endregion

    #region Modify SSH
    # Enable SSH
    try {
        # See if SSH is enabled on boot
        $SSH_ENABLE_STATUS = (systemctl status ssh | grep -i '/lib/systemd') | Where-Object {$_ -Match 'ssh.service; enabled;'}
        if (-not $SSH_ENABLE_STATUS) {
            Start-Process -FilePath (Get-Command -Name systemctl).Source -ArgumentList "enable ssh" -ErrorAction Stop -Wait
        }
    } catch {
        Write-Warning "Main: Failed starting SSH on boot due to error $_"
        exit $exitcode_FailEnableSSH
    }

    # Start SSH
    try {
        # See if SSH is enabled on boot
        if (-not (Get-Process -Name sshd -ErrorAction SilentlyContinue)) {
            Write-Output "Main: Starting SSH..."
            Start-Process -FilePath (Get-Command -Name systemctl).Source -ArgumentList "start ssh" -ErrorAction Stop -Wait
        }
    } catch {
        Write-Warning "Main: Failed starting SSH due to error $_"
        exit $exitcode_FailStartSSH
    }

    # Enable UFW
    try {
        # See if SSH is enabled on boot
        Write-Output "`nMain: Gathering UFW's status"
        $UFW_ENABLE_STATUS = (ufw status | grep -i 'status:') | Where-Object {$_ -Match 'Status: active'}
        if (-not ($UFW_ENABLE_STATUS)) {
            Write-Output "Main: UFW isn't enabled on startup, enabling now."
            Start-Process -FilePath (Get-Command -Name ufw).Source -ArgumentList "enable" -ErrorAction Stop -Wait
        } else {
            Write-Output "Main: UFW is already enabled"
        }
    } catch {
        Write-Warning "Main: Failed starting SSH due to error $_"
        exit $exitcode_FailEnableUFW
    }

    # Add SSH into UFW
    try {
        Write-Output "`nMain: Updating UFW to allow the provided IP Subnets to SSH into the server."
        $UFW_RULE = $null
        foreach ($Subnet in $SSHSubnets) {
            $UFW_RULE = Select-String -Path $UFW_FIREWALL_RULES_CONF -Pattern "^-A ufw-user-input -p tcp --dport 22 -s $Subnet -j ACCEPT$"
            if ($null -eq $UFW_RULE) {
                Write-Verbose "Main: Allowing subnet $Subnet to SSH into this server."
                Start-Process -FilePath (Get-Command -Name ufw).Source -ArgumentList "allow from $Subnet proto tcp to any port 22" -ErrorAction Stop -Wait
            }
        }
    } catch {
        Write-Warning "Main: Failed adding subnet $SSHSubnets to UFW."
        exit $exitcode_FailAdddingSSHSubnet
    }

    # Restart UFW
    try {
        Write-Output "Main: reloading UFW..."
        Start-Process -FilePath (Get-Command -Name ufw).Source -ArgumentList "reload" -ErrorAction Stop -Wait
    } catch {
        Write-Warning "Main: Failed reloading UFW"
        exit $exitcode_FailRestartUFW
    }
    #endregion

    # Install Default Packages
    try {
        Write-Output "`nMain: Installing default packages..."
        Start-Process -FilePath (Get-Command -Name 'apt-get').Source -ArgumentList "-y install $DEFAULT_PACKAGES" -ErrorAction Stop -Wait
    } catch {
        Write-Warning "Main: Failed installing default packages due to error $_"
        exit $exitcode_FailInstallDefaultPackages
    }

    # Set Hostname
    if ($null -ne $FQDN) {
        try {
            Write-Output "`nMain: Setting $HostName's FQDN to $FQDN..."
            Start-Process -FilePath (Get-Command -Name 'hostnamectl').Source -ArgumentList "set-hostname $FQDN" -ErrorAction Stop -Wait
        } catch {
            Write-Warning "Main: Failed to set hostname for $HOSTNAME to $FQDN."
            exit $exitcode_FailSetHostName
        }
    }

    #region set NTP to use the provided NTP Server
    if ($PSBoundParameters.ContainsKey('NTPServer')) {
        Write-Output "`nMain: A NTP Server was provided, updating $NTP_CONF"
        if (-not (Test-Path -Path $NTP_CONF)) {
            Write-Warning "Main: NTP Configuration file $NTP_CONF does not exist. Is NTP Installed?"
            exit $exitcode_MissingNTPFile
        }

        # Gather the NTP Pools & NTP Servers within /etc/ntp.conf
        $NTP_POOLS = Get-Content -Path $NTP_CONF | Where-Object {$_ -match "^pool *."}
        $NTP_SERVERS = Get-Content -Path $NTP_CONF | Where-Object {$_ -match "^server *."}
        
        # Remove NTP Pools
        if ($null -ne $NTP_POOLS) {
            try {
                Write-Output "Main: Commenting out the NTP Pools in $NTP_CONF"
                foreach ($NTP_POOL in $NTP_POOLS) {
                    # Comment out NTP_POOL
                    Write-Verbose "Main: Removing NTP Pool $NTP_POOL"
                    (Get-Content -Path $NTP_CONF) -replace [regex]::Escape($NTP_POOL), $("#" + $NTP_POOL) | Set-Content -Path $NTP_CONF -Force -ErrorAction Stop
                }
            } catch {
                Write-Warning "Main: Failed removing NTP Pools from $NTP_CONF due to error $_"
                exit $exitcode_FailRemoveNTPPools
            }
        }

        if ($null -ne $NTP_SERVERS) {
            # Remove NTP Server
            try {
                Write-Output "Main: Commenting out the NTP Servers in $NTP_CONF"
                foreach ($NTP_SERVER in $NTP_SERVERS) {
                    # Comment out NTP_SERVER
                    Write-Verbose "Main: Removing NTP Server $NTP_SERVER"
                    (Get-Content -Path $NTP_CONF) -replace [regex]::Escape($NTP_SERVER), $("#" + $NTP_SERVER) | Set-Content -Path $NTP_CONF -Force -ErrorAction Stop
                }
            } catch {
                Write-Warning "Main: Failed removing NTP Servers from $NTP_CONF due to error $_"
                exit $exitcode_FailRemoveNTPServers
            }
        }

        # Add our NTP Server
        try {
            Write-Output "Main: Adding NTP Server $NTPServer to $NTP_CONF"
            Add-Content -Path $NTP_CONF -Value "server $NTPServer" -Force -ErrorAction Stop

            # Validate the additional of NTP Server
            if (-not (Select-STring -Path $NTP_CONF -Pattern "^server $NTPServer$")) {
                Write-Warning "Main: Could not find NTP Server ($NTPServer) in $NTP_CONF, stopping."
                exit $exitcode_FailFindNTPServer
            }
        } catch {
            Write-Warning "Main: Failed adding NTP Server $NTPServer to $NTP_CONF due to error $_"
            exit $exitcode_FailSetNTPServer
        }

        # Restart NTP
        try {
            Write-Output "Main: Restarting NTP..."
            Start-Process -FilePath (Get-Command -Name 'systemctl').Source -ArgumentList 'restart ntp' -Wait -ErrorAction Stop
        } catch {
            Write-Warning "Main: Failed restarting NTP due to error $_"
            exit $exitcode_FailRestartNTP
        }
    }
    #endregion

    #region Create Custom SSH Configuration File
    if (-not $SkipCustomSSHFile) {
        Write-Output "`nMain: Creating Custom SSH File: $CUSTOM_SSH_FILE"

        $CUSTOM_SSH_FILE_CONTENTS = "PermitRootLogin no"

        # Generate the SSH_AD_GROUPS string
        if ($PSBoundParameters.ContainsKey('SSHADGroups')) {
            # Create the SSH_AD_GROUPS variable and join the array of provided strings. Replace white space with a backslash
            $SSH_AD_GROUPS = $SSHADGroups.Replace(' ', '\ ') | Join-String -Separator ', '
        }

        if (-not (Test-Path -Path $CUSTOM_SSH_FILE)) {
            try {
                Add-Content -Path $CUSTOM_SSH_FILE -Value $CUSTOM_SSH_FILE_CONTENTS -Force -ErrorAction Stop
                if ($null -ne $SSH_AD_GROUPS) {
                    Add-Content -Path $CUSTOM_SSH_FILE -Value "AllowGroups $SSH_AD_GROUPS" -Force -ErrorAction Stop
                }
            } catch {
                Write-Warning "Main: Failure adding content to the custom ssh file at $CUSTOM_SSH_FILE due to error $_"
                exit $exitcode_FailAdddingSSHCustomFileContent
            }

        } else {
            Write-Output "Main: File $CUSTOM_SSH_FILE already exists, removing."
            # Removing the file and starting over
            try {
                Remove-Item -Path $CUSTOM_SSH_FILE -Force -ErrorAction Stop
            } catch {
                Write-Warning "Main: Failed removing Custom SSH File at $CUSTOM_SSH_FILE due to error $_"
                exit $exitcode_FailRemoveExistingSSHFile
            }
            Write-Output "Main: Creating Custom SSH File: $CUSTOM_SSH_FILE"
            try {
                Add-Content -Path $CUSTOM_SSH_FILE -Value $CUSTOM_SSH_FILE_CONTENTS -Force -ErrorAction Stop
                if ($null -ne $SSH_AD_GROUPS) {
                    Add-Content -Path $CUSTOM_SSH_FILE -Value $SSH_AD_GROUPS -Force -ErrorAction Stop
                }
            } catch {
                Write-Warning "Main: Failure adding content to the custom ssh file at $CUSTOM_SSH_FILE due to error $_"
                exit $exitcode_FailAdddingSSHCustomFileContent
            }
        }
    }
    #endregion

    #region Join Active Directory
    if (-not $SkipADJoin) {
        Write-Output "`nMain: Time to join domain $Domain!"

        # Verify if we're already joined to a domain
        $DOMAIN_STATUS = realm list

        if ($null -ne $DOMAIN_STATUS) {
            Write-Output "Main: We're already connected to a domain, verifying if we're connected to the right domain."
            if ((($domain_status | Where-Object {$_ -match 'domain-name:'}).replace(' ','').split(':')[-1]) -ne $Domain) {
                Write-Warning "Main: We're not connected to domain $Domain."
                exit $exitcode_WrongDomain
            }
        } elseif ($null -eq $DOMAIN_STATUS) {
            Write-Output "Main: We are not connected to a domain, joining now!"
            (ConvertFrom-SecureString -SecureString $ADPassword -AsPlainText) | realm join $Domain --user=$ADUsername

            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Main: Failed joining to domain $Domain with AD Username $ADUsername."
                exit $exitcode_FailJoiningToDomain
            }
        }
    }
    #endregion

    #region Modify mkhomedir
    if (-not $SkipMkhomedir) {
        Write-Output "`nMain: Replacing the contents of mkhomedir in $MKHOMEDIR_CONF"
        $MKHOMEDIR_CONTENTS = @"
Name: activate mkhomedir
Default: yes
Priority: 900
Session-Type: Additional
Session:
        required                        pam_mkhomedir.so umask=0022 skel=/etc/skel
"@
        try {
            Set-Content -Path $MKHOMEDIR_CONF -Value $MKHOMEDIR_CONTENTS -Force -ErrorAction Stop
        } catch {
            Write-Warning "Main: Failed replacing contents of $MKHOMEDIR_CONF due to error $_"
            exit $exitcode_FailReplaceMKHOMEDIRContents
        }

        # Enable mkhomedir
        try {
            Write-Output "Main: Enabling mkhomedir..."
            Start-Process -FilePath (Get-Command -Name 'pam-auth-update').Source -ArgumentList "--enable mkhomedir" -ErrorAction Stop -Wait
        } catch {
            Write-Warning "Main: Failure enabling mkhomedir due to error $_"
            exit $exitcode_FailEnableMKHOMEDIR
        }
    }
    #endregion

    #region Custom SSSD file
    if ($PSBoundParameters.ContainsKey('SSSDADGroups')) {
        Write-Output "`nMain: Creating custom SSSD config file at $SSSD_CONF"
        $SSSD_AD_GROUPS = $SSSDADGroups.Replace(' ', '\ ') | Join-String -Separator ', '
        
        
        $SSSD_CONTENTS = @"
[sssd]

domains = $Domain
config_file_version = 2
services = nss, pam

# Replace example.com with your domain		 
[domain/$Domain]
default_shell = /bin/bash
krb5_store_password_if_offline = True
cache_credentials = False
krb5_realm = $(($Domain).ToUpper())
realmd_tags = manages-system joined-with-adcli
id_provider = ad
fallback_homedir = /home/%u
ad_domain = $Domain
use_fully_qualified_names = False
ldap_id_mapping = True
access_provider = simple
simple_allow_groups = $SSSD_AD_GROUPS
"@

        if (Test-Path -Path $SSSD_CONF) {
            Write-Output "Main: SSSD Config already exists, deleting now."
            try {
                Remove-Item -Path $SSSD_CONF -Force -ErrorAction Stop
            } catch {
                Write-Warning "Main: Failure removing existing SSSD Config at $SSSD_CONF due to error $_"
                exit $exitcode_FailRemoveExistingSSSDFile
            }   
        }

        try {
            Write-Output "Main: Creating new SSSD Configuration file at $SSSD_CONF"
            Add-Content -Path $SSSD_CONF -Value $SSSD_CONTENTS -Force -ErrorAction Stop
        } catch {
            Write-Warning "Main: Failure creating new SSSD Config at $SSSD_CONF due to error $_"
            exit $exitcode_FailCreateNewSSSDFile
        }

        # Change SSSD Configuration file permissions
        try {
            Write-Output "Main: Setting permissions for $SSSD_CONF"
            Start-Process -FilePath (Get-Command -Name 'chmod').Source -ArgumentList "600 $SSSD_CONF"

            $NEW_SSSD_PERMISSIONS = (Get-Item -Path $SSSD_CONF).UnixMode
            if ($NEW_SSSD_PERMISSIONS -ne $SSSD_CONF_PERMISSIONS) {
                Write-Warning "Main: Failed setting correct permissions to $SSSD_CONF. Current Permissions are $NEW_SSSD_PERMISSIONS"
                exit $exitcode_FailChangeSSSDPermissions
            }
        } catch {
            Write-Warning "Main: Failed setting correct permissions to $SSSD_CONF due to error $_"
            exit $exitcode_FailChangeSSSDPermissions
        }

        # Stop SSSD
        try {
            Write-Output "Stopping SSSD..."
            Start-Process -FilePath (Get-Command -Name 'systemctl').Source -ArgumentList "stop sssd" -Wait -ErrorAction Stop
        } catch {
            Write-Warning "Main: Failure stopping SSSD due to error $_"
            exit $exitcode_FailStoppingSSSD
        }

        # Update SSSD's default configuration file
        try {
            Write-Output "Setting SSSD's new configuration file to $SSSD_CONF"
            Start-Process -FilePath (Get-Command -Name 'sssd').Source -ArgumentList "--config $SSSD_CONF" -Wait -ErrorAction Stop
        } catch {
            Write-Warning "Main: Failure changing SSSD's configuration file to $SSSD_CONF due to error $_"
            exit $exitcode_FailChangeSSSDDefaultConfigFile
        }

        # Check the configuration file for any errors
        $SSSD_CONF_CHECK = sssctl config-check
        # Gather the amount of errors in our configuration file
        $SSSD_CONF_CHECK = ($SSSD_CONF_CHECK | Where-Object {$_ -match '^Issues'}).split(':')[-1].replace(' ','') -as [int]
        if ($SSSD_CONF_CHECK -ne 0) {
            Write-Warning "Main: There's syntax errors within $SSSD_CONF. Run 'sssctl config-check' to see what the errors are."
            exit $exitcode_FailSSSDConfigCheck
        }

        # Start SSSD (There's a bug where you need to restart SSSD twice for it to work)
        try {
            Write-Output "Starting SSSD..."
            Start-Process -FilePath (Get-Command -Name 'systemctl').Source -ArgumentList "restart sssd"
            Start-Sleep -Seconds 5
            Start-Process -FilePath (Get-Command -Name 'systemctl').Source -ArgumentList "restart sssd" -ErrorAction Stop
        } catch {
            Write-Warning "Main: Failure stopping SSSD due to error $_"
            exit $exitcode_FailSSSDStartup
        }
    }
    #endregion

    #region Add AD Groups to SUDOers file
    if ($PSBoundParameters.ContainsKey('SudoADGroups')) {
        Write-Output "`nMain: Creating sudoer file $SUDOER_CONF"
        try {
            if (-not (Test-Path -Path $SUDOER_CONF)) {
                Start-Process -FilePath (Get-Command -Name 'touch').Source -ArgumentList "$SUDOER_CONF" -ErrorAction Stop
            }
            Write-Output "Main: Adding Active Directory Groups into Sudoer file $SUDOER_CONF"
            foreach ($SUDO_AD_GROUP in $SudoADGroups) {
                # Replace the white space with backslash just in case there's a space
                $SUDO_AD_GROUP = $SUDO_AD_GROUP.Replace(' ', '\ ')

                # Add a percent sign to the front and add ALL=(ALL) ALL to the end of the string
                $SUDO_AD_GROUP = "%" + $SUDO_AD_GROUP + " ALL=(ALL) ALL"
                if (-not (Select-STring -Path $SUDOER_CONF -Pattern $SUDO_AD_GROUP)) {
                    Add-Content -Path $SUDOER_CONF -Value $SUDO_AD_GROUP -Force
                }
            }
        } catch {
            Write-Warning "Main: Failed adding Active Directory groups into SUDO file $SUDOER_CONF due to error $_"
            exit $exitcode_FailAddingGroupsToSudoerFile
        }
        
        # Verify sudoer file isn't breaking things
        $SUDOER_CONF_CHECK = visudo -cf $SUDOER_CONF
        if ($SUDOER_CONF_CHECK -notmatch "parsed OK$") {
            Write-Warning "Main: There's an issue with your sudoer file at $SUDOER_CONF. For safety purposes, deleting now."
            Remove-Item -Path $SUDOER_CONF -Force
            exit $exitcode_FailSudoerValidationCheck
        }
    }
    #endregion

    # Restart SSH before we end
    Start-Process -FilePath (Get-Command -Name 'systemctl').Source -ArgumentList "restart ssh"
}

[cmdletbinding()]
param (
    [parameter(Mandatory,
        Position=0,
        ValueFromRemainingArguments,
        ValueFromPipeline)]
        [validateSet({Test-Path -Path $_})]
    [parameter(Mandatory,
        Position=0,
        ValueFromRemainingArguments,
        ValueFromPipeline,
        ParameterSetName="SetupSSL")]
        [validateSet({Test-Path -Path $_})]
    [string]$DockerFile,

    [parameter(Mandatory,
        Position=1,
        ParameterSetName="SetupSSL")]
    [switch]$InstallLE,

    [parameter(Mandatory,
        Position=2,
        ParameterSetName="SetupSSL")]
    [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]$CloudFlareAPIToken,

    [parameter(Mandatory,
        Position=3,
        ParameterSetName="SetupSSL")]
        [ValidateScript({$_ -match '^(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})$'})]
    [string]$FQDN
)

begin {
    function Install-LE {
        [cmdletbinding()]
        param (
        )
        begin {
            $CertbotSettings = $null
        }
        process {
            # Update the system
            Write-Output "Install-LE: Update apt packages"
            Start-Process -FilePath (Get-Command -Name "apt").Source -ArgumentList "update -y" -Wait -ErrorAction SilentlyContinue

            Write-Output "Install-LE: Removing Certbot"
            Start-Process -FilePath (Get-Command -Name "apt").Source -ArgumentList "-y remove certbot" -Wait -ErrorAction SilentlyContinue

            Write-Output "Install-LE: Installing Snapd"
            Start-Process -FilePath (Get-Command -Name "apt").Source -ArgumentList "-y install snapd" -Wait -ErrorAction SilentlyContinue

            Write-Output "Install-LE: Installing Snap Core"
            Start-Process -FilePath (Get-Command -Name "snap").Source -ArgumentList "install core" -Wait -ErrorAction SilentlyContinue

            Write-Output "Install-LE: Refreshing Snap Core"
            Start-Process -FilePath (Get-Command -Name "snap").Source -ArgumentList "refresh core" -Wait -ErrorAction SilentlyContinue

            Write-Output "Install-LE: Installing Snap Certbot"
            Start-Process -FilePath (Get-Command -Name "snap").Source -ArgumentList "install --classic certbot" -Wait -ErrorAction SilentlyContinue
            
            if (-not (Test-Path -Path '/usr/bin/certbot')) {
                Write-Output "Install-LE: Link certbot to /usr/bin/certbot"
                Start-Process -FilePath (Get-Command -Name 'ln').Source -ArgumentList "-s /snap/bin/certbot /usr/bin/certbot"
            }
    
            $CertBotSettings = $(& "snap" "get" "certbot") | ConvertFrom-SourceTable
            if (($CertbotSettings | Where-Object Key -eq 'trust-plugin-with-root' | Select-Object -ExpandProperty Value) -ne 'ok') {
                Write-Output "Install-LE: Trusting Root with Certbot in snap's configuration"
                Start-Process -FilePath (Get-Command -Name 'snap').Source -ArgumentList "set certbot trust-plugin-with-root=ok" -Wait -ErrorAction SilentlyContinue
            }

            Write-Output "Install-LE: Installing Snap Certbot CloudFlare plugin"
            Start-Process -FilePath (Get-Command -Name "snap").Source -ArgumentList "install certbot-dns-cloudflare" -Wait -ErrorAction SilentlyContinue
        }
    }


    function Install-Docker {
        [cmdletbinding()]
        param (

        )

        begin {
            $KEYRING_DIR = '/etc/apt/keyrings'
            $DOCKER_GPG_TEMP_FILE = "$ENV:TEMP/docker.gpg"
            $DOCKER_GPG_KEYRING = $KEYRING_DIR + "/" + "docker.gpg"
            $DOCKER_SOURCE_APT_LIST = '/etc/apt/sources.list.d/docker.list'

            $DOCKER_GPG_URL = "https://download.docker.com/linux/ubuntu/gpg"

            $OLD_DOCKER_APTS = "docker docker-engine docker.io containerd runc"
            $APT_ESSENTIALS = "ca-certificates gnupg lsb-release uidmap"
            $APT_DOCKER = "docker-ce docker-ce-cli containerd.io docker-compose-plugin"

            # Reset these variables
            $ARCH = $null
            $LSB_RELEASE = $null
            $SOURCE_STRING = $null
        }
        process {
            # Remove old versions
            Write-Output "Install-Docker: Removing old versions of docker..."
            Start-Process -FilePath (Get-Command -Name "apt").Source -ArgumentList "remove -y $OLD_DOCKER_APTS" -Wait -ErrorAction SilentlyContinue

            Write-Output "Install-Docker: Install the bare essential apt packages..."
            Start-Process -FilePath (Get-Command -Name "apt").Source -ArgumentList "install -y $APT_ESSENTIALS" -Wait -ErrorAction SilentlyContinue

            # Update the system
            Write-Output "Install-Docker: Update apt packages"
            Start-Process -FilePath (Get-Command -Name "apt").Source -ArgumentList "update -y" -Wait -ErrorAction SilentlyContinue

            # Verify if /etc/apt/keyrings exist
            if (-not (Test-Path -Path $KEYRING_DIR)) {
                Write-Output "Install-Docker: Directory /etc/apt/keyrings does not exist, creating now."
                try {
                    New-Item -Path $KEYRING_DIR -ItemType Directory -Force -ErrorAction Stop
                } catch {
                    Throw "Install-Docker: Failure creating directory $KEYRING_DIR due to error $_"
                    break
                }
            }

            # Download Docker's GPG key
            try {
                Write-Output "Install-Docker: Downloading Docker's GPG key to $DOCKER_GPG_TEMP_FILE..."
                Invoke-WebRequest -Uri $DOCKER_GPG_URL -OutFile $DOCKER_GPG_TEMP_FILE -ErrorAction Stop
            } catch {
                Throw "Install-Docker: Failed downloading Docker's GPG key to /tmp/docker.gpg due to error $_"
                break
            }

            # Add GPG key to keylist
            try {
                if (Test-Path -Path $DOCKER_GPG_KEYRING) {
                    Remove-Item -Path $DOCKER_GPG_KEYRING -Force
                }
                Write-Output "Install-Docker: Adding docker gpg to $DOCKER_GPG_KEYRING"
                Start-Process -FilePath (Get-Command -Name 'gpg').Source -ArgumentList "-o $DOCKER_GPG_KEYRING --dearmor $DOCKER_GPG_TEMP_FILE" -Wait -ErrorAction Stop
            } catch {
                Throw "Install-Docker: Failed adding $DOCKER_GPG_TEMP_FILE to $DOCKER_GPG_KEYRING due to error $_"
                break
            }

            # Generate apt source list for docker
            $ARCH = dpkg --print-architecture
            $LSB_RELEASE = lsb_release -cs
            $SOURCE_STRING = "deb [arch=$ARCH signed-by=$DOCKER_GPG_KEYRING] https://download.docker.com/linux/ubuntu $LSB_RELEASE stable"
            
            try {
                Write-Output "Install-Docker: Creating the source apt list file for docker..."
                $SOURCE_STRING | Tee-Object -FilePath $DOCKER_SOURCE_APT_LIST -ErrorAction Stop
            } catch {
                Throw "Install-Docker: Failed creating $DOCKER_SOURCE_APT_LIST due to error $_"
                break
            }
            
            # Update permissions to docker.gpg
            Write-Output "Install-Docker: To prevent errors with Apt Update, we'll need to modify the permissions of $DOCKER_GPG_KEYRING"
            Start-Process -FilePath (get-Command -Name 'chmod').Source -ArgumentList "a+r $DOCKER_GPG_KEYRING"

            # Update Apt Packages
            Write-Output "Install-Docker: Update apt packages"
            Start-Process -FilePath (Get-Command -Name "apt").Source -ArgumentList "update -y" -ErrorAction SilentlyContinue

            # Install Docker
            try {
                Start-Process -FilePath (Get-Command -Name "apt").Source -ArgumentList "install -y $APT_DOCKER" -Wait -ErrorAction Stop
            } catch {
                Throw "Install-Docker: Failed installing docker due to error $_"
                break
            }
        }
    }

    function Build-DockerImage {
        [cmdletbinding()]
        param (
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ValueFromPipeline)]
            [ValidateSet({Test-Path -Path $_})]
            [string]$DockerFile,

            [parameter(Mandatory,
                Position=1)]
                [ValidateNotNullOrEmpty()]
            [string]$ImageName
        )

        process {
            try {
                Write-Output "`nBuild-DockerImage: Creating docker image $ImageName"
                Start-Process -FilePath (Get-Command -Name 'docker').Source -ArgumentList "build -t $ImageName`:latest $DockerFile" -Wait -ErrorAction Stop
            } catch {
                Throw "Build-DockerImage: Failed building docker image due to error $_"
                break
            }
        }
    }


    function Get-DockerNetworks {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        [OutputType([Object[]])] 
        param (
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Name")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameID")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameDriver")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameIDDriver")]
            [Validatenotnullorempty()]
            [string]$Name,

            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ID")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameID")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="IDDriver")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameIDDriver")]
            [Validatenotnullorempty()]
            [string]$NetworkID,

            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Driver")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="IDDriver")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameDriver")]
            [parameter(Mandatory,
                Position=2,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameIDDriver")]
            [Validatenotnullorempty()]
            [string]$Driver
        )
        begin {
            $Data = $null
            $Docker = (Get-Command -Name 'docker').Source
        }

        process {
            try {
                switch ($PSCmdlet.ParameterSetName) {
                    "Name" {
                        $Data = $(& "$Docker" "network" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object Name -Like $Name
                    }
                    "NameID" {
                        $Data = $(& "$Docker" "network" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Name -Like $Name -and $_.'Network ID' -like $NetworkID}
                    }
                    "NameDriver" {
                        $Data = $(& "$Docker" "network" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Name -Like $Name -and $_.Driver -like $Driver}
                    }
                    "NameIDDriver" {
                        $Data = $(& "$Docker" "network" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {
                            $_.Name -Like $Name -and $_.Driver -Like $Driver -and $_.'Network ID' -like $NetworkID
                        }
                    }
                    "ID" {
                        $Data = $(& "$Docker" "network" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object $_.'Network ID' -Like $NetworkID
                    }
                    "IDDriver" {
                        $Data = $(& "$Docker" "network" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Driver -Like $Driver -and $_.'Network ID' -like $NetworkID}
                    }
                    "Driver" {
                        $Data = $(& "$Docker" "network" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Driver -Like $Driver}
                    }
                    "Default" {
                        # No parameters were given, output all
                        $Data = $(& "$Docker" "network" "ls") | ConvertFrom-SourceTable -ErrorAction Stop
                    }
                }
            } catch {
                Throw "Get-DockerNetworks: Failure retrieving docker networks due to error $_"
            }
        }
        end {
            return $Data
        }
    }

    function Get-DockerContainers {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        [OutputType([Object[]])] 
        param (
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Name")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameID")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameImage")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameIDImage")]
            [Validatenotnullorempty()]
            [string]$Name,

            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ID")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameID")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="IDImage")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameIDDriver")]
            [Validatenotnullorempty()]
            [string]$ContainerID,

            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Image")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="IDImage")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameImage")]
            [parameter(Mandatory,
                Position=2,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameIDImage")]
            [Validatenotnullorempty()]
            [string]$ImageName,

            [parameter(Mandatory=$false)]
            [switch]$all
        )
        begin {
            $Data = $null
            $Docker = (Get-Command -Name 'docker').Source
        }

        process {
            try {
                # Retrieve Data, if '-all' was provided, show online & offline containers, otherwise only show running containers
                if ($all) {
                    $Data = $(& "$Docker" "container" "ls" "--all")
                } else {
                    $Data = $(& "$Docker" "container" "ls")
                }

                switch ($PSCmdlet.ParameterSetName) {
                    "Name" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object Names -Like $Name
                    }
                    "NameID" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Names -Like $Name -and $_.'Container ID' -like $ContainerID}
                    }
                    "NameImage" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Names -Like $Name -and $_.Image -like $ImageName}
                    }
                    "NameIDImage" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {
                            $_.Names -Like $Name -and $_.Image -Like $ImageName -and $_.'Container ID' -like $ContainerID
                        }
                    }
                    "ID" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object $_.'Container ID' -Like $ContainerID
                    }
                    "IDImage" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Image -Like $ImageName -and $_.'Container ID' -like $ContainerID}
                    }
                    "Image" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Image -Like $ImageName}
                    }
                    "Default" {
                        # No parameters were given, output all
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop
                    }
                }
            } catch {
                Throw "Get-DockerContainers: Failure retrieving docker networks due to error $_"
            }
        }
        end {
            return $Data
        }
    }

    function Get-DockerVolumes {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        [OutputType([Object[]])] 
        param (
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Name")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameDriver")]
            [Validatenotnullorempty()]
            [string]$VolumeName,

            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Driver")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="NameDriver")]
            [Validatenotnullorempty()]
            [string]$Driver
        )
        begin {
            $Data = $null
            $Docker = (Get-Command -Name 'docker').Source
        }

        process {
            try {
                switch ($PSCmdlet.ParameterSetName) {
                    "Name" {
                        $Data = $(& "$Docker" "volume" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.'Volume Name' -Like $VolumeName}
                    }
                    "NameDriver" {
                        $Data = $(& "$Docker" "volume" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.'Volume Name' -Like $VolumeName -and $_.Driver -like $Driver}
                    }
                    "Driver" {
                        $Data = $(& "$Docker" "volume" "ls") | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object Driver -Like $Driver
                    }
                    "Default" {
                        # No parameters were given, output all
                        $Data = $(& "$Docker" "volume" "ls") | ConvertFrom-SourceTable -ErrorAction Stop
                    }
                }
            } catch {
                Throw "Get-DockerVolumes: Failure retrieving docker volumes due to error $_"
            }
        }
        end {
            return $Data
        }
    }

    function Get-DockerImages {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        [OutputType([Object[]])] 
        param (
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Image")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ImageTag")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ImageID")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ImageTagID")]
                [ValidateNotNullOrEmpty()]
            [string]$ImageName,

            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Tag")]
            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="TagID")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ImageTag")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ImageTagID")]
                [ValidateNotNullOrEmpty()]
            [string]$Tag,

            [parameter(Mandatory,
                Position=0,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ID")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ImageID")]
            [parameter(Mandatory,
                Position=1,
                ValueFromPipelineByPropertyName,
                ParameterSetName="TagID")]
            [parameter(Mandatory,
                Position=2,
                ValueFromPipelineByPropertyName,
                ParameterSetName="ImageTagID")]
                [ValidateNotNullOrEmpty()]
            [string]$ID,

            [parameter(Mandatory=$false,
                Position=3)]
            [switch]$all
        )
        begin {
            $Data = $null
            $Docker = (Get-Command -Name 'docker').Source
        }

        process {
            try {
                if ($all) {
                    $Data = $(& "$Docker" "image" "ls" "--all")
                } else {
                    $Data = $(& "$Docker" "image" "ls")
                }

                # Filter Data by parameter set
                switch ($PSCmdlet.ParameterSetName) {
                    "Image" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object Repository -Like $ImageName
                    }
                    "ImageID" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Repository -Like $ImageName -and $_.'Image ID' -like $ID}
                    }
                    "ImageTag" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Repository -Like $ImageName -and $_.Tag -like $Tag}
                    }
                    "ImageTagID" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {
                            $_.Repository -Like $ImageName -and $_.Tag -Like $Tag -and $_.'Image ID' -like $ID
                        }
                    }
                    "Tag" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object Tag -Like $Tag
                    }
                    "TagID" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.Tag -Like $Tag -and $_.'Image ID' -like $ID}
                    }
                    "ID" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.'Image ID' -Like $ID}
                    }
                    "Default" {
                        # No parameters were given, output all
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop
                    }
                }
            } catch {
                Throw "Get-DockerImages: Failure retrieving docker images due to error $_"
            }
        }
        end {
            return $Data
        }
    }

    function Get-DockerStatus {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        [OutputType([Object[]])] 
        param (
            [parameter(Mandatory,
                ParameterSetName='ImageName',
                ValueFromPipelineByPropertyName)]
                [ValidateNotNullOrEmpty()]
            [string]$ImageName,

            [parameter(Mandatory,
                ParameterSetName="ContainerID",
                ValueFromPipelineByPropertyName)]
                [ValidateNotNullOrEmpty()]
            [string]$ContainerID,

            [parameter(Mandatory,
                ValueFromPipelineByPropertyName,
                ParameterSetName="Name")]
                [ValidateNotNullOrEmpty()]
            [string]$Name,

            [parameter(Mandatory=$false)]
            [switch]$all
        )
        begin {
            $Data = $null
            $Docker = (Get-Command -Name 'docker').Source
        }

        process {
            try {
                if ($all) {
                    $Data = $(& "$Docker" "ps" "--all")
                } else {
                    $Data = $(& "$Docker" "image")
                }

                # Filter data by parameterset name
                switch ($PSCmdlet.ParameterSetName) {
                    "ImageName" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object Image -Like $ImageName | Select-Object -ExpandProperty Status
                    }
                    "ContainerID" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object {$_.'Container ID' -Like $ContainerID} | Select-Object -ExpandProperty Status
                    }
                    "Name" {
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Where-Object Names -Like $Name | Select-Object -ExpandProperty Status
                    }
                    "Default" {
                        # No parameters were given, output all
                        $Data = $Data | ConvertFrom-SourceTable -ErrorAction Stop | Select-Object Names, 'Container ID', Image, Status
                    }
                }
            } catch {
                Throw "Get-DockerStatus: Failure retrieving docker images due to error $_"
            }
        }
        end {
            return $Data
        }
    }

    function ConvertFrom-SourceTable {
    <#PSScriptInfo
        .VERSION 0.4.0
        .GUID 0019a810-97ea-4f9a-8cd5-4babecdc916b
        .AUTHOR iRon
        .COMPANYNAME
        .COPYRIGHT
        .TAGS Read Input Convert Resource Table Format MarkDown
        .LICENSE https://github.com/iRon7/ConvertFrom-SourceTable/LICENSE.txt
        .PROJECTURI https://github.com/iRon7/ConvertFrom-SourceTable
        .ICON https://raw.githubusercontent.com/iRon7/Join-Object/master/ConvertFrom-SourceTable.png
        .EXTERNALMODULEDEPENDENCIES
        .REQUIREDSCRIPTS
        .EXTERNALSCRIPTDEPENDENCIES
        .RELEASENOTES
        .PRIVATEDATA
    #>

    <#
    .SYNOPSIS
    Converts a fixed column table to objects.
    .DESCRIPTION
    The ConvertFrom-SourceTable cmdlet creates objects from a fixed column
    source table (format-table) possibly surrounded by horizontal and/or
    vertical rulers. The ConvertFrom-SourceTable cmdlet supports most data
    types using the following formatting and alignment rules:
        Data that is left aligned will be parsed to the generic column type
        which is a string by default.
        Data that is right aligned will be evaluated.
        Data that is justified (using the full column with) is following the
        the header alignment and evaluated if the header is right aligned.
        The default column type can be set by prefixing the column name with
        a standard (PowerShell) cast operator (a data type enclosed in
        square brackets, e.g.: "[Int]ID")
    Definitions:
        The width of a source table column is outlined by the header width,
        the ruler width and the width of the data.
        Column and Data alignment (none, left, right or justified) is defined
        by the existence of a character at the start or end of a column.
        Column alignment (which is used for a default field alignment) is
        defined by the first and last character or space of the header and
        the ruler of the outlined column.
    .PARAMETER InputObject
        Specifies the source table strings to be converted to objects.
        Enter a variable that contains the source table strings or type a
        command or expression that gets the source table strings.
        You can also pipe the source table strings to ConvertFrom-SourceTable.
        Note that streamed table rows are intermediately processed and
        released for the next cmdlet. In this mode, there is a higher
        possibility that floating tables or column data cannot be determined
        to be part of a specific column (as there is no overview of the table
        data that follows). To resolve this, use one of the folowing ruler or
        header specific parameters.
    .PARAMETER Header
        A string that defines the header line of an headless table or a multiple
        strings where each item represents the column name.
        In case the header contains a single string, it is used to define the
        (property) names, the size and alignment of the column, therefore it is
        key that the columns names are properly aligned with the rest of the
        column (including any table indents).
        If the header contains multiple strings, each string will be used to
        define the property names of each object. In this case, column alignment
        is based on the rest of the data and possible ruler.
    .PARAMETER Ruler
        A string that replaces any (horizontal) ruler in the input table which
        helps to define character columns in occasions where the table column
        margins are indefinable.
    .PARAMETER HorizontalDash
        This parameter (Alias -HDash) defines the horizontal ruler character.
        By default, each streamed table row (or a total raw table) will be
        searched for a ruler existing out of horizontal dash characters ("-"),
        spaces and possible vertical dashes. If the ruler is found, the prior
        line is presumed to be the header. If the ruler is not found within
        the first (two) streamed data lines, the first line is presumed the
        header line.
        If -HorizontalDash explicitly defined, all (streamed) lines will be
        searched for a matching ruler.
        If -HorizontalDash is set to `$Null`, the first data line is presumed
        the header line (unless the -VerticalDash parameter is set).
    .PARAMETER VerticalDash
        This parameter (Alias -VDash) defines the vertical ruler character.
        By default, each streamed table row (or a total raw table) will be
        searched for a header with vertical dash characters ("|"). If the
        header is not found within the first streamed data line, the first
        line is presumed the header line.
        If -VerticalDash explicitly defined, all (streamed) lines will be
        searched for a header with a vertical dash character.
        If -VerticalDash is set to `$Null`, the first data line is presumed
        the header line (unless the -HorizontalDash parameter is set).
    .PARAMETER Junction
        The -Junction parameter (default: "+") defines the character used for
        the junction between the horizontal ruler and vertical ruler.
    .PARAMETER Anchor
        The -Anchor parameter (default: ":") defines the character used for
        the alignedment anchor. If used in the header row, it will be used to
        define the default alignment, meaning that justified (full width)
        values will be evaluted.
    .PARAMETER Omit
        A string of characters to omit from the header and data. Each omitted
        character will be replaced with a space.
    .PARAMETER Literal
        The -Literal parameter will prevent any right aligned data to be
        evaluated.
    .EXAMPLE
        $Colors = ConvertFrom-SourceTable '
        Name       Value         RGB
        ----       -----         ---
        Black   0x000000       0,0,0
        White   0xFFFFFF 255,255,255
        Red     0xFF0000     255,0,0
        Lime    0x00FF00     0,255,0
        Blue    0x0000FF     0,0,255
        Yellow  0xFFFF00   255,255,0
        Cyan    0x00FFFF   0,255,255
        Magenta 0xFF00FF   255,0,255
        Silver  0xC0C0C0 192,192,192
        Gray    0x808080 128,128,128
        Maroon  0x800000     128,0,0
        Olive   0x808000   128,128,0
        Green   0x008000     0,128,0
        Purple  0x800080   128,0,128
        Teal    0x008080   0,128,128
        Navy    0x000080     0,0,128
        '
        PS C:\> $Colors | Where {$_.Name -eq "Red"}
        Name    Value RGB
        ----    ----- ---
        Red  16711680 {255, 0, 0}
    .EXAMPLE
        $Employees = ConvertFrom-SourceTable '
        | Department  | Name    | Country |
        | ----------- | ------- | ------- |
        | Sales       | Aerts   | Belgium |
        | Engineering | Bauer   | Germany |
        | Sales       | Cook    | England |
        | Engineering | Duval   | France  |
        | Marketing   | Evans   | England |
        | Engineering | Fischer | Germany |
        '
    .EXAMPLE
        $ChangeLog = ConvertFrom-SourceTable '
        [Version] [DateTime]Date Author      Comments
        --------- -------------- ------      --------
        0.0.10    2018-05-03     Ronald Bode First design
        0.0.20    2018-05-09     Ronald Bode Pester ready version
        0.0.21    2018-05-09     Ronald Bode removed support for String[] types
        0.0.22    2018-05-24     Ronald Bode Better "right aligned" definition
        0.0.23    2018-05-25     Ronald Bode Resolved single column bug
        0.0.24    2018-05-26     Ronald Bode Treating markdown table input as an option
        0.0.25    2018-05-27     Ronald Bode Resolved error due to blank top lines
        '
    .EXAMPLE
        $Files = ConvertFrom-SourceTable -Literal '
        Mode                LastWriteTime         Length Name
        ----                -------------         ------ ----
        d----l       11/16/2018   8:30 PM                Archive
        -a---l        5/22/2018  12:05 PM          (726) Build-Expression.ps1
        -a---l       11/16/2018   7:38 PM           2143 CHANGELOG
        -a---l       11/17/2018  10:42 AM          14728 ConvertFrom-SourceTable.ps1
        -a---l       11/17/2018  11:04 AM          23909 ConvertFrom-SourceTable.Tests.ps1
        -a---l         8/4/2018  11:04 AM         (6237) Import-SourceTable.ps1
        '
    .LINK
        Online Version: https://github.com/iRon7/ConvertFrom-SourceTable
    #>
        [CmdletBinding()][OutputType([Object[]])] 
        param(
            [Parameter(ValueFromPipeLine = $True)] 
            [String[]]$InputObject,
            [String[]]$Header,
            [string]$Ruler,
            [Alias("HDash")] 
            [char]$HorizontalDash = '-',
            [Alias("VDash")] 
            [char]$VerticalDash = '|',
            [char]$Junction = '+',
            [char]$Anchor = ':',
            [string]$Omit,
            [switch]$Literal
        )
        begin {
            enum Alignment{ 
                None; 
                Left; 
                Right; 
                Justified 
            }
            
            enum Mask{ 
                All = 8; 
                Header = 4; 
                Ruler = 2; 
                Data = 1 
            }
            $Auto = !$PSBoundParameters.ContainsKey('HorizontalDash') -and !$PSBoundParameters.ContainsKey('VerticalDash')
            $HRx = if ($HorizontalDash) { 
                '\x{0:X2}' -f [int]$HorizontalDash 
            }
            $VRx = if ($VerticalDash) { 
                '\x{0:X2}' -f [int]$VerticalDash 
            }
            $JNx = if ($Junction) { 
                '\x{0:X2}' -f [int]$Junction 
            }
            $ANx = if ($Anchor) { 
                '\x{0:X2}' -f [int]$Anchor 
            }
            $RulerPattern = if ($VRx) { 
                "^[$HRx$VRx$JNx$ANx\s]*$HRx[$HRx$VRx$JNx$ANx\s]*$" 
            } elseif ($HRx) { 
                "^[$HRx\s]*$HRx[$HRx\s]*$" 
            } else { 
                '\A(?!x)x' 
            }
            if (!$PSBoundParameters.ContainsKey('Ruler') -and $HRx) { 
                Remove-Variable 'Ruler'; 
                $Ruler = $Null 
            }
            if (!$Ruler -and !$HRx -and !$VRx) { 
                $Ruler = '' 
            }
            if ($Ruler) { 
                $Ruler = $Ruler -split '[\r\n]+' | Where-Object { 
                    $_.Trim() 
                } | Select-Object -First 1 
            }
            $HeaderLine = if (@($Header).Count -gt 1) { 
                '' 
            } elseif ($Header) { 
                    $Header 
            }
            $TopLine = if ($HeaderLine) { 
                '' 
            }
            $LastLine,$OuterLeftColumn,$OuterRightColumn,$Mask = $Null
            $RowIndex = 0; 
            $Padding = 0; 
            $Columns = New-Object Collections.Generic.List[HashTable]
            $Property = New-Object System.Collections.Specialized.OrderedDictionary             
            # Include support from PSv2
            function Null { 
                $Null 
            }; 
            function True { 
                $True 
            }; 
            function False { 
                $False 
            };

            function Debug-Column {
                if ($VRx) { 
                    Write-Debug $Mask 
                }
                else { 
                    Write-Debug (($Mask | ForEach-Object { 
                        if ($_) { 
                            '{0:x}' -f $_ 
                        } else { 
                            ' ' 
                        } 
                    }) -join '') 
                }
                $CharArray = (' ' * ($Columns[-1].End + 1)).ToCharArray()

                for ($i = 0; $i -lt $Columns.Count; $i++) { 
                    $Column = $Columns[$i]
                    
                    for ($c = $Column.Start + $Padding; $c -le $Column.End - $Padding; $c++) { 
                        $CharArray[$c] = '-' 
                    }
                    $CharArray[($Column.Start + $Column.End) / 2] = "$i"[-1]

                    if ($Column.Alignment -band [Alignment]::Left) { 
                        $CharArray[$Column.Start + $Padding] = ':' 
                    }
                    if ($Column.Alignment -band [Alignment]::Right) { 
                        $CharArray[$Column.End - $Padding] = ':' 
                    }
                }
                Write-Debug ($CharArray -join '')
            }

            function Mask ([string]$Line, [byte]$Or = [Mask]::Data) {
                    $Init = [Mask]::All * ($Null -eq $Mask)
                    if ($Init) { 
                        ([ref]$Mask).Value = New-Object Collections.Generic.List[Byte] 
                    }

                    for ($i = 0; $i -lt ([math]::Max($Mask.Count,$Line.Length)); $i++) {
                        if ($i -ge $Mask.Count) { 
                            ([ref]$Mask).Value.Add($Init) 
                        }
                        $Mask[$i] = if ($i -lt $Line.Length -and $Line[$i] -match '\S') { 
                            $Mask[$i] -bor $Or 
                        } else { 
                            $Mask[$i] -band (0xFF -bxor [Mask]::All) 
                        }
                    }
                }
            function Slice ([string]$String,[int]$Start,[int]$End = [int]::MaxValue) {
                if ($Start -lt 0) { 
                    $End += $Start; 
                    $Start = 0 
                }
                if ($End -ge 0 -and $Start -lt $String.Length) {
                    if ($End -lt $String.Length) { 
                        $String.Substring($Start,$End - $Start + 1) 
                    } else { 
                        $String.Substring($Start) 
                    }
                } else { 
                    $Null 
                }
            }
            function TypeName ([string]$TypeName) {
                if ($Literal) {
                    $Null,$TypeName.Trim()
                } else {
                    $Null = $TypeName.Trim() -match '(\[(.*)\])?\s*(.*)'
                    $Matches[2]
                    if ($Matches[3]) { 
                        $Matches[3] 
                    } else { 
                        $Matches[2] 
                    }
                }
            }
            function ErrorRecord ($Line,$Start,$End,$Message) {
                $Exception = New-Object System.InvalidOperationException "$Message + $($Line -Replace '[\s]', ' ') + $(' ' * $Start)$('~' * ($End - $Start + 1))"
                New-Object Management.Automation.ErrorRecord $Exception, `
                $_.Exception.ErrorRecord.FullyQualifiedErrorId, `
                $_.Exception.ErrorRecord.CategoryInfo.Category, `
                $_.Exception.ErrorRecord.TargetObject
            }
        }
        process {
            $Lines = $InputObject -split '[\r\n]+'
            if ($Omit) {
                $Lines = @(
                    foreach ($Line in $Lines) {
                            foreach ($Char in [Char[]]$Omit) { 
                                $Line = $Line.Replace($Char,' ') 
                            }
                            $Line
                    }
                )
            }
            $NextIndex,$DataIndex = $Null

            if (!$Columns) {
                for ($Index = 0; $Index -lt $Lines.Length; $Index++) {
                    $Line = $Lines[$Index]
                    if ($Line.Trim()) {
                        if ($Null -ne $HeaderLine) {
                            if ($Null -ne $Ruler) {
                                if ($Line -notmatch $RulerPattern) { 
                                    $DataIndex = $Index 
                                }
                            } else {
                                if ($Line -match $RulerPattern) { 
                                    $Ruler = $Line 
                                }
                                else {
                                    $Ruler = ''
                                    $DataIndex = $Index
                                }
                            }
                        } else {
                            if ($Null -ne $Ruler) {
                                if ($LastLine -and (!$VRx -or $Ruler -notmatch $VRx -or $LastLine -match $VRx) -and $Line -notmatch $RulerPattern) {
                                    $HeaderLine = $LastLine
                                    $DataIndex = $Index
                                }
                            } else {
                                if (!$RulerPattern) {
                                    $HeaderLine = $Line
                                } elseif ($LastLine -and (!$VRx -or $Line -notmatch $VRx -or $LastLine -match $VRx) -and $Line -match $RulerPattern) {
                                    $HeaderLine = $LastLine
                                    if (!$Ruler) { $Ruler = $Line }
                                }
                            }
                        }
                        if ($Line -notmatch $RulerPattern) {
                            if ($VRx -and $Line -match $VRx -and $TopLine -notmatch $VRx) { 
                                $TopLine = $Line; $NextIndex = $Null 
                            } elseif ($Null -eq $TopLine) { 
                                $TopLine = $Line 
                            } elseif ($Null -eq $NextIndex) { 
                                $NextIndex = $Index 
                            }
                            $LastLine = $Line
                        }
                        if ($DataIndex) { 
                            break 
                        }
                    }
                }
                if (($Auto -or ($VRx -and $TopLine -match $VRx)) -and $Null -ne $NextIndex) {
                    if ($Null -eq $HeaderLine) {
                        $HeaderLine = $TopLine
                        if ($Null -eq $Ruler) { 
                            $Ruler = '' 
                        }
                        $DataIndex = $NextIndex
                    } elseif ($Null -eq $Ruler) {
                        $Ruler = ''
                        $DataIndex = $NextIndex
                    }
                }
                if ($Null -ne $DataIndex) {
                    $HeaderLine = $HeaderLine.TrimEnd()
                    if ($TopLine -notmatch $VRx) {
                        $VRx = ''
                        if ($Ruler -notmatch $ANx) { 
                            $ANx = '' 
                        }
                    }
                    if ($VRx) {
                        $Index = 0; $Start = 0; $Length = $Null; $Padding = [int]::MaxValue
                        if ($Ruler) {
                            $Start = $Ruler.Length - $Ruler.TrimStart().Length
                            if ($Ruler.Length -gt $HeaderLine.Length) { $HeaderLine += ' ' * ($Ruler.Length - $HeaderLine.Length) }
                        }
                        $Mask = '?' * $Start
                        foreach ($Column in ($HeaderLine.Substring($Start) -split $VRx)) {
                            if ($Null -ne $Length) { 
                                $Mask += '?' * $Length + $VerticalDash 
                            }
                            $Length = $Column.Length
                            $Type,$Name = if (@($Header).Count -le 1) { 
                                TypeName $Column.Trim() 
                            } elseif ($Index -lt @($Header).Count) { 
                                TypeName $Header[$Index] 
                            }

                            if ($Name) {
                                $End = $Start + $Length - 1
                                $Padding = [math]::Min($Padding,$Column.Length - $Column.TrimStart().Length)
                                if ($Ruler -or $End -lt $HeaderLine.Length - 1) { 
                                    $Padding = [math]::Min($Padding,$Column.Length - $Column.TrimEnd().Length) 
                                }
                                $Columns.Add(@{ Index = $Index; Name = $Column; Type = $Null; Start = $Start; End = $End })
                                $Property.Add($Name,$Null)
                            }
                            $Index++; $Start += $Column.Length + 1
                        }
                        $Mask += '*'
                        foreach ($Column in $Columns) {
                            $Anchored = $Ruler -and $ANx -and $Ruler -match $ANx
                            if (!$Ruler) {
                                if ($Column.Start -eq 0) {
                                    $Column.Start = [math]::Max($HeaderLine.Length - $HeaderLine.TrimStart().Length - $Padding,0)
                                    $OuterLeftColumn = $Column
                                } elseif ($Column.End -eq $HeaderLine.Length - 1) {
                                    $Column.End = $HeaderLine.TrimEnd().Length + $Padding
                                    $OuterRightColumn = $Column
                                }
                            }
                            $Column.Type,$Column.Name = TypeName $Column.Name.Trim()
                            if ($Anchored) {
                                $Column.Alignment = [Alignment]::None
                                if ($Ruler[$Column.Start] -match $ANx) { 
                                    $Column.Alignment = $Column.Alignment -bor [Alignment]::Left 
                                }
                                if ($Ruler[$Column.End] -match $ANx) { 
                                    $Column.Alignment = $Column.Alignment -bor [Alignment]::Right 
                                }
                            } else {
                                $Column.Alignment = [Alignment]::Justified
                                if ($HeaderLine[$Column.Start + $Padding] -notmatch '\S') { 
                                    $Column.Alignment = $Column.Alignment -band -bnot [Alignment]::Left 
                                }
                                if ($Column.End - $Padding -ge $HeaderLine.Length -or $HeaderLine[$Column.End - $Padding] -notmatch '\S') { 
                                    $Column.Alignment = $Column.Alignment -band -bnot [Alignment]::Right 
                                }
                            }
                        }
                    } else {
                        Mask $HeaderLine ([Mask]::Header)
                        if ($Ruler) { 
                            Mask $Ruler ([Mask]::Ruler) 
                        }
                        $Lines | Select-Object -Skip $DataIndex | Where-Object { $_.Trim() } | ForEach-Object { 
                            Mask $_ 
                        }

                        # Connect (rulerless) single spaced headers where either column is empty
                        if (!$Ruler -and $HRx) {                    
                            $InWord = $False; $WordMask = 0
                            for ($i = 0; $i -le $Mask.Count; $i++) {
                                if ($i -lt $Mask.Count) { 
                                    $WordMask = $WordMask -bor $Mask[$i] 
                                }
                                $Masked = $i -lt $Mask.Count -and $Mask[$i]

                                if ($Masked -and !$InWord) { 
                                    $InWord = $True; 
                                    $Start = $i 
                                }
                                elseif (!$Masked -and $InWord) {
                                    $InWord = $False; 
                                    $End = $i - 1
                                    # only header
                                    if ([Mask]::Header -eq $WordMask -band 7) { 
                                        if ($Start -ge 2 -and $Mask[$Start - 2] -band [Mask]::Header) { 
                                            $Mask[$Start - 1] = [Mask]::Header 
                                        }
                                        elseif (($End + 2) -lt $Mask.Count -and $Mask[$End + 2] -band [Mask]::Header) { 
                                            $Mask[$End + 1] = [Mask]::Header 
                                        }
                                    }
                                    $WordMask = 0
                                }
                            }
                        }
                        $InWord = $False; $Index = 0; $Start,$Left = $Null

                        for ($i = 0; $i -le $Mask.Count; $i++) {
                            $Masked = $i -lt $Mask.Count -and $Mask[$i]

                            if ($Masked -and !$InWord) { 
                                $InWord = $True;
                                $Start = $i; 
                                $WordMask = 0 
                            }
                            elseif ($InWord) {
                                if ($i -lt $Mask.Count) {
                                    $WordMask = $WordMask -bor $Mask[$i]
                                }
                                if (!$Masked) {
                                    $InWord = $False; $End = $i - 1
                                    if ($i -lt $Mask.Count) {
                                        $WordMask = $WordMask -bor $Mask[$i]
                                    }
                                    $Type,$Name = if (@($Header).Count -le 1) { 
                                        TypeName "$(Slice -String $HeaderLine -Start $Start -End $End)".Trim() 
                                    }
                                    elseif ($Index -lt @($Header).Count) { 
                                        TypeName $Header[$Index] 
                                    }
                                    if ($Name) {
                                        if ($Columns.Where{ $_.Name -eq $Name }) { 
                                            Write-Warning "Duplicate column name: $Name." 
                                        }
                                        else {
                                            if ($Type) {
                                                $Type = try { 
                                                    [type]$Type 
                                                } catch {
                                                    Write-Error -ErrorRecord (ErrorRecord -Line $HeaderLine -Start $Start -End $End -Message (
                                                            "Unknown type {0} in header at column '{1}'" -f $Type,$Name
                                                        ))
                                                }
                                            }
                                            $Column = @{
                                                Index = $Index++
                                                Name = $Name
                                                Type = $Type
                                                Start = $Start
                                                End = $End
                                                Alignment = $Null
                                                Left = $Left
                                                Right = $Null
                                                Mask = $WordMask
                                            }
                                            $Columns.Add($Column)
                                            if ($Left) { 
                                                $Left.Right = $Column 
                                            }
                                            $Left = $Column
                                            $Property.Add($Name,$Null)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    $RulerPattern = if ($Ruler) { 
                        '^' + ($Ruler -replace "[^$HRx]","[$VRx$JNx$ANx\s]" -replace "[$HRx]","[$HRx]") 
                    } else { 
                        '\A(?!x)x' 
                    }
                }
            }
            if ($Columns) {
                if ($VRx) {
                    foreach ($Line in ($Lines | Where-Object { $_ -like $Mask })) {
                        if ($OuterLeftColumn) {
                            $Start = [math]::Max($Line.Length - $Line.TrimStart().Length - $Padding,0)
                            if ($Start -lt $OuterLeftColumn.Start) {
                                $OuterLeftColumn.Start = $Start
                                $OuterLeftColumn.Alignment = $Column.Alignment -band -bnot [Alignment]::Left
                            }
                        } elseif ($OuterRightColumn) {
                            $End = $Line.TrimEnd().Length + $Padding
                            if ($End -gt $OuterRightColumn.End) {
                                $OuterRightColumn.End = $End
                                $OuterRightColumn.Alignment = $Column.Alignment -band -bnot [Alignment]::Right
                            }
                        }
                    }
                } else {
                    $HeadMask = if ($Ruler) { 
                        [Mask]::Header -bor [Mask]::Ruler 
                    } else { 
                        [Mask]::Header 
                    }
                    $Lines | Select-Object -Skip (0 + $DataIndex) | Where-Object { $_.Trim() } | ForEach-Object { 
                        Mask $_ 
                    }
    
                    if (!$RowIndex) {
                        for ($c = $Columns.Count - 1; $c -ge 0; $c --) {
                            $Column = $Columns[$c]
                            $MaskStart = $Mask[$Column.Start]; $MaskEnd = $Mask[$Column.End]
                            $HeadStart = $MaskStart -band $HeadMask; $HeadEnd = $MaskEnd -band $HeadMask
                            $AllStart = $MaskStart -band [Mask]::All; $AllEnd = $MaskEnd -band [Mask]::All
                            $IsLeftAligned = ($HeadStart -eq $HeadMask -and $HeadEnd -ne $HeadMask) -or ($AllStart -and !$AllEnd)
                            $IsRightAligned = ($HeadStart -ne $HeadMask -and $HeadEnd -eq $HeadMask) -or (!$AllStart -and $AllEnd)
                            if ($IsLeftAligned) { 
                                $Column.Alignment = $Column.Alignment -bor [Alignment]::Left 
                            }
                            if ($IsRightAligned) { 
                                $Column.Alignment = $Column.Alignment -bor [Alignment]::Right 
                            }
                        }
                        if ($DebugPreference -ne 'SilentlyContinue' -and !$RowIndex) { 
                            Write-Debug ($HeaderLine -replace '\s',' '); 
                            Debug-Column 
                        }
                    }

                    # Include any consecutive characters at te right
                    foreach ($Column in $Columns) {                         
                        $MaxEnd = if ($Column.Right) { 
                            $Column.Right.Start - 2 
                        } else { 
                            $Mask.Count - 1 
                        }
                        for ($i = $Column.End + 1; $i -le $MaxEnd; $i++) {
                            if ($Mask[$i]) {
                                $Column.End = $i
                                $Column.Alignment = $Column.Alignment -band -bnot [Alignment]::Right
                            } else { 
                                break 
                            }
                        }
                    }
    
                     # Include any consecutive characters at te left
                    foreach ($Column in $Columns) {                        
                        $MinStart = if ($Column.Left) { 
                            $Column.Left.End + 2 
                        } else { 
                            0 
                        }
                        for ($i = $Column.Start - 1; $i -ge $MinStart; $i --) {
                            if ($Mask[$i]) {
                                $Column.Start = $i
                                $Column.Alignment = $Column.Alignment -band -bnot [Alignment]::Left
                            } else { 
                                break 
                            }
                        }
                    }
    
                    # Include any floating characters at the right
                    foreach ($Column in $Columns) {                   
                        # unless the column is right aligned
                        if ($Column.Alignment -ne [Alignment]::Right) {     
                            $MaxEnd = if ($Column.Right) { 
                                $Column.Right.Start - 2 
                            } else { 
                                $Mask.Count - 1 
                            }
                            for ($i = $Column.End + 1; $i -le $MaxEnd; $i++) {
                                if ($Mask[$i]) {
                                    $Column.End = $i
                                    $Column.Alignment = $Column.Alignment -band -bnot [Alignment]::Right
                                }
                            }
                        }
                    }
                    # Include any floating characters at the left
                    foreach ($Column in $Columns) {            
                        # unless the column is left aligned             
                        if ($Column.Alignment -ne [Alignment]::Left) {      
                            $MinStart = if ($Column.Left) { 
                                $Column.Left.End + 2 
                            } else { 
                                0 
                            }
                            for ($i = $Column.Start - 1; $i -ge $MinStart; $i --) {
                                if ($Mask[$i]) {
                                    $Column.Start = $i
                                    $Column.Alignment = $Column.Alignment -band -bnot [Alignment]::Left
                                }
                            }
                        }
                    }
    
                    # Include any leftover floating characters at the right
                    foreach ($Column in $Columns) {           
                        # where the column is right aligned              
                        if ($Column.Alignment -ne [Alignment]::Right) {     
                            $MaxEnd = if ($Column.Right) { 
                                $Column.Right.Start - 2 
                            } else { 
                                $Mask.Count - 1 
                            }
                            for ($i = $Column.End + 1; $i -le $MaxEnd; $i++) {
                                if ($Mask[$i]) {
                                    $Column.End = $i
                                    $Column.Alignment = $Column.Alignment -band -bnot [Alignment]::Right
                                }
                            }
                        }
                    }
                }
                if ($DebugPreference -ne 'SilentlyContinue' -and !$RowIndex) { 
                    Write-Debug ($HeaderLine -replace '\s',' '); 
                    Debug-Column 
                }
                foreach ($Line in ($Lines | Select-Object -Skip ([int]$DataIndex))) {
                    if ($Line.Trim() -and ($Line -notmatch $RulerPattern)) {
                        $RowIndex++

                        if ($DebugPreference -ne 'SilentlyContinue') { 
                            Write-Debug ($Line -replace '\s',' ') 
                        }
                        $Fields = if ($VRx -and $Line -notlike $Mask) { 
                            $Line -split $VRx 
                        }

                        foreach ($Column in $Columns) {
                            $Property[$Column.Name] = if ($Fields) {
                                $Fields[$Column.Index].Trim()
                            } else {
                                $Field = Slice -String $Line -Start $Column.Start -End $Column.End
                                if ($Field -is [string]) {
                                    $Tail = $Field.TrimStart()
                                    $Value = $Tail.TrimEnd()
                                    if (!$Literal -and $Value -gt '') {
                                        $IsLeftAligned = $Field.Length - $Tail.Length -eq $Padding
                                        $IsRightAligned = $Tail.Length - $Value.Length -eq $Padding
                                        $Alignment = if ($IsLeftAligned -ne $IsRightAligned) {
                                            if ($IsLeftAligned) { 
                                                [Alignment]::Left 
                                            } else { 
                                                [Alignment]::Right 
                                            }
                                        } else { 
                                            $Column.Alignment 
                                        }
                                        if ($Alignment -eq [Alignment]::Right) {
                                            try { 
                                                & ([scriptblock]::Create($Value)) 
                                            } catch { 
                                                $Value
                                                Write-Error -ErrorRecord (ErrorRecord -Line $Line -Start $Column.Start -End $Column.End -Message (
                                                        "The expression '{0}' in row {1} at column '{2}' can't be evaluated. Check the syntax or use the -Literal switch." -f $Value,$RowIndex,$Column.Name
                                                    ))
                                            }
                                        } elseif ($Column.Type) {
                                            try { 
                                                & ([scriptblock]::Create("[$($Column.Type)]`$Value")) 
                                            } catch { 
                                                $Value
                                                Write-Error -ErrorRecord (ErrorRecord -Line $Line -Start $Column.Start -End $Column.End -Message (
                                                        "The value '{0}' in row {1} at column '{2}' can't be converted to type {1}." -f $Valuee,$RowIndex,$Column.Name,$Column.Type
                                                    ))
                                            }
                                        } else { 
                                            $Value 
                                        }
                                    } else { 
                                        $Value 
                                    }
                                } else { 
                                    '' 
                                }
                            }
                        }
                        New-Object PSObject -Property $Property
                    }
                }
                if ($DebugPreference -ne 'SilentlyContinue' -and $RowIndex) { 
                    Debug-Column 
                }
            }
        }
    }
    function Test-Function {
        [cmdletbinding()]
        param (
            [parameter(Mandatory=$false,
                Position=0)]
                [ValidateScript({
                    if ($Test2) {
                        Throw "You can only have -Test1 or -Test2 active."
                    } else {
                        $True
                    }})]
            [switch]$Test1,

            [parameter(Mandatory=$false,
                Position=0)]
                [ValidateScript({
                    if ($Test1) {
                        Throw "You can only have -Test1 or -Test2 active."
                    } else {
                        $true
                    }})]
            [switch]$Test2
        )
    }
    function New-UFWRule {
        <#
        .Synopsis
            Adds a firewall rule onto said system.
        .DESCRIPTION
            This script will convert an OVA image to a .zip and utilizes StarWind V2V to convert said vmdk to VHD/VHDx. Once converted, the script will import the VM to Hyper-V (if you allow it).
        .PARAMETER OVAPath
            The path to your OVA file.
        .PARAMETER VMName
            The desired name of your virtual machine. This parameter is also used for converting the OVA file.
        .PARAMETER VMPath
            Where would you like the exported virtual machine to reside? 
        .PARAMETER ProvisionType
            What type of Provisioning do you prefer? Thick or Thin? (Default is thin provisioned)
        .PARAMETER VHDType
            What type of Virtual hard disk do you prefer? VHD or VHDX (Default is VHDX)
        .PARAMETER SkipImport
            Use this switch if you just want to convert your OVA file and NOT import this into a Virtual Machine within Hyper-V
        .PARAMETER vSwitchName
            The Virtual Switch name for your Virtual Machine Import (run Get-VMSwitch | Select Name)
        .PARAMETER VMGeneration
            What Virtual Machine Generation do you want? Default is 1.
        .PARAMETER Processors
            How many processing cores should your VM have? Default is 1.
        .PARAMETER RAM
            How much starting RAM should your VM have? Default is 2GB
        .EXAMPLE
            .\ConvertTo-VHDX.ps1 -OVAPath 'C:\VMs\vm_image.ova' -VMName 'Ova Import VM'
            
            The above will import vm_image.ova into Hyper-V with the VM Name 'Ova Import VM'
        .EXAMPLE
            .\ConvertTo-VHDX.ps1 -OVAPath 'C:\VMs\vm_image.ova' -VMName 'Ova Import VM' -ProvisionType Thick -VHDType vhd -SkipImport
            
            The above will convert vm_image.ova to a Thick-Provisioned vhd. It will NOT be imported into Hyper-V.
        .LINK
            StarWind V2V Download:
            https://www.starwindsoftware.com/starwind-v2v-converter
        .NOTES
            Autor: Zack
        #>
        [cmdletbinding()]
        param (
            [parameter(ParameterSetName = "ComputerName", Mandatory, Position = 0)]
            [Alias("host", "server", "computer")]
            [ValidateNotNullOrEmpty()]
            [string[]]$ComputerName,

            [parameter(ParameterSetName = "Session", Mandatory, Position = 0)]
            [ValidateNotNullOrEmpty()]
            [System.Management.Automation.Runspaces.PSSession[]]$Session,

            [parameter(ParameterSetName = "ComputerName", ValueFromPipelineByPropertyName)]
            [parameter(ParameterSetName = "Services", ValueFromPipelineByPropertyName)]
            [System.Management.Automation.PSCredential]$Creds,

            [parameter(Mandatory,
                Position=0)]
                [ValidateSet('allow', 'deny')]
            [string]$Action,

            [parameter(Mandatory,
                Position=1,
                ParameterSetName="Services")]
                [ValidateNotNullOrEmpty()]
            [string[]]$Services,

            [parameter(Mandatory,
                Position=1,
                ParameterSetName="Port")]
            [parameter(Mandatory,
                Position=1,
                ParameterSetName="PortTo")]
            [parameter(Mandatory,
                Position=0,
                ParameterSetName="PortAndType")]
            [parameter(Mandatory,
                Position=1,
                ParameterSetName="FromPort")]
            [parameter(Mandatory,
                Position=1,
                ParameterSetName="FromPortProto")]
            [parameter(Mandatory,
                Position=1,
                ParameterSetName="FromPortTo")]
            [parameter(Mandatory,
                Position=1,
                ParameterSetName="PortToProto")]
            [parameter(Mandatory,
                Position=1,
                ParameterSetName="All")]
                [ValidateRange(1, 65535)]
            [int]$Port,

            [parameter(Mandatory,
                Position=1,
                ParameterSetName="From")]
            [parameter(Mandatory,
                Position=2,
                ParameterSetName="FromPort")]
            [parameter(Mandatory,
                Position=2,
                ParameterSetName="FromPortProto")]
            [parameter(Mandatory,
                Position=2,
                ParameterSetName="FromPortTo")]
            [parameter(Mandatory,
                Position=2,
                ParameterSetName="All")]
                [ValidateScript({$_ -match "^\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b(\/([0-9]|[1-2][0-9]|3[0-2]))?$"})]
            [string]$From,

            [parameter(Mandatory,
                Position=1,
                ParameterSetName="To")]
            [parameter(Mandatory,
                Position=2,
                ParameterSetName="PortTo")]
            [parameter(Mandatory,
                Position=2,
                ParameterSetName="PortToProto")]
            [parameter(Mandatory,
                Position=3,
                ParameterSetName="FromPortTo")]
            [parameter(Mandatory,
                Position=3,
                ParameterSetName="All")]
                [ValidateScript({$_ -match "^\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b(\/([0-9]|[1-2][0-9]|3[0-2]))?$"})]
            [string]$To,

            [parameter(Mandatory,
                Position=2,
                ParameterSetName="PortAndType")]
            [parameter(Mandatory,
                Position=3,
                ParameterSetName="FromPortProto")]
            [parameter(Mandatory,
                Position=3,
                ParameterSetName="PortToProto")]
            [parameter(Mandatory,
                Position=4,
                ParameterSetName="All")]
                [ValidateSet('tcp', 'udp', 'both')]
            [string]$Protocol
        )

        begin {
            # Set the provided parameters to lower (Services will be set to ToLower in its for-loop if provided)
            $Action = $Action.ToLower()
            if ($PSBoundParameters.Contains('Protocol')) {
                $Protocol = $Protocol.ToLower()
            }

            # If a service was
            if ($PSCmdlet.ParameterSetName -eq 'Services') {
                # Reset these variables
                $UFW_SERVICES = $null
                $ServiceNotFound = $null
                $Service = $null
                $Pattern = "^([(a-zA-Z)]+)([\s][a-zA-Z]([\w]*)+)?"

                try {
                    # Retrieve the list of service names within /etc/services
                    $UFW_SERVICES = (Get-Content -Path '/etc/services' -ErrorAction Stop) | Foreach-Object {
                        
                        # Match a number or word until a space. Check if a word exists after the initial space and retrieve that as well.
                        # Match examples: 'Nginx', 'Nginx Full'
                        # NOT a match: 'Nginx 1'
                        if ($_ -match $Pattern) {
                            (Select-STring -InputObject $_ -Pattern $Pattern).Matches.Captures.Value
                        }
                    }
                    # Retrieve the unique services within /etc/services
                    $UFW_SERVICES = $UFW_SERVICES | Select-Object -Unique

                    # Iterate through the provided services to see if they exist. 
                    $ServiceNotFound += foreach ($Service in $Services) {
                        $Service = $Service.ToLower()

                        # If the service is not found, add it to the array, otherwise proceed
                        if ((Compare-Object -ReferenceObject $Service -DifferenceObject $UFW_SERVICES -ExcludeDifferent -IncludeEqual).Count -eq 0) {
                            $Service
                        }
                        continue
                    }
                    # Throw an exception if a provided service does not exist
                    if ($ServiceNotFound.count -gt 0) {
                        Throw "New-UFWRule: The following services do not exist within /etc/services: $($ServiceNotFound -join ', ')"
                    }
                } catch {
                    Throw "New-UFWRule: Error accessing /etc/services due to error $_"
                }
            }
        }

        process {
            try {

                switch ($PSCmdlet.ParameterSetName) {
                    # Example: ufw allow http
                    "Services" {
                        foreach ($Service in $Services) {

                            $UFWCommand = "ufw $Action $Service"

                            Write-Verbose "New-UFWRule: Adding rule '$UFWCommand'"
                            Invoke-Expression $UFWCommand -ErrorAction Stop
                        }
                    }
    
                    # Example: ufw deny from 192.168.1.0/24
                    "From" {
                        $UFWCommand = "ufw $Action from $From"
                        Write-Verbose "New-UFWRule: Adding rule '$UFWCommand'"
                        Invoke-Expression $UFWCommand -ErrorAction Stop
                    }
    
                    # Example: ufw allow from 192.168.1.1 to any port 22
                    "FromPort" {
                        $UFWCommand = "ufw $Action from $From to any port $Port"
                        Write-Verbose "New-UFWRule: Adding rule '$UFWCommand' (TCP/UDP)"
                        Invoke-Expression $UFWCommand -ErrorAction Stop
                    }
    
                    # Example: ufw allow from 192.168.1.1 to any port 22 proto tcp
                    "FromPortProto" {
                        if ($Protocol -eq 'both') {
                            $UFWCommand = "ufw $Action from $From to any port $Port"
                            Write-Verbose "New-UFWRule: Adding rule '$UFWCommand' (TCP/UDP)"
                            Invoke-Expression $UFWCommand -ErrorAction Stop
                        } else {
                            $UFWCommand = "ufw $Action from $From to any port $Port proto $Protocol"
                            Write-Verbose "New-UFWRule: Adding rule '$UFWCommand'"
                            Invoke-Expression $UFWCommand -ErrorAction Stop
                        }
                        
                    }
    
                    # Example: ufw allow from 192.168.1.1/32 to 192.168.2.1
                    "FromPortTo" {
                        $UFWCommand = "ufw $Action from $From to $To"
                        Write-Verbose "New-UFWRule: Adding rule '$UFWCommand' (Full Access)"
                        Invoke-Expression $UFWCommand -ErrorAction Stop
                    }
    
                    # Example: ufw allow 53
                    "Port" {
                        $UFWCommand = "ufw $Action $Port"
                        Write-Verbose "New-UFWRule: Adding rule '$UFWCommand' (TCP/UDP)"
                        Invoke-Expression $UFWCommand -ErrorAction Stop
                    }
                    # Example: ufw allow 53/tcp
                    "PortAndType" {
                        $UFWCommand = "ufw $Action $Port/$Protocol"
                        Write-Verbose "New-UFWRule: Adding rule '$UFWCommand'"
                        Invoke-Expression $UFWCommand -ErrorAction Stop
                    }
                    # Example: ufw allow from any to 192.168.1.0/24 port 22
                    "PortTo" {
                        $UFWCommand = "ufw $Action from any to $To port $Port"
                        Write-Verbose "New-UFWRule: Adding rule '$UFWCommand' (TCP/UDP)"
                        Invoke-Expression $UFWCommand -ErrorAction Stop
                    }
    
                    # Example: ufw allow from any to 192.168.1.0/24 port 22 proto tcp
                    "PortToProto" {
                        if ($Protocol -eq 'both') {
                            $UFWCommand = "ufw $Action from any to $To port $Port"
                            Write-Verbose "New-UFWRule: Adding rule '$UFWCommand' (TCP/UDP)"
                            Invoke-Expression $UFWCommand -ErrorAction Stop
                        } else {
                            $UFWCommand = "ufw $Action from any to $To port $Port proto $Protocol"
                            Write-Verbose "New-UFWRule: Adding rule '$UFWCommand'"
                            Invoke-Expression $UFWCommand -ErrorAction Stop
                        }
                    }
                    # Example: ufw allow from any to 192.168.1.0/24
                    "To" {
                        $UFWCommand = "ufw $Action from any to $To"
                        Write-Verbose "New-UFWRule: Adding rule '$UFWCommand' (Full Access)"
                        Invoke-Expression $UFWCommand -ErrorAction Stop
                    }
                    
                    # Example: ufw allow from 192.168.1.1/32 to 192.168.2.1 port 22 proto tcp
                    "All" {
                        if ($Protocol -eq 'both') {
                            $UFWCommand = "ufw $Action from $From to $To port $Port"
                            Write-Verbose "New-UFWRule: Adding rule '$UFWCommand' (TCP/UDP)"
                            Invoke-Expression $UFWCommand -ErrorAction Stop
                        } else {
                            $UFWCommand = "ufw $Action from $From to $To port $Port proto $Protocol"
                            Write-Verbose "New-UFWRule: Adding rule '$UFWCommand'"
                            Invoke-Expression $UFWCommand -ErrorAction Stop
                        }
                    }
                }
            } catch {
                Throw "New-UFWRule: Failure adding rule '$UFWCommand' due to error $_"
            }
        }
    }

    function Get-UFWRule {
        [cmdletbinding()]
        [OutputType([Object[]])]
        param (
            [parameter(Mandatory=$false,
                Position=0)]
                [ValidateRange(0, 65535)]
            [int]$Port,

            [parameter(Mandatory=$false,
                Position=1)]
                [ValidateSet("tcp", "udp")]
            [string]$PortType,

            [Parameter(Mandatory=$false,
                Position=2)]
                [ValidateSet("Allow", "Deny")]
            [string]$Action,

            [parameter(Mandatory=$false,
                Position=3,
                helpMessage="Enter a subnet in CIDR notation (e.g., 192.168.1.0/24)")]
                [ValidateSet({$_ -match '^\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b(\/([0-9]|[1-2][0-9]|3[0-2]))?$'})]
            [string]$Subnet
        )

        begin {

            [scriptblock]$FilterScript = $null
            $Filter = 0000
            if ($PSBoundParameters.ContainsKey('Port')) {
                $Filter += 1000
                $FilterScript = {$_.To -like "*$PORT*"}
            }

            # Porttype has a filter of 0100
            if ($PSBoundParameters.ContainsKey('PortType')) {
                if ($Filter -eq 1000) {
                    $FilterScript = { $_.To -like "*$Port*" -and $_.PortType -eq $PortType}
                } else {
                    $FilterScript = {$_.PortType -eq $PortType}
                }
                $Filter += 0100
            }

            # Action has a filter of 0010
            if ($PSBoundParameters.ContainsKey('Action')) {
                
                # -PortType & -Action was provided
                if ($Filter -eq 0100) {
                    $FilterScript = {$_.PortType -eq $PortType -and $_.Action -eq $Action}
                
                # -Port & -Action was provided
                } elseif ($Filter -eq 1000) {
                    $FilterScript = {$_.To -like "*$Port*" -and $_.Action -eq $Action}

                # -Port, -PortType, & -Action was provided
                } elseif ($Filter -eq 1100) {
                    $FilterScript = { $_.To -like "*$Port*" -and $_.PortType -eq $PortType -and $_.Action -eq $Action}

                # Only -Action was provided
                } else {
                    $FilterScript = {$_.Action -eq $Action}
                }
                $Filter += 0010
            }

            if ($PSBoundParameters.ContainsKey('Subnet')) {
                # Only -Action was provided
                if ($Filter -eq 0010) {
                    $FilterScript = {$_.Action -eq $Action -and $_.From -like "*$Subnet*"}

                # Only -PortType was provided
                } elseif ($Filter -eq 0100) {
                    $FilterScript = {$_.PortType -eq $PortType -and $_.From -like "*$Subnet*"}
                
                # Only -Port was provided
                } elseif ($Filter -eq 1000) {
                    $FilterScript = {$_.To -like "*$Port*" -and $_.From -like "*$Subnet*"}

                # -Port, -PortType, & -Action was provided
                } elseif ($Filter -eq 1100) {
                    $FilterScript = { $_.To -like "*$Port*" -and $_.PortType -eq $PortType -and $_.From -like "*$Subnet*"}

                # -Port, -PortType, -Action, & -Subnet was provided
                } elseif ($Filter -eq 1110) {
                    $FilterScript = { $_.To -like "*$Port*" -and $_.PortType -eq $PortType -and $_.Action -eq $Action -and $_.From -like "*$Subnet*"}

                # Only -Subnet was provided
                } else {
                    $FilterScript = {$_.From -like "*$Subnet*"}
                }
                $Filter += 0001
            }
            Write-Debug "Get-UFWRule: Filter: $Filter"
            Write-Debug "Get-UFWRule: FilterScript: $FilterScript"
        }

        end {
            if ($Filter -eq 0000) {
                Write-Verbose "Get-UFWRule: A filter wasn't provided, outputting the entire ufw list"
                return ((ufw verbose | grep -v "Status") | ConvertFrom-SourceTable)
            } else {
                return ((ufw verbose | grep -v "Status") | ConvertFrom-SourceTable | Where-Object -FilterScript $FilterScript)
            }
        }
    }

    #region Variables
    $WIKI_WORK_DIRECTORY = "/opt/wiki"
    $LE_CLOUDFLARE_API_FILE = $WIKI_WORK_DIRECTORY + "/" + ".acme_credentials"
    
    $CONTAINER_WIKI_NAME = 'wiki'
    $CONTAINER_WIKI_COMPANION_NAME = 'wiki-update-companion'

    $NETWORK_NAME = 'wikinet'
    $WIKI_HTTP_PORT = '3000'
    $WIKI_HTTPS_PORT = '3443'
    $WIKI_DOCKER_IMAGE = "ghcr.io/requarks/wiki:2"
    $WIKI_COMPANION_DOCKER_IMAGE = "ghcr.io/requarks/wiki-update-companion:latest"

    # Database Variables
    $DB_SECRET_LOCATION = $WIKI_WORK_DIRECTORY + "/" + ".db-secret"
    $CONTAINER_DB_NAME = 'db'
    $DB_VOLUME_NAME = 'pgdata'
    $DB_NAME = 'wiki'
    $DB_USERNAME = 'wiki'
    #endregion

    #region Reset these variables
    $CONTAINER_DB = $null
    $CONTAINER_WIKI = $null
    $CONTAINER_WIKI_UPDATE_COMPANION = $null
    #endregion

    #region Exit Codes
    $exitcode_NotRoot = 10
    $exitcode_FailCreateWorkDirectory = 11
    $exitcode_FailInstallDocker = 12
    $exitcode_FailCreateNetwork = 13
    $exitcode_FailCreateVolume = 14
    $exitcode_MissingOpenssl = 15
    $exitcode_FailCreateDBSecret = 16

    $exitcode_ContainerDBExists = 17
    $exitcode_ContainerWikiExists = 18
    $exitcode_ContainerWikiCompExists = 19

    $exitcode_NetworkExists = 20
    $exitcode_DBVolumeExists = 21

    $exitcode_FailCreateDBContainer = 22
    $exitcode_FailCreateWikiContainer = 23
    $exitcode_FailCreateWikiCompanionContainer = 24

    $exitcode_MissingUFW = 25
    #endregion
}

process {
    #region Requirements
    # Stop the script if the user isn't running as root
    if ($PSVersionTable.Platform -eq "Unix") {
        if ($(whoami) -ne "root") {
            Write-Log -EntryType Warning -Message "Main: You must run this script as root, stopping."
            exit $exitcode_NotRoot
        }
    }

    # Verify OpenSSL exists
    if (-not (Get-Command -Name "openssl")) {
        Write-Warning "Missing Command openssl, is it installed?"
        exit $exitcode_MissingOpenssl
    }

    # Create the wiki work directory if that does not exist
    if (-not (Test-Path -Path $WIKI_WORK_DIRECTORY)) {
        try {
            Write-Output "`nMain: Creating Wiki Work Directory $WIKI_WORK_DIRECTORY"
            New-Item -Path $WIKI_WORK_DIRECTORY -ItemType Directory -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failure creating wiki work directory: $WIKI_WORK_DIRECTORY due to error $_"
            exit $exitcode_FailCreateWorkDirectory
        }
    }

    # Verify if ufw is installed
    if (-not (Get-Command -Name 'ufw')) {
        Write-Warning "Missing command ufw, is it installed?"
        exit $exitcode_MissingUFW
    }
    #endregion

    #region Install Docker
    try {
        Write-Output "`nMain: Installing Docker..."
        Install-Docker -ErrorAction Stop
    } catch {
        Write-Warning "Failed installing docker due to error $_"
        exit $exitcode_FailInstallDocker
    }
    #endregion

    #region Prepare WikiJS for SSL Implementation
    if ($PSCmdlet.ParameterSetName -eq 'SetupSSL') {
        Write-Output "`nMain: Installing Let's Encrypt with CloudFlare plugin"
        Install-LE

        try {
            Write-Output "`nMain: Storing Let's Encrypt API Credentials to $LE_CLOUDFLARE_API_FILE"
            Tee-Object -InputObject (ConvertFrom-SecureString -SecureString $CloudFlareAPIToken -AsPlainText) -FilePath $LE_CLOUDFLARE_API_FILE -ErrorAction Stop | Out-Null

            # Set the permissions of said file to 600
            Start-Process -FilePath (Get-Command -Name 'chmod').Source -ArgumentList "600 $LE_CLOUDFLARE_API_FILE"
        } catch {
            Write-Warning "Failed storing API Credentials to path $LE_CLOUDFLARE_API_FILE"
        }

        # Create SSL Certificate
        try {
            # Verify the certificate doesn't exist first
            
        } catch {
            Write-Warning "Failure creating initial SSL certificate for $FQDN"
        }
    }   
    #endregion

    #region Check if we can create Containers (for later)
    $CONTAINER_DB = Get-DockerContainers -Name $CONTAINER_DB_NAME -all -ErrorAction SilentlyContinue
    $CONTAINER_WIKI = Get-DockerContainers -Name $CONTAINER_WIKI_NAME -all -ErrorAction SilentlyContinue
    $CONTAINER_WIKI_UPDATE_COMPANION = Get-DockerContainers -Name $CONTAINER_WIKI_COMPANION_NAME -all -ErrorAction SilentlyContinue
    if ($null -ne $CONTAINER_DB) {
        Write-Warning "Container $CONTAINER_DB_NAME already exists. You may need to remove it or update variable CONTAINER_DB_NAME in this script."
        exit $exitcode_ContainerDBExists
    }

    if ($null -ne $CONTAINER_WIKI) {
        Write-Warning "Container $CONTAINER_WIKI_NAME already exists. You may need to remove it or update variable CONTAINER_WIKI_NAME in this script."
        exit $exitcode_ContainerWikiExists
    }

    if ($null -ne $CONTAINER_WIKI_UPDATE_COMPANION) {
        Write-Warning "Container $CONTAINER_WIKI_COMPANION_NAME already exists. You may need to remove it or update variable CONTAINER_WIKI_COMPANION_NAME in this script."
        exit $exitcode_ContainerWikiCompExists
    }
    #endregion

    #region Create Wiki Network
    try {
        Write-Output "`nMain: Creating docker network $NETWORK_NAME"
        if (Get-DockerNetworks -Name $NETWORK_NAME -ErrorAction SilentlyContinue) {
            Write-Warning "Docker Network $NETWORK_NAME already exists. Remove it or update variable NETWORK_NAME in this script."
            exit $exitcode_NetworkExists
        }
        Start-Process -FilePath (Get-Command -Name 'docker').Source -ArgumentList "network create $NETWORK_NAME" -ErrorAction Stop -Wait
    } catch {
        Write-Warning "Failed creating docker network $NETWORK_NAME due to error $_"
        exit $exitcode_FailCreateNetwork
    }
    #endregion

    #region Create Database Secret
    try {
        Write-Output "`nMain: Creating Database secret at $DB_SECRET_LOCATION"
        # The only way to suppress the output...
        & "openssl" "rand" "-base64" "32" | Tee-Object -FilePath $DB_SECRET_LOCATION -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "Failure creating DB Secret to path $DB_SECRET_LOCATION"
        exit $exitcode_FailCreateDBSecret
    }
    #endregion

    #region Create DB volume
    try {
        Write-Output "`nMain: Creating docker volume $DB_VOLUME_NAME"
        if (Get-DockerVolumes -VolumeName $DB_VOLUME_NAME -ErrorAction SilentlyContinue) {
            Write-Warning "Docker DB Volume $DB_VOLUME_NAME already exists. Remove it or update variable DB_VOLUME_NAME in this script."
            exit $exitcode_DBVolumeExists
        }
        Start-Process -FilePath (Get-Command -Name 'docker').Source -ArgumentList "volume create $DB_VOLUME_NAME" -ErrorAction Stop -Wait
    } catch {
        Write-Warning "Failed creating docker DB volume $DB_VOLUME_NAME due to error $_"
        exit $exitcode_FailCreateVolume
    }
    #endregion

    #region Create Database Container
    Write-Output "`nMain: Creating database container..."
    #docker create --name=db -e POSTGRES_DB=wiki -e POSTGRES_USER=wiki -e POSTGRES_PASSWORD_FILE=/etc/wiki/.db-secret -v /etc/wiki/.db-secret:/etc/wiki/.db-secret:ro `
    #   -v pgdata:/var/lib/postgresql/data --restart=unless-stopped -h db --network=wikinet postgres:11
    $(& "docker" "create" "--name=$CONTAINER_DB_NAME" "-e POSTGRES_DB=$DB_NAME" "-e POSTGRES_PASSWORD_FILE=$DB_SECRET_LOCATION" `
        "-v $DB_SECRET_LOCATION`:$DB_SECRET_LOCATION`:ro" "-v $DB_VOLUME_NAME`:/var/lib/postgresql/data" "--restart=unless-stopped" "-h $CONTAINER_DB_NAME" `
        "--network=$NETWORK_NAME" "postgres`:11")
    
    # Did we get an error?
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed creating docker database container $CONTAINER_DB_NAME."
        exit $exitcode_FailCreateDBContainer
    }
    #endregion

    #region Create Wiki Container
    #docker create --name=wiki -e DB_TYPE=postgres -e DB_HOST=db -e DB_PORT=5432 -e DB_PASS_FILE=/etc/wiki/.db-secret `
    #   -v /etc/wiki/.db-secret:/etc/wiki/.db-secret:ro -e DB_USER=wiki -e DB_NAME=wiki -e UPGRADE_COMPANION=1 `
    #   --restart=unless-stopped -h wiki --network=wikinet -p 80:3000 -p 443:3443 ghcr.io/requarks/wiki:2
    Write-Output "`nMain: Creating docker container $CONTAINER_WIKI_NAME"
    $(& "docker" "create" "--name=$CONTAINER_WIKI_NAME" "-e DB_TYPE=postgres" "-e DB_HOST=$CONTAINER_DB_NAME" "-e $DB_PORT=5432" "-e DB_PASS_FILE=$DB_SECRET_LOCATION" `
        "-v $DB_SECRET_LOCATION`:$DB_SECRET_LOCATION`:ro" "-e DB_USER=$DB_USERNAME" "-e DB_NAME=$DB_NAME" "-e UPGRADE_COMPANION=1" `
        "--restart=unless-stopped" "-h $CONTAINER_WIKI_NAME" "--network=$NETWORK_NAME" "-p 80:$WIKI_HTTP_PORT" "-p 443:$WIKI_HTTPS_PORT" "$WIKI_DOCKER_IMAGE")
    
    # Did we get an error?
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed creating docker container $CONTAINER_WIKI_NAME."
        exit $exitcode_FailCreateWikiContainer
    }
    #endregion

    #region Create Wiki Companion Container
    #docker create --name=wiki-update-companion -v /var/run/docker.sock:/var/run/docker.sock:ro `
    # --restart=unless-stopped -h wiki-update-companion --network=wikinet ghcr.io/requarks/wiki-update-companion:latest
    Write-Output "`nMain: Creating docker container $CONTAINER_WIKI_UPDATE_COMPANION"
    $(& "docker" "create" "--name=$CONTAINER_WIKI_UPDATE_COMPANION" "-v /var/run/docker.sock:/var/run/docker.sock:ro" "--restart=unless-stopped" `
        "-h $CONTAINER_WIKI_UPDATE_COMPANION" "--network=$NETWORK_NAME" "$WIKI_COMPANION_DOCKER_IMAGE")

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed creating docker container $CONTAINER_WIKI_UPDATE_COMPANION"
        exit $exitcode_FailCreateWikiCompanionContainer
    }
    #endregion

    #region Firewall port check

    #endregion
}

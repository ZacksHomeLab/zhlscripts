<#
.Synopsis
    This script will deploy multiple Azure DevOps Agents to Ubuntu 22.04 LTS. 
.DESCRIPTION
    This script will install docker, build a docker image, configure an agent for Azure Pipelines, and deploy said agents to Azure.
.PARAMETER AzpUrl
    The URL for your Azure DevOps instance (e.g., https://dev.azure.com/zackshomelab)
.PARAMETER AZPToken
    The PAT Token to authenticate your Agent to your Tenant. (NOTE: This is a secure string, see the examples on how to pass the token)
.PARAMETER DockerFile
    If you do not want to use the provided DockerFile within this script, pass the path to your own Docker File with this Parameter.
.PARAMETER TargetArch
    The target architecture of your OS. The default is linux-x64
.PARAMETER AzpPool
    The name of the Agent Pool these agents will reside in. The default is 'default'.
.PARAMETER StartAgents
    This switch will allow you to run the docker image. This script allows you to build the docker image, start the agent, or do both at once!
.PARAMETER AgentAmount
    If your pass '-StartAgents', you must give the amount of agents to start. The minimum is 1 and the maximum is 10.
.PARAMETER SkipImageBuild
    This switch will skip the building of said docker image and go straight to starting the Agents (if -StartAgents was provided).
.EXAMPLE
    ./New-AZLinuxAgent.ps1 -AzpUrl "https://dev.azure.com/zackshomelab" -AZPToken ("MY_PAT_TOKEN_HERE" | ConvertTo-SecureString -AsPlainText) -AzpPool "Linux" `
        -StartAgents -AgentAmount 4

    The above will create the docker image and deploy 4 agents to my 'Linux' Agent Pool within my organization.
.EXAMPLE
    ./New-AZLinuxAgent.ps1 -AzpUrl "https://dev.azure.com/zackshomelab" -AZPToken (Get-Content -Path "~/.token" | ConvertTo-SecureString -AsPlainText) -AzpPool "Linux" `
        -StartAgents -AgentAmount 4 -SkipImageBuild
    
    The above will SKIP the docker image creation while deploying 4 agents to my 'Linux' Agent Pool within my organization.
.NOTES
    Author - Zack
    NOTE: I have only tested this script with Ubuntu 22.04.1
.LINK
    GitHub - https://github.com/ZacksHomeLab
#>
[cmdletbinding()]
param (
    [parameter(Mandatory,
        Position=0,
        ParameterSetName="BuildImage")]
    [parameter(Mandatory,
        Position=0,
        ParameterSetName="StartAgents")]
    [parameter(Mandatory,
        Position=0,
        ParameterSetName="StartAgentsSkipBuild")]
        [ValidateScript({$_ -match "^https://dev.azure.com/(.*)$"})]
    [string]$AzpUrl,

    [parameter(Mandatory,
        Position=1,
        ParameterSetName="BuildImage")]
    [parameter(Mandatory,
        Position=1,
        ParameterSetName="StartAgents")]
    [parameter(Mandatory,
        Position=1,
        ParameterSetName="StartAgentsSkipBuild")]
    [System.Security.SecureString]$AZPToken,

    [parameter(Mandatory=$false,
        Position=2,
        ParameterSetName="BuildImage")]
    [parameter(Mandatory=$false,
        Position=2,
        ParameterSetName="StartAgents")]
        [ValidateScript({Test-Path -Path $_})]
    [string]$DockerFile,

    [parameter(Mandatory=$false,
        Position=3,
        ParameterSetName="BuildImage")]
    [parameter(Mandatory=$false,
        Position=3,
        ParameterSetName="StartAgents")]
    [parameter(Mandatory=$false,
        Position=3,
        ParameterSetName="StartAgentsSkipBuild")]
    [ValidateSet("linux-x64", "linux-arm64", "linux-arm", "rhel.6-x64")]
    [string]$TargetArch = 'linux-x64',

    [parameter(Mandatory=$false,
        Position=4,
        ParameterSetName="BuildImage")]
    [parameter(Mandatory=$false,
        Position=4,
        ParameterSetName="StartAgents")]
    [parameter(Mandatory=$false,
        Position=4,
        ParameterSetName="StartAgentsSkipBuild")]
    [string]$AzpPool = "default",

    [parameter(Mandatory,
        Position=5,
        ParameterSetName="StartAgents")]
    [parameter(Mandatory,
        Position=5,
        ParameterSetName="StartAgentsSkipBuild")]
    [switch]$StartAgents,

    [parameter(Mandatory,
        Position=6,
        ParameterSetName="StartAgents")]
    [parameter(Mandatory,
        Position=6,
        ParameterSetName="StartAgentsSkipBuild")]
        [ValidateRange(1, 10)]
    [int]$AgentAmount,

    [parameter(Mandatory,
        Position=7,
        ParameterSetName="StartAgentsSkipBuild")]
    [switch]$SkipImageBuild
)

begin {

    #region Variables
    $AZP_URL = $AzpUrl
    if ($AZP_URL[-1] -eq '/') {
        $AZP_URL = $AZP_URL.Substring(0,$AZP_URL.Length-1)
    }
    $AZP_AGENT_DIRECTORY = "/opt/dockeragent"
    $AZP_DOCKER_FILE = $AZP_AGENT_DIRECTORY + "/" + "Dockerfile"
    $AZP_START_SH = $AZP_AGENT_DIRECTORY + "/" + "start.sh"

    $AZP_DOCKER_DIRECTORIES = $AZP_AGENT_DIRECTORY

    # The location that will house the given token
    $AZP_TOKEN_FILE = $AZP_AGENT_DIRECTORY + "/" + ".token"
    #endregion

    #region Exit Codes
    $exitcode_NotRoot = 10
    $exitcode_FailCreatingDockerDirectories = 11
    $exitcode_FailSavingAZPToken = 12
    $exitcode_FailCreatingStartSH = 13
    $exitcode_FailInstallDocker = 14
    $exitcode_FailCreateDockerImage = 15
    $exitcode_FailStartingLinuxAgents = 16
    $exitcode_FailMovingDockerFile = 17
    #endregion

    #region Functions
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

    function New-DockerDirectories {
        [cmdletbinding()]
        param (
            [parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
            [System.Object[]]$Directories
        )

        process {
            try {
                foreach ($DIR in $Directories) {
                    if (-not (Test-Path -Path $DIR)) {
                        Write-Verbose "New-DockerDirectories: Creating directory $DIR"
                        New-Item -Path $DIR -ItemType Directory -Force -ErrorAction Stop
                    }
                }
            } catch {
                Throw "New-DockerDirectories: Failure creating docker directories due to error $_"
                break
            }
        }
    }

    function New-AZPStartSHFile {
        [cmdletbinding()]
        param (
            [parameter(Mandatory,
                Position=0)]
                [ValidateNotNullOrEmpty()]
            [string]$Path,

            [parameter(Mandatory=$false,
                Position=1)]
            [string]$AzpPool = "default",

            [parameter(Mandatory,
                Position=2)]
            [ValidateSet("linux-x64", "linux-arm64", "linux-arm", "rhel.6-x64")]
            [string]$TargetArch
        )

        begin {
            #$AZP_AGENT_NAME = $(hostname -s) + "_" + $((Get-Date).ToString('yyyyMMddHHmmss'))
            $START_SH_CONTENTS = @"
#!/bin/bash
set -e

if [ -z "`$AZP_URL" ]; then
  echo 1>&2 "error: missing AZP_URL environment variable"
  exit 1
fi

if [ -z "`$AZP_TOKEN_FILE" ]; then
  if [ -z "`$AZP_TOKEN" ]; then
    echo 1>&2 "error: missing AZP_TOKEN environment variable"
    exit 1
  fi
  mkdir --parents /azp
  AZP_TOKEN_FILE=/azp/.token
  echo -n `$AZP_TOKEN > "`$AZP_TOKEN_FILE"
fi


unset AZP_TOKEN

export AGENT_ALLOW_RUNASROOT="1"

cleanup() {
    if [ -e config.sh ]; then
    print_header "Cleanup. Removing Azure Pipelines agent..."

    # If the agent has some running jobs, the configuration removal process will fail.
    # So, give it some time to finish the job.
    while true; do
        ./config.sh remove --unattended --auth PAT --token `$(cat "`$AZP_TOKEN_FILE") && break

        echo "Retrying in 30 seconds..."
        sleep 30
    done
    fi
}

print_header() {
    lightcyan='\033[1;36m'
    nocolor='\033[0m'
    echo -e "`${lightcyan}`$1`${nocolor}"
}

# Let the agent ignore the token env variables
export VSO_AGENT_IGNORE=AZP_TOKEN,AZP_TOKEN_FILE

print_header "1. Determining matching Azure Pipelines agent..."

AZP_AGENT_PACKAGES=`$(curl -LsS \
    -u user:`$(cat "`$AZP_TOKEN_FILE") \
    -H 'Accept:application/json;' \
    "`$AZP_URL/_apis/distributedtask/packages/agent?platform=$TargetArch&top=1")

AZP_AGENT_PACKAGE_LATEST_URL=`$(echo "`$AZP_AGENT_PACKAGES" | jq -r '.value[0].downloadUrl')

if [ -z "`$AZP_AGENT_PACKAGE_LATEST_URL" -o "`$AZP_AGENT_PACKAGE_LATEST_URL" == "null" ]; then
    echo 1>&2 "error: could not determine a matching Azure Pipelines agent"
    echo 1>&2 "check that account '`$AZP_URL' is correct and the token is valid for that account"
    exit 1
fi

print_header "2. Downloading and extracting Azure Pipelines agent..."

curl -LsS `$AZP_AGENT_PACKAGE_LATEST_URL | tar -xz & wait $!

source ./env.sh

trap 'cleanup; exit 0' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

print_header "3. Configuring Azure Pipelines agent..."

./config.sh --unattended \
    --agent "`${AZP_AGENT_NAME:-`$(hostname)}" \
    --url "`$AZP_URL" \
    --auth PAT \
    --token `$(cat "`$AZP_TOKEN_FILE") \
    --pool "$AzpPool" \
    --work "`${AZP_WORK:-_work}" \
    --replace \
    --acceptTeeEula & wait $!

print_header "4. Running Azure Pipelines agent..."

trap 'cleanup; exit 0' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

chmod +x ./run.sh

# To be aware of TERM and INT signals call run.sh
# Running it with the --once flag at the end will shut down the agent after the build is executed
./run.sh "$@" & wait $!
"@
        }

        process {
            if (Test-Path -Path $Path) {
                Remove-Item -Path $Path -Force
            }
            Write-Output "New-AZPStartSHFile: Creating Start.sh file located at $Path"
            Add-Content -Path $Path -Value $START_SH_CONTENTS -ErrorAction Stop
        }
    }

    function New-AZPDockerFile {
        [cmdletbinding()]
        param (
            [parameter(Mandatory,
                Position=0)]
                [ValidateNotNullOrEmpty()]
            [string]$Path,

            [parameter(Mandatory,
                Position=1)]
            [ValidateSet("linux-x64", "linux-arm64", "linux-arm", "rhel.6-x64")]
            [string]$TargetArch
        )

        begin {
            $DOCKER_FILE_CONTENTS = @"
FROM ubuntu:22.04
RUN DEBIAN_FRONTEND=noninteractive apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    curl \
    git \
    iputils-ping \
    jq \
    lsb-release \
    software-properties-common \
    zip \
    unzip \
    wget \
    dotnet-sdk-6.0 \
    aspnetcore-runtime-6.0 \
    npm \
    nodejs \
    gulp

# An issue with Ubuntu 22.04 and Azure Agent. The work around is the below commands:
# https://github.com/microsoft/azure-pipelines-agent/issues/3834
RUN wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
RUN dpkg -i libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb && rm libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
RUN sed -i 's/openssl_conf = openssl_init/#openssl_conf = openssl_init/g' /etc/ssl/openssl.cnf

# Install Apache JMeter 5.5 & Java 8
#RUN wget https://dlcdn.apache.org//jmeter/binaries/apache-jmeter-5.5.tgz
#RUN tar xzf apache-jmeter-5.5.tgz
#RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends default-jre

# Install Docker (Specifically to build docker images for Azure Pipelines)
RUN curl -fsSL https://get.docker.com -o get-docker.sh
RUN chmod +x get-docker.sh
RUN sh get-docker.sh

RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Can be 'linux-x64', 'linux-arm64', 'linux-arm', 'rhel.6-x64'.
ENV TARGETARCH=$TargetArch

WORKDIR /azp

COPY ./start.sh .
RUN chmod +x start.sh

ENTRYPOINT [ "./start.sh" ]
"@
        }

        process {
            if (Test-Path -Path $Path) {
                Remove-Item -Path $Path -Force
            }
            Write-Output "New-AZPDockerFile: Creating docker file located at $Path"
            Add-Content -Path $Path -Value $DOCKER_FILE_CONTENTS -ErrorAction Stop
        }
    }

    function New-DockerImage {
        [cmdletbinding()]
        param (
            [parameter(Mandatory = $false)]
            [string]$ImageName = "dockeragent"
        )
        process {
            try {
                Write-Output "`nNew-DockerImage: Creating docker image $ImageName"
                Start-Process -FilePath (Get-Command -Name 'docker').Source -ArgumentList "build -t $ImageName`:latest ." -Wait -ErrorAction Stop
            } catch {
                Throw "New-DockerImage: Failed building docker image due to error $_"
                break
            }
        }
    }
    function Save-AZPToken {
        [cmdletbinding()]
        param (
            [parameter(Mandatory,
                Position=0)]
                [ValidateNotNullOrEmpty()]
            [System.Security.SecureString]$AZPToken,

            [Parameter(Mandatory,
                Position=1)]
                [ValidateNotNullOrEmpty()]
            [string]$AZPTokenFile
        )

        process {
            Write-Output "Save-AZPToken: Saving Token to $AZPTokenFile..."
            (ConvertFrom-SecureString -SecureString $AZPToken -AsPlainText) | Out-File $AZPTokenFile -ErrorAction Stop
        }
    }

    function Get-AZPToken {
        [cmdletbinding()]
        param (
            [Parameter(Mandatory,
                Position=1)]
                [ValidateScript({Test-Path -Path $_})]
            [string]$AZPTokenFile
        )
        
        end {
            return (Get-Content -Path $AZPTokenFile)
        }
    }

    function Get-RunningAgents {
        end {
            return $(docker ps -q | wc -l)
        }
    }
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

    #region create necessary directories
    if ($PSCMdlet.ParameterSetName -ne 'StartAgentsSkipBuild') {
        try {
            Write-Output "`nMain: Creating the necessary docker directories"
            New-DockerDirectories -Directories $AZP_DOCKER_DIRECTORIES -ErrorAction Stop
        } catch {
            Write-Warning "Failed creating Docker Directories due to error $_"
            exit $exitcode_FailCreatingDockerDirectories
        }
    }
    #endregion

    #region Save AZP Token to file
    if (-not (Test-Path -Path $AZP_TOKEN_FILE)) {
        try {
            Write-Output "`nMain: Exporting AZP Token to $AZP_TOKEN_FILE"
            Save-AZPToken -AZPToken $AZPToken -AZPTokenFile $AZP_TOKEN_FILE -ErrorAction Stop
            Start-Process -FilePath (Get-Command -Name 'chmod').Source -ArgumentList "600 $AZP_TOKEN_FILE"
        } catch {
            Write-Warning "Failed exporting AZP_Token to $AZP_TOKEN_FILE due to error $_"
            exit $exitcode_FailSavingAZPToken
        }
    }
    #endregion

    if ($PSCMdlet.ParameterSetName -ne 'StartAgentsSkipBuild') {
        #region Generate the Start.sh file for the docker image
        try {
            Write-Output "`nMain: Creating start.sh file for our docker containers at path $AZP_START_SH..."
            New-AZPStartSHFile -Path $AZP_START_SH -AzpPool $AzpPool -TargetArch $TargetArch -ErrorAction Stop
        } catch {
            Write-Warning "Failure creating start.sh file at $AZP_START_SH due to error $_"
            exit $exitcode_FailCreatingStartSH
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

        #region Create Docker File
        if (-not ($PSBoundParameters.ContainsKey('DockerFile'))) {
            try {
                Write-Output "`nMain: Creating docker image file..."
                New-AZPDockerFile -Path $AZP_DOCKER_FILE -TargetArch $TargetArch -ErrorAction Stop
            } catch {
                Write-Warning "Failed installing docker due to error $_"
                exit $exitcode_FailInstallDocker
            }
        } else {
            try {
                Move-Item -Path $DockerFile -Destination $AZP_DOCKER_FILE -Force -ErrorAction Stop
            } catch {
                Write-Warning "Failed moving provided docker file to location $AZP_DOCKER_FILE"
                exit $exitcode_FailMovingDockerFile
            }
        }
        #endregion

        #region Create Docker Image
        Set-Location -Path $AZP_AGENT_DIRECTORY

        try {
            New-DockerImage -ErrorAction Stop
        } catch {
            Write-Warning "Failed creating Docker Image due to error $_"
            exit $exitcode_FailCreateDockerImage
        }
        #endregion
    }

    #region Start Agents
    if ($PSCMdlet.ParameterSetName -like "*StartAgents*") {
        Write-Output "`nMain: Time to start some agents!"

        # Count the number of running agents
        $RUNNING_AGENTS = Get-RunningAgents
        # Calculate the amount of agents we should create
        $AMOUNT_TO_START = ($AgentAmount - $RUNNING_AGENTS)

        # if we were given 10 agents to start and we have 7 running, amount_to_start would be 3
        if ($AMOUNT_TO_START -gt 0) {

            # Iterate through the amount of agents we need to start
            for ($i = 0; $i -lt $AMOUNT_TO_START; $i++) {
                # Agent Name Example: zhldocker01_20230127052732
                $AZP_AGENT_NAME = $(hostname -s) + "_" + $((Get-Date).ToString('yyyyMMddHHmmss'))
                # Name of the job that will be created
                $JOB_NAME = "DOCKER_$i"

                # Remove the job if it already exists
                if (Get-Job -Name $JOB_NAME -ErrorAction SilentlyContinue) {
                    Get-Job -Name $JOB_NAME | Remove-Job -Force
                }
                # Run the docker container
                try {
                    Start-Job -Name $JOB_NAME -ScriptBlock {
                        Start-Process -FilePath (Get-Command -Name 'docker').Source -ArgumentList "run -v /var/run/docker.sock:/var/run/docker.sock -e AZP_URL=$using:AzpUrl -e AZP_TOKEN=$(Get-Content -Path $using:AZP_TOKEN_FILE) -e AZP_AGENT_NAME=$using:AZP_AGENT_NAME dockeragent:latest" -ErrorAction Stop
                    } -ErrorAction Stop
                    Start-Sleep -Seconds 10
                } catch {
                    Write-Warning "Failed starting job $JOB_NAME due to error $_"
                    Get-Job | Remove-Job -Force
                    exit $exitcode_FailStartingLinuxAgents
                }

                # Wait for the job to finish before proceeding to the next agent
                # I noticed some agents would not show up in Azure if the jobs executed too quick.
                # Waiting for each individual job fixes the issue.
                Write-Output "`nMain: Waiting for Job $JOB_NAME to complete!"
                $JOB_STATE = $null
                $COUNTER = 0

                do {
                    Write-Output "Main: Waiting for $JOB_NAME to finish..."
                    Start-Sleep -Seconds 5
                    $JOB_STATE = (Get-Job -Name $JOB_NAME).State
                } until ($JOB_STATE -ne 'Running' -or $COUNTER -gt 240)

                # The job ran too long, remove the job and continue
                if ($COUNTER -gt 240 -and $JOB_STATE -ne 'Completed') {
                    Write-Warning "Main: Script waited 4 minutes for $JOB_NAME to finish."

                    if ((Get-Job -Name $JOB_NAME).State -eq 'Running') {
                        Get-Job -Name $JOB_NAME | Stop-Job
                    }
                    Get-Job -Name $JOB_NAME | Remove-Job -Force
                    continue
                }

                # Remove the job once completed
                if ($JOB_STATE -eq 'Completed') {
                    Write-Output "Main: Job $JOB_NAME has completed! Verify the new Agent exists in pool $AzpPool"
                    Get-Job -Name $JOB_NAME | Remove-Job -Force
                }
            }
        } else {
            Write-Warning "Main: You wanted to start $AgentAmount agents but there's already $RUNNING_AGENTS running. Set the amount of agents higher than $RUNNING_AGENTS."
        }
    }
    #endregion
}

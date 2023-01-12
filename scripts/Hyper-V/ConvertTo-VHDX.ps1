<#
.Synopsis
    This script will Import an OVA Image into Hyper-V.
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
    [parameter(Mandatory,
        Position=0)]
    [string]$OVAPath,

    [parameter(Mandatory,
        Position=1)]
    [string]$VMName,

    [parameter(Mandatory=$false,
        Position=2)]
    [string]$VMPath = "$ENV:USERPROFILE\Documents\Hyper-V\Virtual Hard Disks",

    [parameter(Mandatory=$false,
        Position=3)]
    [ValidateSet('thin', 'thick')]
    [string]$ProvisionType = 'thin',

    [parameter(Mandatory=$false,
        Position=4)]
    [ValidateSet('vhd', 'vhdx')]
    [string]$VHDType = 'vhdx',

    [parameter(Mandatory,
        Position=5,
        ParameterSetName='SkipImport')]
    [switch]$SkipImport,

    [parameter(Mandatory=$false,
        Position=5,
        ParameterSetName='Import')]
    [string]$vSwitchName = "Default Switch",

    [parameter(Mandatory=$false,
        Position=6,
        ParameterSetName='Import')]
    [validateSet(1, 2)]
    [string]$VMGeneration = 1,

    [parameter(Mandatory=$false,
        Position=7,
        ParameterSetName='Import')]
    [ValidateScript({$_ -gt 0 -and $_ -le $ENV:NUMBER_OF_PROCESSORS})]
    [int]$Processors = 1,

    [parameter(Mandatory=$false,
        Position=8,
        ParameterSetName='Import')]
    [ValidateScript({$_ -ge 1 -and $_ -le (((Get-CimInstance -ClassName 'Cim_PhysicalMemory' | Measure-Object -Property Capacity -Sum).Sum / 1GB) * 0.95)})]
    [int]$RAM = 2
)


#region Constant Variables
$ExportDirectory = $ENV:TEMP
$UnZIPPath = "$ExportDirectory\$VMName"
$NewZIPFilePath = "$ExportDirectory\$VMName.zip"
# Example: ft_vhdx_thin
$VMFileType = "ft_$($VHDType)_$($ProvisionType)"

# Remove the trailing '\' of VMPath if provided
if ($VMPath[-1] -eq '\') {
    do {
        $VMPath = $VMPath.Substring(0, $VMPath.Length - 1)
    } until ($VMPath[-1] -ne '\')  
}

# New VM Full Path (Example: C:\Users\Zack\Documents\Hyper-V\Virtual Hard Disks\VM Name.vhdx)
$NewVMPath = "$VMPath\$VMName.$VHDType"
#endregion

#region Exit Codes
$exitcode_MissingV2V = 10
$exitcode_Missing7ZIP = 11
$exitcode_ErrorImporting7ZIPModule = 12
$exitcode_MissingOVA = 13
$exitcode_FailureCreatingZIPFile = 14
$exitcode_FailureUnzippingFile = 15
$exitcode_MissingVMDKFiles = 16
$exitcode_CannotCreateVMDirectory = 17
$exitcode_FailureConvertingVM = 18
$exitcode_NovSwitchesExist = 19
$exitcode_FailureGatheringvSwitches = 20
$exitcode_failureCreatingVM = 21
#endregion

#region Functions
function Import-7Zip4Powershell {
    [cmdletbinding()]
    param (
    )

    Process {
        if (-not (Get-Module -Name 7Zip4Powershell)) {
            Write-Verbose "`Import-7Zip4Powershell: Checking if we need to install/import 7Zip4Powershell..."

            # Install/Import AZ if not installed already
            if (-not (Get-InstalledModule -Name '7Zip4Powershell' -ErrorAction SilentlyContinue)) {
    
                # Set to TLS 1.2 if it has to go out and download something
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                write-verbose "Import-7Zip4Powershell: Module 7Zip4Powershell isn't installed, installing now."
                
                # Install the module
                Install-Module -Name 7Zip4Powershell -Repository PSGallery -Force

                if (Get-InstalledModule -Name '7Zip4Powershell' -ErrorAction SilentlyContinue) {
                    Write-Verbose "Import-7Zip4Powershell: 7Zip4Powershell was sucessfully installed!"
                } else {
                    Write-Warning "Import-7Zip4Powershell: Error installing 7Zip4Powershell"
                    Throw "Import-7Zip4Powershell: Error installing 7Zip4Powershell"
                    break
                }
                # Once Installed, import the module
                if (-not (Get-Module -Name 7ZIP4PowerShell -ErrorAction SilentlyContinue)) {
                    Write-Verbose "Import-7Zip4Powershell: Importing Module, this will take some time."
                    Import-Module -name 7Zip4Powershell -ErrorAction SilentlyContinue

                    if (Get-Module -Name 7Zip4Powershell) {
                        Write-Verbose "Import-7Zip4Powershell: Module 7Zip4Powershell was sucessfully imported!"
                    } else {
                        Throw "Import-7Zip4Powershell: Error importing Module 7Zip4Powershell"
                        break
                    }
                }
                
            } else {
                # Module is installed, try to import it
                if (-not (Get-Module -Name 7Zip4Powershell -ErrorAction SilentlyContinue)) {
                    Write-Verbose "Import-7Zip4Powershell: Module 7Zip4Powershell was already installed, importing now."
                    Import-Module -name 7Zip4Powershell -ErrorAction SilentlyContinue

                    if (Get-Module -Name 7Zip4Powershell) {
                        Write-Verbose "Import-7Zip4Powershell: Module 7Zip4Powershell was sucessfully imported!"
                    } else {
                        Throw "Import-7Zip4Powershell: Error importing Module 7Zip4Powershell"
                    }
                } else {
                    Write-Verbose "Import-7Zip4Powershell: Module 7Zip4Powershell was already imported."
                }
            }
        } else {
            Write-Verbose "Import-7Zip4Powershell: Module 7Zip4Powershell was already imported."
        }
    }
}
#endregion

#region Preconditions
if (-not (Test-Path -Path $VMPath)) {
    try {
        New-Item -ItemType Directory -Path $VMPath -ErrorAction Stop
    } catch {
        Write-Warning "Main: Failed creating directory $VMPath."
        exit $exitcode_CannotCreateVMDirectory
    }
}

# Verify if StarWind V2V is installed
Write-Verbose "Main: Checking if StarWind V2V is installed..."
if (-not (Test-Path -Path 'C:\Program Files\StarWind Software\StarWind V2V Converter\V2V_ConverterConsole.exe')) {
    Write-Warning "StarWind V2V not installed, download said program at https://www.starwindsoftware.com/starwind-v2v-converter"
    exit $exitcode_MissingV2V
} else {
    Write-Verbose "Main: StarWind V2V is installed!"
    $V2VApp = 'C:\Program Files\StarWind Software\StarWind V2V Converter\V2V_ConverterConsole.exe'
}

# Verify OVA File exists
if (-not (Test-Path -Path $OVAPath)) {
    Write-Warning "OVA File $OVAPath does not exist!"
    exit $exitcode_MissingOVA
}

# Check if 7ZIP is installed. If installed, check if it's in PATH
if ($null -eq (Get-Command -name '7z.exe' -ErrorAction SilentlyContinue) -and (-not (Test-Path -Path "C:\Program Files\7-Zip\7z.exe"))) {
    Write-Warning "Main: You need 7-Zip installed to run this script, stopping."
    exit $exitcode_Missing7ZIP
} else {
    if ($null -eq (Get-Command -Name '7z.exe' -ErrorAction SilentlyContinue)) {
        $7ZipPath = (Get-ChildItem "C:\Program Files\7-Zip\","C:\Program Files (x86)\7-Zip\" -Filter '7z.exe' -ErrorAction SilentlyContinue).DirectoryName
        if (($ENV:Path -split ';') -notcontains $7ZipPath) {
            foreach ($7Zip in $7ZIPPath) {
                Write-Verbose "Main: Attempting to add path $7Zip to our Path Variables for this session."
                $ENV:Path += ";$7Zip;"
            }
        } else {
            Write-Output "Main: 7-ZIP ($7ZIP) is already in the environment paths for this script!"
        }
    }
}

# Try to import 7ZIp4PowerShell
try {
    Write-Verbose "Main: Attempting to install/import 7Zip4PowerShell module..."
    Import-7Zip4Powershell -ErrorAction Stop
} catch {
    $Message = $_ | Select-Object *
    Write-Warning "Main: Error installing 7ZIP4PowerShell module due to error $Message."
    exit $exitcode_ErrorImporting7ZIPModule
}

#endregion

#region Convert OVA File into zip file
try {
    Write-Verbose "Main: Attempting to create $NewZIPFilePath from $OVAPath..."
    Copy-Item -Path $OVAPath -Destination $NewZIPFilePath -ErrorAction Stop

    if (Test-Path -Path $NewZIPFilePath) {
        Write-Output "Main: Successfully created file $NewZIPFilePath!"
    }
} catch {
    Write-Warning "Main: Failed creating file $NewZIPFilePath from $OVAPath..."
    exit $exitcode_FailureCreatingZIPFile
}
#endregion

#region Unzip the Zip file
try {
    Write-Verbose "Main: Attempting to Unzip $NewZIPFilePath to destination $UnZIPPath"
    Expand-7Zip -ArchiveFileName $NewZIPFilePath -TargetPath $UnZIPPath -ErrorAction Stop

} catch {
    Write-Warning "Main: Failed unzipping file $NewZIPFilePath to $UnZIPPath"
    exit $exitcode_FailureUnzippingFile
}
#endregion

#region Convert VMDK
$VMDKFile = (Get-ChildItem -Path $UnZIPPath -Filter "*.vmdk").FullName

if ($null -eq $VMDKFile) {
    Write-Warning "Main: Could not find VMDK Files in path $UnZIPPath."
    exit $exitcode_MissingVMDKFiles
}

try {
    Write-Verbose "Main: Begin converting $VMDKFile to $NewVMPath"
    # Documentation for V2V_ConverterConsole.exe = https://www.starwindsoftware.com/v2v-help/CommandLineInterface.html
    Start-Process -FilePath $V2VApp -ArgumentList "convert in_file_name=$VMDKFile out_file_name=`"$NewVMPath`" out_file_type=$VMFileType" -Wait -ErrorAction Stop

    # Find VMDK to convert to VHD.
    if (Test-Path -Path $NewVMPath) {
        Write-Output "Main: Successfully exported VM $VMName to $NewVMPath!"
    } else {
        Write-Warning "$V2VApp ran but could not find converted VM."
        exit $exitcode_FailureConvertingVM
    }

} catch {
    Write-Warning "Main: Failed converting $VMDKFile to $NewVMPath."
    exit $exitcode_FailureConvertingVM
}
#endregion

# Import VM into Hyper-V
if ($PSCmdlet.ParameterSetName -eq 'Import') {
    if (-not (Get-VMSwitch -Name $vSwitchName)) {
        Write-Warning "Main: Virtual Switch $vSwitchName does not exist!"
        try {
            $vSwitchNames = Get-VMSwitch -ErrorAction Stop | Select-Object -ExpandProperty Name

            if ($null -eq $vSwitchNames) {
                Write-Warning "Main: Could not find any Virtual Switches, do you have any?"
                exit $exitcode_NovSwitchesExist
            }

            Write-Output "Here are the names of the installed Virtual Switches:"
            foreach ($switch in $vSwitchNames) {
                Write-Output "$switch"
            }
        } catch {
            Write-Warning "Main: Failed gathering VMSwitch Names from your Hyper-V Hypervisor."
            exit $exitcode_FailureGatheringvSwitches
        }
        
    }

    if (-not (Get-VM -Name $VMName -ErrorAction SilentlyContinue)) {
        Write-Verbose "Main: Attempting to create new VM $VMName with the following specs:"
        Write-Verbose "RAM: $($RAM)GB"
        Write-Verbose "CPU Cores: $Processors"
        Write-Verbose "Generation: $VMGeneration"
        Write-Verbose "VHD Path: $NewVMPath"
        try {
            New-VM -Name $VMName -MemoryStartupBytes "$(($RAM).ToString())GB" -VHDPath $NewVMPath -Generation $VMGeneration -SwitchName $vSwitchName | Set-VM -ProcessorCount $Processors -Passthru
        } catch {
            $Message = $_ | Select-Object *
            Write-Warning "Main: Failure creating VM $VMName"
            Write-Warning $Message
            exit $exitcode_failureCreatingVM
        }
    } else {
        Write-Warning "VM $VMName already exists!"
    }
}

# Cleanup time
Write-Verbose "Main: Cleaning up unzipped items..."
Remove-Item -Path $UnZIPPath -Recurse -Force

<#
.Synopsis
    This function will run a provided command and arguments.
.DESCRIPTION
    This function was created due to the inconsistencies of running Start-Process in Linux. This function provides a 
    consistent way of running non-PowerShell commands that require many parameters/arguments to run (e.g., docker).
    
    PowerShell commands or aliases will NOT work with this function. For example commands such as: echo, history, or cp
    will NOT work. Use the build-in PowerShell commands for those.
.PARAMETER Name
    The path or name of the command to be ran.
.PARAMETER Arguments
    The optional parameters/arguments to be added with your command.
.PARAMETER WorkingDirectory
    The current WorkingDirectory to run said Command. If you are not using the full path to files, you should probably
    use this parameter. 
.PARAMETER LoadUserProfile
    Gets or sets a value that indicates whether the Windows user profile is to be loaded from the registry.

    This will NOT work on Unix/Linux.
.PARAMETER Timer
    Provide a timer (in ms) for how long you want to wait for the process to exit/end.
.PARAMETER Verb
    Specifies a verb to use when this cmdlet starts the process. The verbs that are available are determined by the filename extension of the file that runs in the process.

    The following table shows the verbs for some common process file types.

    File type	Verbs
    .cmd	Edit, Open, Print, RunAs, RunAsUser
    .exe	Open, RunAs, RunAsUser
    .txt	Open, Print, PrintTo
    .wav	Open, Play
    To find the verbs that can be used with the file that runs in a process, use the New-Object cmdlet to create a System.Diagnostics.ProcessStartInfo object for the file. The available verbs are in the Verbs property of the ProcessStartInfo object. For details, see the examples.

    This will NOT work on Unix/Linux.
.PARAMETER Passthru
    Pass the object into the pipeline. Using -Passthru will ignore error-handling.
.NOTES
    Author - Zack Flowers
.LINK
    GitHub: https://github.com/zackshomelab
.EXAMPLE
    Start-Command -Name 'docker' -CommandArguments "container ls --all"
    
    Example #1:
    This example executes command 'docker' and passes arguments 'container ls --all' to display the offline/online containers.
.EXAMPLE
    Start-Command -Name 'docker' -CommandArguments "container", "ls", "--all"

    Example #2:
    This example is simular to Example #1, except it accepts comma-separated arguments.
.EXAMPLE
    $whoami = Start-Command -Name 'whoami' -Passthru

    $whoami

    Title        : whoami
    OutputStream : System.Management.Automation.PSEventJob
    OutputData   : zac
    ErrorStream  : 
    ErrorData    : 
    ExitCode     : 0

    Example #3:
    This example utilizes the -Passthru feature of this script.
.INPUTS
    None
.OUTPUTS
    System.String
    System.Management.Automation.PSCustomObject
#>
function Start-Command {
    [cmdletbinding(DefaultParameterSetName="default")]
    param (
        [parameter(Mandatory,
            Position=0,
            ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
        [string]$Name,

        [parameter(Mandatory=$false,
            Position=1,
            ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
        [object]$Arguments,

        [parameter(Mandatory=$false,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path $_})]
        [string]$WorkingDirectory,

        [parameter(Mandatory=$false)]
            [ValidateScript({
                if ($PSVersionTable.Platform -eq "Unix") {
                    Throw "-LoadUserProfile cannot be used on Unix/Linux."
                }
            })]
        [switch]$LoadUserProfile,

        [parameter(Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName="timer")]
            [ValidateRange(1, 600000)]
        [int]$Timer,

        [parameter(Mandatory=$false,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({
                if ($PSVersionTable.Platform -eq "Unix") {
                    Throw "-Verb cannot be used on Unix/Linux."
                }
            })]
        [string]$Verb,

        [parameter(Mandatory=$false)]
        [switch]$Passthru
    )

    begin {
        $FileName = (Get-Command -Name $Name -ErrorAction SilentlyContinue).Source

        # If we cannot find the provided FileName, this could be due to the user providing..
        # ..a command that is a PowerShell Alias (e.g., echo, history, cp)
        if ($null -eq $FileName -or $FileName -eq "") {
            
            # Source doesn't exist. Let's see if the provided command is a PowerShell command
            $getPSCommand = (Get-Command -Name $Name -ErrorAction SilentlyContinue)

            if ($null -eq $getPSCommand -or $getPSCommand -eq "") {
                Throw "Start-Command: Could not find command $Name nor could we find its PowerShell equivalent."
            }

            # Stop the script if the command was found but it returned an alias. 
            # Sometimes, a command may not return a source but WILL return an alias. This will cause issues with incompatibility with..
            # ..parameters for said commands.
            #
            # Example commands that will not work: echo, history, and cd
            if ($getPSCommand.CommandType -eq 'Alias') {
                Throw "Start-Command: This function does not support Aliases. Command $Name matches $($getPSCommand.ResolvedCommand.Name)."
            }

            # This function does not support Microsoft PowerShell commands.
            if ($getPSCommand.Source -like "Microsoft.PowerShell*") {
                Throw "Start-Command: This function should only be used for Non-PowerShell commands (e.g., wget, touch, mkdir, etc.)"
            }

            # Retrieve the version of PowerShell and its location and replace $FileName with it
            $FileName = $PSVersionTable.PSEdition -eq 'Core' ? (Get-Command -Name 'pwsh').Source : (Get-Command -Name 'powershell').Source
            
            # Reconfigure Arguments to execute PowerShell
            $Arguments = "-noprofile -Command `"& {$($getPSCommand.ReferencedCommand.Name) $Arguments}`""
        }

        # Data Object will store all streams of data from our command
        $dataObject = [pscustomobject]@{
            Title        = $Name
            OutputStream = ''
            OutputData   = ''
            ErrorData    = ''
            ExitCode     = 0
        }
    }
    process {

        $processStartInfoProps = @{
            Arguments               = $null -ne $Arguments ? $Arguments : $null
            CreateNoWindow          = $true
            ErrorDialog             = $false
            FileName                = $FileName
            RedirectStandardError   = $true
            RedirectStandardInput   = $true
            RedirectStandardOutput  = $true
            UseShellExecute         = $false
            WindowStyle             = [System.Diagnostics.ProcessWindowStyle]::Hidden
            WorkingDirectory        = $PSBoundParameters.ContainsKey('WorkingDirectory') ? $WorkingDirectory : $PSScriptRoot
            Verb                    = $PSBoundParameters.ContainsKey('Verb') ? $Verb : $null
        }

        # This will Error on Unix/Linux Systems if property LoadUserProfile is added regardless if it's null or false.
        if ($PSBoundParameters.ContainsKey('LoadUserProfile')) {
            $processStartInfoProps.Add('LoadUserProfile', $LoadUserProfile)
        }

        try {

            $process = New-Object System.Diagnostics.Process
            $process.EnableRaisingEvents = $true

            $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo -Property $processStartInfoProps
            $process.StartInfo = $processStartInfo

            # Register Process OutputDataReceived:
            #   This will create a background job to capture output data
            #   Reference: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.standardoutput?redirectedfrom=MSDN&view=net-7.0#System_Diagnostics_Process_StandardOutput
            $outputEventParams = @{
                InputObject = $process
                SourceIdentifier = 'OnOutputDataReceived '
                EventName = 'OutputDataReceived'
                Action = {
                    param (
                        [System.Object]$sender,
                        [System.Diagnostics.DataReceivedEventArgs]$e
                    )

                    foreach ($data in $e.Data) { 
                        if ($null -ne $data -and $data -ne "") { 
                            $($data).Trim()
                        } 
                    }
                }
            }
            $dataObject.OutputStream = Register-ObjectEvent @outputEventParams

            # Start the process/command
            if ($process.Start()) {
                $process.BeginOutputReadLine()
                $dataObject.ErrorData = $process.StandardError.ReadToEnd()

                if ($PSCmdlet.ParameterSetName -eq 'timer') {
                    $process.WaitForExit($Timer) | Out-Null
                } else {
                    $process.WaitForExit()
                }
            }
            
            # Retrieve the exit code and the OutputStream Job
            $dataObject.ExitCode = $process.ExitCode
            $dataObject.OutputData = Receive-Job -id $($dataObject.OutputStream.id)

            [bool]$hasError = ($null -ne $($dataObject.ErrorData) -and $($dataObject.ErrorData) -ne "") ? $true : $false
            [bool]$hasOutput = ($null -ne $($dataObject.OutputData) -and $($dataObject.OutputData) -ne "") ? $true : $false

            # Output Errors or Output if -PassThru was not provided
            if ($Passthru) {
                if ($hasError) {
                    $dataObject.ErrorData = $($dataObject.ErrorData.Trim())
                }
                $dataObject
            } else {

                if ($hasError) {
                    if ($($ErrorActionPreference) -ne 'Stop') {
                        Write-Error "Exit Code $($dataObject.ExitCode): $($dataObject.ErrorData.Trim())"
                    } else {
                        Throw "Exit Code $($dataObject.ExitCode): $($dataObject.ErrorData.Trim())"
                    }
                }

                if ($hasOutput) {
                    $($dataObject.OutputData)
                }
            }
        }
        finally {

            # Cleanup
            $process.Close()
            Unregister-Event -SourceIdentifier $($dataObject.OutputStream.Name) -Force | Out-Null
            Remove-Job -Id $($dataObject.OutputStream.Id) -Force
        }
    }
}

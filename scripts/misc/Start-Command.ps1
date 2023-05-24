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
.PARAMETER CommandArguments
    The optional parameters/arguments to be added with your command.
.PARAMETER WorkingDirectory
    The current WorkingDirectory to run said Command. If you are not using the full path to files, you should probably
    use this parameter. 
.PARAMETER LoadUserProfile
    Gets or sets a value that indicates whether the Windows user profile is to be loaded from the registry.

    This will NOT work on Unix/Linux/Mac.
.PARAMETER RedirectStandardInput
    Gets or sets a value indicating whether the input for an application is read from the StandardInput stream.
.PARAMETER RedirectStandardOutput
    Gets or sets a value that indicates whether the textual output of an application is written to the StandardOutput stream.
.PARAMETER RedirectStandardError
    Gets or sets a value that indicates whether the error output of an application is written to the StandardError stream.
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
    $Output = (Start-Command -Name 'whoami' -RedirectStandardOutput).Output

    if ($Output -ne "root") {
        Write-Output "You are not root"
    }
    Write-Output "You are root!"

    Example #3:
    This example demonstrates how to retrieve the output of said Command and use it for conditionals.
.INPUTS
    None
.OUTPUTS
    System.String
#>
function Start-Command {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
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
        [object]$CommandArguments,

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

        [parameter(Mandatory=$false)]
        [switch]$RedirectStandardOutput = $false,

        [parameter(Mandatory=$false)]
        [switch]$RedirectStandardInput = $false,

        [parameter(Mandatory=$false)]
        [switch]$RedirectStandardError = $false
    )

    begin {
        
        $process = New-Object System.Diagnostics.Process
        
        # Retrieve the command's path 
        $commandPath = (Get-Command -Name $Name -ErrorAction SilentlyContinue).Source

        if ($null -eq $commandPath -or $commandPath -eq "") {
            
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

            # Retrieve the version of PowerShell and its location and replace $commandPath with it
            if ($PSVersionTable.PSEdition -eq 'Core') {
                $commandPath = (Get-Command -Name 'pwsh').Source
            } else {
                $commandPath = (Get-Command -Name 'powershell').Source
            }
            
            #$test = "-noprofile -Command {$getPSCommand $CommandArguments}"
            # Reconfigure Arguments to execute PowerShell
            $CommandArguments = "-noprofile -Command `"& {$($getPSCommand.ReferencedCommand.Name) $CommandArguments}`""
        }

        #region Populate ProcessStartInfo properties
        $processStartInfoProps = @{
            FileName                = $commandPath
            UseShellExecute         = $False
        }
        
        # Add arguments if they were provided
        if ($PSBoundParameters.ContainsKey('CommandArguments')) {
            $processStartInfoProps.add('Arguments', $CommandArguments)
        }

        if ($PSBoundParameters.ContainsKey('WorkingDirectory')) {
            $processStartInfoProps.add('WorkingDirectory', $WorkingDirectory)
        }

        if ($PSBoundParameters.ContainsKey('RedirectStandardInput')) {
            $processStartInfoProps.add('RedirectStandardInput', $RedirectStandardInput)
        } else {
            $RedirectStandardInput = $false
        }

        if ($PSBoundParameters.ContainsKey('RedirectStandardOutput')) {
            $processStartInfoProps.add('RedirectStandardOutput', $RedirectStandardOutput)
        } else {
            $RedirectStandardOutput = $false
        }

        if ($PSBoundParameters.ContainsKey('RedirectStandardError')) {
            $processStartInfoProps.add('RedirectStandardError', $RedirectStandardError)
        } else {
            $RedirectStandardError = $false
        }

        if ($PSBoundParameters.ContainsKey('LoadUserProfile')) {
            $processStartInfoProps.add('LoadUserProfile', $LoadUserProfile)
        }
        #endregion

        $redirectObject = [pscustomobject]@{
            Title = $Name
            Input = ''
            Output = ''
            Error = ''
            ExitCode = ''
        }
    }
    process {
    
        # Create ProcessStartInfo object with our provided properties
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo -Property $processStartInfoProps
        # Start the process
        $process.StartInfo = $processStartInfo
        $process.Start() | Out-Null
        $process.WaitForExit()

        # Trim the input/output if -RedirectStandardInput or -RedirectStandardOutput are provided
        if ($RedirectStandardInput) {
            $redirectObject.Input = $process.StandardInput.ReadToEnd()
            if ($null -ne $($redirectObject.Input) -or $($redirectObject.Input) -ne "") {
                $redirectObject.input = $($redirectObject.input).trim()
            }
        }

        if ($RedirectStandardOutput) {
            $redirectObject.Output = $process.StandardOutput.ReadToEnd()
            if ($null -ne $($redirectObject.Output) -or $($redirectObject.Output) -ne "") {
                $redirectObject.Output = $($redirectObject.Output).trim()
            }
        }
        
        # Regardless if we have an error or not, this is required if we want try / catch to work.
        $redirectObject.Error = $process.StandardError.ReadToEnd()
        $redirectObject.ExitCode = $process.ExitCode
        
        # Output the object if any of these conditions are true
        if ($RedirectStandardInput -or $RedirectStandardOutput -or $RedirectStandardError) {
            $redirectObject
        }
    }
}

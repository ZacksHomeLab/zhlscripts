<#
.Synopsis
    This script will load provided functions into a remote session.
.DESCRIPTION
    This script will load provided functions into a remote session.
.PARAMETER Functions
    The name of the functions and/or commands that need to be initialized on a remote session.
.PARAMETER Session
    The PSSession of the remote destination.
.NOTES
    Author - Zack Flowers
.LINK
    GitHub: https://github.com/zackshomelab
.EXAMPLE
    Send-Functions -Functions "New-RandomPassword" -Session (New-PSSession -ComputerName 'Server1' -Credential (Get-Credential))
    
    The above example will create a PSSession to computer Server1 and send function New-RandomPassword over.
.INPUTS
    System.Management.Automation.Runspaces.PSSession
.OUTPUTS
    None
#>
function Send-Function {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory,
            Position=0,
            ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
        [System.String[]]$Functions,

        [Parameter(Mandatory,
            Position=1,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    begin {
        $commandDefinition = $null
        $functionData = @{}
        $foundCommand = $null
    }
    Process {
        # Iterate through provided function and store the found functions and its code into $functionData
        foreach ($Function in $Functions) {
            
            # Retrieve the function from Get-Command
            $foundCommand = Get-Command -Name $Function -ErrorAction SilentlyContinue
            $commandDefinition = $null

            # Skip if the command isn't found
            if (-not $foundCommand) {
                Write-Warning "Send-Function: Function $Function does not exist, skipping."
                continue
            }

            # Retrieve the function and its definition
            $commandDefinition = @"
                $($foundCommand.CommandType) $Function {
                    $($foundCommand.Definition)
                }
"@

            # Store the function & command definition into functionData
            $functionData.Add($Function, $commandDefinition)
        }

        # Enter the provided remote session and load the functions into its script scope
        if ($null -ne $functionData) {
            try {
                Invoke-Command -Session $Session -ScriptBlock {
                    # Store functionData in $data ($using:hashtable[$key] gives an error)
                    $data = $using:functionData
    
                    # Iterate through each function and load the function and its source code by
                    # dot-sourcing it.
                    foreach ($key in $data.keys) {
                        . ([ScriptBlock]::Create($data[$key]))
                    }
                } -ErrorAction Stop
            } catch {
                Throw "Send-Function: Could not send functions to remote session due to error $_"
            }
        }
    }
}

# Use the PowerShell extension setting `powershell.scriptAnalysis.settingsPath` to get the current workspace
# to use this PSScriptAnalyzerSettings.psd1 file to configure code analysis in Visual Studio Code.
# This setting is configured in the workspace's `.vscode/settings.json`.
#
# For more information on PSScriptAnalyzer settings see:
# https://github.com/PowerShell/PSScriptAnalyzer/blob/master/README.md#settings-support-in-scriptanalyzer
#
# You can see the predefined PSScriptAnalyzer settings here:
# https://github.com/PowerShell/PSScriptAnalyzer/tree/master/Engine/Settings
@{
    Severity     = @(
        'Error',
        'Warning',
        'Information'
    )

    # Analyze **only** the following rules. Use IncludeRules when you want
    # to invoke only a small subset of the default rules.
    IncludeRules = @(
        # Consecutive assignment statements are more readable if they are aligned.
        'PSAlignAssignmentStatement',

        # PowerShell has built-in variables known as automatic variables.
        # Many of them are read-only and PowerShell throws an error when trying to assign an value on those.
        'PSAvoidAssignmentToAutomaticVariable',

        # Mandatory parameters should not have a default values because there is no scenario where the default can be used.
        'PSAvoidDefaultValueForMandatoryParameter',

        # Switch parameters for commands should default to false.
        'PSAvoidDefaultValueSwitchParameter',

        # Avoid usage of global variables.
        'PSAvoidGlobalVars',

        # Invoking non-constant members can cause potential bugs.
        'PSAvoidInvokingEmptyMembers',

        # Lines should be no longer than a configured number of characters (default: 120), including leading whitespace (indentation).
        'PSAvoidLongLines',

        # Parameters should not have more than one type specifier. Multiple type specifiers on parameters can cause runtime errors.
        'PSAvoidMultipleTypeAttributes',

        # The value of the HelpMessage attribute should not be an empty string or a null value as this causes PowerShell's
        # interpreter to throw an error when executing the function or cmdlet.
        'PSAvoidNullOrEmptyHelpMessageAttribute',

        # Lines should not end with a semicolon.
        'PSAvoidSemicolonsAsLineTerminators',

        # Functions that use ShouldContinue should have a boolean force parameter to allow user to bypass it.
        'PSAvoidShouldContinueWithoutForce',

        # Lines should not end with whitespace characters.
        'PSAvoidTrailingWhitespace',

        # Avoid using the broken algorithms MD5 or SHA-1.
        'PSAvoidUsingBrokenHashAlgorithms',

        # An alias is an alternate name or nickname for a cmdlet or for a command element,
        # such as a function, script, file, or executable file.
        'PSAvoidUsingCmdletAliases',

        # The names of computers should never be hard coded as this will expose sensitive information.
        # The ComputerName parameter should never have a hard coded value.
        'PSAvoidUsingComputerNameHardcoded',

        # The use of the AsPlainText parameter with the ConvertTo-SecureString command can expose secure information.
        'PSAvoidUsingConvertToSecureStringWithPlainText',

        # In PowerShell 5.0, a number of fields in module manifest files (.psd1) have been changed.
        'PSAvoidUsingDeprecatedManifestFields',

        # Empty catch blocks are considered a poor design choice because any errors occurring in a try block cannot be handled.
        'PSAvoidUsingEmptyCatchBlock',

        # Password parameters that take in plaintext will expose passwords and compromise the security of your system.
        'PSAvoidUsingPlainTextForPassword',

        # Using positional parameters reduces the readability of code and can introduce errors.
        # It is possible that a future version of the cmdlet could change in a way that would break existing scripts
        # if calls to the cmdlet rely on the position of the parameters.
        'PSAvoidUsingPositionalParameters',

        # As of PowerShell 3.0, the CIM cmdlets should be used over the WMI cmdlets.
        'PSAvoidUsingWMICmdlet',

        # The use of Write-Host is greatly discouraged unless in the use of commands with the Show verb.
        'PSAvoidUsingWriteHost',

        # Checks that lines don't end with a backtick followed by whitespace.
        'PSMisleadingBacktick',

        # Close brace placement should follow a consistent style.
        # It should be on a new line by itself and should not be followed by an empty line.
        'PSPlaceCloseBrace',

        # Open brace placement should follow a consistent style.
        # It can either follow K&R style (on same line) or the Allman style (not on same line).
        'PSPlaceOpenBrace',

        # To ensure that PowerShell performs comparisons correctly, the $null element should be on the left side of the operator.
        'PSPossibleIncorrectComparisonWithNull',

        # In many programming languages, the equality operator is denoted as == or =, but PowerShell uses -eq.
        'PSPossibleIncorrectUsageOfAssignmentOperator',

        # In many programming languages, the comparison operator for 'greater than' is > but PowerShell
        # uses -gt for it and -ge (greater or equal) for >=.
        'PSPossibleIncorrectUsageOfRedirectionOperator',

        # Comment based help should be provided for all PowerShell commands.
        'PSProvideCommentHelp',

        # You cannot use following reserved characters in a function or cmdlet name as these can cause parsing or runtime errors.
        'PSReservedCmdletChar',

        # You can't redefine common parameters in an advanced function.
        # Using the CmdletBinding or Parameter attributes creates an advanced function.
        'PSReservedParams',

        # This rule identifies parameters declared in a script, scriptblock, or function scope that have not been used in that scope.
        'PSReviewUnusedParameter',

        # Whenever we call a command, care should be taken that it is invoked with the correct syntax and parameters.
        'PSUseCmdletCorrectly',

        # Indentation should be consistent throughout the source file.
        'PSUseConsistentIndentation',

        # This rule is not enabled by default. The user needs to enable it through settings.
        'PSUseConsistentWhitespace',

        # This is a style/formatting rule. PowerShell is case insensitive where applicable.
        'PSUseCorrectCasing',

        # Variables that are assigned but not used are not needed.
        'PSUseDeclaredVarsMoreThanAssignments',

        # A command should return the same type as declared in OutputType.
        'PSUseOutputTypeCorrectly',

        # Functions that support pipeline input should always handle parameter input in a process block.
        'PSUseProcessBlockForPipelineCommand',

        # If the cmdlet or function has a Credential parameter, the parameter must accept the PSCredential type.
        'PSUsePSCredentialType',

        # UseToExportFieldsInManifest
        'PSUseToExportFieldsInManifest',

        # If a scriptblock is intended to be run in a new runspace, variables inside it
        # should use the $using: scope modifier, or be initialized within the scriptblock.
        'PSUseUsingScopeModifierInNewRunspaces',

        # Check if help file uses UTF-8 encoding.
        'PSUseUTF8EncodingForHelpFile'
    )

    # Do not analyze the following rules. Use ExcludeRules when you have
    # commented out the IncludeRules settings above and want to include all
    # the default rules except for those you exclude below.
    # Note that if a rule is in both IncludeRules and ExcludeRules, the rule
    # will be excluded.
    #
    # ExcludeRules = @('PSAvoidUsingWriteHost')

    Rules        = @{
        PSAlignAssignmentStatement         = @{
            Enable         = $true
            CheckHashtable = $true
        }

        PSAvoidLongLines                   = @{
            Enable            = $true
            MaximumLineLength = 180
        }

        PSAvoidSemicolonsAsLineTerminators = @{
            Enable = $true
        }

        PSAvoidUsingPositionalParameters   = @{
            CommandAllowList = @(
                'Write-Host',
                'Write-Output',
                'Write-Verbose',
                'Write-Information',
                'Write-Error',
                'Write-Debug',
                'throw'
            )
            Enable           = $true
        }

        PSPlaceOpenBrace                   = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }

        PSPlaceCloseBrace                  = @{
            Enable             = $true
            NewLineAfter       = $false
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore  = $false
        }

        PSProvideCommentHelp               = @{
            Enable                  = $true
            ExportedOnly            = $false
            BlockComment            = $true
            VSCodeSnippetCorrection = $false
            Placement               = 'before'
        }

        PSUseConsistentIndentation         = @{
            Enable              = $true
            Kind                = 'space'
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            IndentationSize     = 4
        }

        PSUseConsistentWhitespace          = @{
            Enable          = $true
            CheckInnerBrace = $true
            CheckOpenBrace  = $false # incorrectly flags all `Should -Throw` Pester assertions
            CheckOpenParen  = $true
            CheckOperator   = $false # conflicts with `PSAlignAssignmentStatement`
            CheckPipe       = $true
            CheckSeparator  = $true
            CheckParameter  = $true
        }

        PSUseCorrectCasing                 = @{
            Enable = $true
        }
    }
}

<#
.Synopsis
    This script will generate a password.
.DESCRIPTION
    This script will generate a random password based on the provided requirements.
.PARAMETER length
    The length of the password.
.PARAMETER upper
    The bare minimum number of Uppercase characters to have in the password.
.PARAMETER lower
    The bare minimum number of Lowercase characters to have in the password.
.PARAMETER number
    The bare minimum number of Numeric characters to have in the password.
.PARAMETER special
    The bare minimum number of Special characters to have in the password.

    The following characters are considered Special: )#^*%{.]~+[!@&\:_'`/($=,}<;|>"-?
.EXAMPLE
    New-RandomPassword -length 15 -upper 5 -lower 5 -number 3 -special 2

    The above will generate a 15 character long password with 5 upper characters,
    5 lower characters, 3 numbers, and 2 special characters.

    Example Output #1: D!vTH4+xaGbu60G
    Example Output #2: GK0'06ItHa=pyhI
.EXAMPLE
    New-RandomPassword -length 20

    The above will generate a 20 character long password using the default values of:
        Uppercase: 1
        Lowercase: 1
        Numbers: 1
        Special: 1

    Example Output #1: #w=hR|m/.egxjvz:Fg9:
    Example Output #2: >qHj\+m/gD8>9t.,&W'Z
.NOTES
    Author - Zack Flowers
.LINK
    GitHub - https://github.com/ZacksHomeLab
#>
function New-RandomPassword {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateRange(4,512)]
        [int]$length,

        [Parameter(Mandatory=$false)]
        [ValidateScript({$_ -le $length -and 
            $_ -ge 0 -and 
            $_ -is [int]})]
        [int]$upper = 1,

        [Parameter(Mandatory=$false)]
        [ValidateScript({$_ -le $length -and 
            $_ -ge 0 -and 
            $_ -is [int]})]
        [int]$lower = 1,

        [Parameter(Mandatory=$false)]
        [ValidateScript({$_ -le $length -and 
            $_ -ge 0 -and 
            $_ -is [int]})]
        [int]$number = 1,

        [Parameter(Mandatory=$false)]
        [ValidateScript({$_ -le $length -and 
            $_ -ge 0 -and 
            $_ -is [int]})]
        [int]$special = 1
    )

    Begin {
        # Throw an error if the provided requirements exceed length
        if(($upper + $lower + $number + $special) -gt $length) {
            Throw "New-RandomPassword: Upper, Lower, Numeric, and Special characters cannot exceed the provided length."
        }

        # Generate an object that contains Uppercase, Lowercase, Numbers, Special, and Any characters
        # Probably a little over engineered
        #
        # It would probably be more efficient to use pre-determined strings like "ABCD..."
        $charSet = @{
            Lower = (97..122) | 
                Get-Random -Count 26 | 
                ForEach-Object {
                    [char]$_
                }

            Upper = (65..90) | 
                Get-Random -Count 26 | 
                ForEach-Object {
                    [char]$_
                }

            Number = (48..57) | 
                Get-Random -Count 10 | 
                ForEach-Object {
                    [char]$_
                }

            Special = (33..47) + (58..64) + (91..96) + (123..126) | 
                Get-Random -Count 32 | 
                ForEach-Object {
                    [char]$_
                }
            Any = (33..47) + (58..64) + (91..96) + (123..126) + (48..57) + (65..90) + (97..122) |
                Get-Random -Count 94 |
                ForEach-Object {
                    [char]$_
                }
        }

        $newPassword = $null

        # Initialize these variables if they don't exist
        if ($null -eq $upper) {
            $upper = 0
        }

        if ($null -eq $lower) {
            $lower = 0
        }

        if ($null -eq $number) {
            $number = 0
        }

        if ($null -eq $special) {
            $special = 0
        }
        
        # Create a variable to hold the amount of 'random' choices
        # This is here so we are guranteed to fill the password with $length of chars
        $any = $length - ($upper + $lower + $number + $special)

        # Create a variable to hold the amount of char choices
        # For example, 8 any, 1 upper, 1 lower, 1 special, 1 number
        $choices = @()
    }

    Process {

        # Loop through the size of $length and store the charact into $newPassword at
        # the end of the loop
        $newPassword = for ($i = $length; $i -gt 0; $i--) {

            $choices = @()
            $typeOfChar = $null

            # Populate the $choices array with the amount of char selections we have
            if ($upper -gt 0) {
                $choices += ,('Upper') * $upper
            }
            if ($lower -gt 0) {
                $choices += ,('Lower') * $lower
            }
            if ($special -gt 0) {
                $choices += ,('Special') * $special
            }
            if ($number -gt 0) {
                $choices += ,('Number') * $number
            }
            if ($any -gt 0) {
                $choices += ,('Any') * $any
            }

            # Make a random selection of what type of char to select
            $typeOfChar = Get-Random -InputObject $choices

            # Select a random character based on type
            $character = Get-Random -InputObject $charSet[$typeOfChar]

            # As we're going to recreate the array on next iteration
            # I'm just going to decrement the choosen variable instead
            switch ($typeOfChar) {
                'Any' {
                    if ($any -gt 0) {
                        $any--
                    }
                    # Add character into $newPassword
                    $character
                    continue
                }
                'Upper' {
                    if ($upper -gt 0) {
                        $upper--
                    }
                    # Add character into $newPassword
                    $character
                    continue
                }
                'Lower' {
                    if ($lower -gt 0) {
                        $lower--
                    }
                    # Add character into $newPassword
                    $character
                    continue
                }
                'Special' {
                    if ($special -gt 0) {
                        $special--
                    }
                    # Add character into $newPassword
                    $character
                    continue
                }
                'Number' {
                    if ($number -gt 0) {
                        $number--
                    }
                    # Add character into $newPassword
                    $character
                    continue
                }
            }
        }

        # Join the array into a single string
        $newPassword = $newPassword -join ''
    }

    end {
        # Output the password
        Write-Debug "New-RandomPassword: Generated Password - $newPassword"
        return $newPassword
    }
}

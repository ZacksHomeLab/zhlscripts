<#
.Synopsis
    Compares hash values between a source and target.
.DESCRIPTION
    Compares hash values between a source and target. If there's different hashes, function will return true, otherwise false.
.PARAMETER Source
    The one or many paths of files/folders to retrieve said hash values from.
.PARAMETER Container
    The one or many paths of files/folders to retrieve said hash values from.
.EXAMPLE
    $LE_PRIVATE_KEY = "/etc/letsencrypt/live/$URL/privkey.pem"
    $LE_FULLCHAIN = "/etc/letsencrypt/live/$URL/fullchain.pem"
    $LE_CA_FILE = "/etc/letsencrypt/live/$URL/chain.pem"

    # Location to store the certificates in WikiJS's environment
    $WIKIJS_SSL_PRIVATE_KEY = "/opt/wiki/letsencrypt/privkey.pem"
    $WIKIJS_SSL_FULLCHAIN = "/opt/wiki/letsencrypt/fullchain.pem"
    $WIKIJS_SSL_CA_FILE = "/opt/wiki/letsencrypt/chain.pem"
    
    $source = $(Get-Item -Path $LE_PRIVATE_KEY).ResolvedTarget, `
            $(Get-Item -Path $LE_FULLCHAIN).ResolvedTarget, `
            $(Get-Item -Path $LE_CA_FILE).ResolvedTarget
        
    $target = $WIKIJS_SSL_PRIVATE_KEY, $WIKIJS_SSL_FULLCHAIN, $WIKIJS_SSL_CA_FILE
        
    # This will return true if we have different hash values
    $needToCopy = Get-DifferentHashStatus -Source $source -Target $target -ErrorAction Stop

    if ($needToCopy) { Write-Output "We have different hash values." }
.NOTES
    Author - Zack Flowers
.LINK
    GitHub - https://github.com/ZacksHomeLab/
#>
function Get-DifferentHashStatus {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [string[]]$Source,

        [parameter(Mandatory)]
        [string[]]$Target
    )

    Begin {
        # Add source and target files together
        $files = ($Source + $Target)
    }
    process {

        # if we have different file hashes, this will return 1 (aka we have differences).
        # Otherwise, this will return 0 (aka we have no differences)
        (Get-FileHash -Path $files | 
            Select-Object -Property Path, Hash | 
            Group-Object -Property Hash | 
            Where-Object Count -eq 1).Count -as [bool]
    }
}

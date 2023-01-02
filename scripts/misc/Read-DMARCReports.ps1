<#
.Synopsis
    This script analyzes DMARC Reports sent to dmarc@starkbros.com and sends a summary to whomever is in the $EmailAddresses parameter.
.DESCRIPTION
    This script utilizes an azure application to use Microsoft Graph api which queries a given mailbox (dmarc@starkbros.com) and looks for
    attachments. Once found, the attachments are converted from their base64 encode into .zip files to be extracted. The script will then
    use 7Zip to extract said files. Once extracted, the script will read these XML files and query for specific strings to determine if
    a given record passes DMARC. The results are sent to $EmailAddresses.
.NOTES
    Author - Zack Flowers
.PARAMETER DmarcEmails
    The email addresses of the inboxes that house our dmarc reports. Default is dmarc@starkbros.com & dmarc@starkbros.ca
.PARAMETER Days
    The given timeframe to query the search (i.e., Only search for emails within the last 2 days)
.PARAMETER Hours
    The given timeframe to query the search (i.e., Only search for emails within the last 8 hours)
.PARAMETER CertSubject
    The subject line of the certificate used by the Azure Application. The default is AzAppDmarcReader (the name of the Azure Application, will only work on
    one computer though)
.PARAMETER CertPath
    The Path of where the certificate resides on the host machine. The default is 'Cert:\LocalMachine\My'.
.PARAMETER TenantId
    The TenantID assigned to the Azure Application. The default is '7fefc8ea-912f-4a2b-9289-93698cc38a86'
.PARAMETER AppId
    The Application ID assigned to the Azure Application. The default app is PRTG Backups Emails, which is ID 'd8323542-6934-4bb7-9155-9f85a5598978'
.PARAMETER AppName
    The name of the application in Azure. (Not needed if an AppID was given but needed if you do NOT provide an AppId)
.PARAMETER Log
    The log file to store the output of this script.
.PARAMETER AttachmentDirectory
    The directory to store the attachments. Default is (C:\Windows\Temp\Dmarc-Reports_$((Get-Date).toString('yyyy-MM-dd'))).
.PARAMETER Analysis
    The amount of detail to be shown in the email. Basic or Advanced, the default is Basic.
.PARAMETER DisplayResults
    Use this parameter if you want to only show Fail, Pass, or Both DMARC Results. Default is Both.
.PARAMETER EmailAddresses
    The array of email addresses to receive the Dmarc Analysis report.
.EXAMPLE
    This is how to run the script if no default parameters were given. Checks emails in the mailbox dmarc@starkbros.com within the past day, uses the azure
    application AppID and TenantID. The basic analysis will be sent to zack.flowers@starkbros.com

    .\Read-DMARCReports.ps1 -Email 'dmarc@starkbros.com' -Days 1 -CertSubject 'AzAppDMARCReader' -TenantID '7fefc8ea-912f-4a2b-9289-93698cc38a86' `
    -AppId 'd8323542-6934-4bb7-9155-9f85a5598978' -Log 'C:\Windows\Temp\Read-DmarcReports.log' -Analysis Basic -EmailAddresses 'zack.flowers@starkbros.com'

.EXAMPLE
    This is how to run the script with the default values. NOTE, this will only work like this on the server that has the SSL certificate for your AppID in Azure. Otherwise, you'll have to
    add your own AppID and CertSubject.
    .\Read-DMARCReports.ps1
.LINK
    Documentation can be found here: https://confluence.starkbros.com/display/INF/Azure+App%3A+DMARC+Report+Reader
#>
[cmdletbinding()]
param (
    [parameter(Mandatory=$false)]
    [string[]]$DmarcEmails = @('dmarc@starkbros.com'),

    [parameter(Mandatory=$false)]
    [int]$Days = 1,

    [Parameter(Mandatory=$false)]
    [int]$Hours,

    [Parameter(Mandatory=$false)]
    [string]$CertSubject = 'AzAppDmarcReader',

    [Parameter(Mandatory=$false)]
    [string]$CertPath = 'Cert:\LocalMachine\My',

    [parameter(Mandatory=$false)]
    [string]$TenantId = '7fefc8ea-912f-4a2b-9289-93698cc38a86',

    [Parameter(Mandatory=$false)]
    [string]$AppId = 'd8323542-6934-4bb7-9155-9f85a5598978',

    [Parameter(Mandatory=$false)]
    [string]$AppName,

    [Parameter(Mandatory=$false)]
    [string]$Log = 'C:\Windows\Temp\Read-DmarcReports.log',

    [parameter(Mandatory=$false)]
    [string]$AttachmentDirectory,

    [parameter(Mandatory=$false)]
    [ValidateSet("Basic", "Advanced")]
    [string]$Analysis = 'Basic',

    [parameter(Mandatory=$false)]
    [ValidateSet("Pass", "Fail", "Both")]
    [string]$DisplayResults = 'Both',

    [parameter(Mandatory=$false)]
    [switch]$CheckIPsForBlacklist,

    [parameter(Mandatory=$false)]
    [string[]]$EmailAddresses = @('DailyDMARCAnalysis@starkbros.com'),

    [parameter(Mandatory=$false)]
    [switch]$KeepFailFiles
)

#region Test Variables
<# Test Variables
$DmarcEmails = @('dmarc@starkbros.ca', 'dmarc@starkbros.com')
$Email = 'dmarc@starkbros.com'
$CertSubject = $ENV:COMPUTERNAME
$Days = 7
$AppId = 'b7145826-73df-4ba9-b717-8f7d954c28ff'
$TenantId = '7fefc8ea-912f-4a2b-9289-93698cc38a86'#>
#endregion


#region Variables
# Default Log File Path
if ($null -ne $Log) {
    $script:LOG_Path = $Log
} else {
    $script:LOG_PATH = 'C:\Windows\Temp\Read-DmarcReports.log'
}
# Default Attachment Directory Path
$DEFAULT_ATTACHMENT_DIRECTORY = "C:\Windows\Temp\Dmarc-Reports_$((Get-Date).toString('yyyy-MM-dd'))"

# Reset the Json Web Token
$JWT = $null
# Reset the Access Token to make API Calls
$AccessToken = $null
# Reset the certificate to authenticate with the application
$Cert = $null
# Reset the certificate's thumbprint
$Thumbprint = $null
# Reset the response of the API Call
$Response = $null
#endregion

#region Exit Codes for Connecting to Azure Region
$exitCode_MissingPowerShellModuleAZ = 40
$exitcode_FailedGettingTenantIDFromAzureSubscription = 42
$exitcode_FailedGettingAppIDWithAppNameFromAzure = 43
$exitcode_FailedGivingAppNameOrAppID = 44
$exitcode_FailedGettingCertificateFromStore = 45
$exitcode_FailedGettingThumbprintFromCertificate = 46
$exitcode_FailedConnectingToAzure = 47
$exitcode_FailedCreatingJWTToken = 48
$exitcode_FailedGettingAccessTokenFromAzure = 49
$exitcode_FailedProvidingHoursOrDays = 50
#endregion

#region PreCondition exit codes
$exitcode_Missing7ZIP = 21
#endregion

#region PRTG Result codes
# 403 error reading emails
$resultCode_ForbiddenReadingEmails = 4
# Failed making api call more than 4 times for reading email inbox
$resultCode_OtherIssuesReadingEmails = 5
# 403 error reading attachments from email messages
$resultCode_ForbiddenGettingAttachmentsFromEmail = 6
# Failed making api call more than 4 times for reading attachments from email messages
$resultCode_OtherIssuesReadingAttachmentsFromEmail = 7
# 403 error reading attachments from digging deeper into an email
$resultCode_ForbiddenGettingAttachmentsFromDeeperInspection = 8
# Failed making api call more than 4 times for digging deeper into an email to retrieve attachment data
$resultCode_OtherIssuesGettingAttachmentsFromDeeperInspection = 9
# We have to make a new directory for our attachments, if we can't find it, this result will happen.
$resultCode_FailedGettingNewDirectoryForAttachments = 10
# If we fail making a new directory, result to this
$resultCode_FailedCreatingNewDirectory = 11
# Attachments were extracted but cannot find them, was there a issue with the GetAttachmentLocation?
$resultCode_ExtractedAttachmentsButCantFindThem = 12
# We read our extracted files but there's zero data somehow
$resultCode_ReadingExtractedFilesGaveZeroData = 13
# Everything was fine until we tried sending the email of our analysis.
$resultCode_FailedSendingEmail = 14
#endregion

#region Functions
function Import-AZ {
    [cmdletbinding()]
    param (
        [string[]]$Module = 'AZ'
    )

    Process {
        if (-not (Get-Module -Name AZ)) {
            Write-Verbose "`Import-AZ: Checking if we need to install/import AZ..."

            # Install/Import AZ if not installed already
            if (-not (Get-InstalledModule -Name 'AZ' -ErrorAction SilentlyContinue)) {
    
                # Set to TLS 1.2 if it has to go out and download something
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                write-verbose "Import-AZ: Module AZ isn't installed, installing now."
                
                # Install the module
                Install-Module -Name Az -Repository PSGallery -Force -Scope AllUsers

                if (Get-InstalledModule -Name 'Az' -ErrorAction SilentlyContinue) {
                    Write-Verbose "Import-AZ: AZ was sucessfully installed!"
                } else {
                    Write-Warning "Import-AZ: Error installing AZ"
                    Throw "Import-AZ: Error installing AZ"
                    break
                }
                foreach ($Mod in $Module) {
                    # Once Installed, import the module
                    if (-not (Get-Module -Name $Mod -ErrorAction SilentlyContinue)) {
                        Write-Verbose "Import-AZ: Importing Module, this will take some time."
                        Import-Module -name $Mod -ErrorAction SilentlyContinue

                        if (Get-Module -Name $Mod) {
                            Write-Verbose "Import-AZ: Module $Mod was sucessfully imported!"
                        } else {
                            Throw "Import-AZ: Error importing Module $Mod"
                            break
                        }
                    }
                }
            } else {
                # Module is installed, try to import it
                foreach ($Mod in $Module) {
                    if (-not (Get-Module -Name $Mod -ErrorAction SilentlyContinue)) {
                        Write-Verbose "Import-AZ: Module $Mod was already installed, importing now."
                        Import-Module -name $Mod -ErrorAction SilentlyContinue
    
                        if (Get-Module -Name $Mod) {
                            Write-Verbose "Import-AZ: Module $Mod was sucessfully imported!"
                        } else {
                            Throw "Import-AZ: Error importing Module $Mod"
                        }
                    } else {
                        Write-Verbose "Import-AZ: Module $Mod was already imported."
                    }
                }
            }
        } else {
            Write-Verbose "Import-AZ: Module 'Az' was already imported."
        }
    }
}
function Get-CertThumbPrint {
    [cmdletbinding()]
    param (
        [string]$CertPath,
        [string]$Subject,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    begin {
        if ($null -eq $Cert) {
            $Cert = Get-ChildItem -Path $CertPath -ErrorAction SilentlyContinue | Where-Object Subject -Match $Subject
        }
        $Thumbprint = $null
    }

    process {
        if ($null -eq $Cert) {
            Throw "Get-CertThumbPrint: Did not find a certificate with Subject $Subject in Path $CertPath."
        } else {
            $Thumbprint = $Cert.Thumbprint
        }
    }

    end {
        return $Thumbprint
    }
}

function Get-Cert {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CertPath,
        [parameter(Mandatory)]
        [string]$CertSubject
    )

    BEGIN {
        $Cert = Get-ChildItem -Path $CertPath -ErrorAction SilentlyContinue | Where-Object Subject -Match $CertSubject
    }

    END {
        if ($null -eq $Cert) {
            Throw "Get-Cert: Did not find a certificate with Subject $CertSubject in Path $CertPath."
        } else {
            return $Cert
        }
    }
}

function New-JWToken {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,Position=0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [parameter(Mandatory,Position=1)]
        [string]$AppId,
        [parameter(Mandatory,Position=2)]
        [string]$TenantId,
        [parameter(Mandatory,Position=3)]
        [string]$Guid
    )

    begin {

        $JWTHeaders = @{
            'alg' = "RS256"
            'typ' = "JWT"
            'x5t'= [System.Convert]::ToBase64String($Cert.GetCertHash())
        } | ConvertTo-Json -Compress

        $JWTStart = ([DateTimeOffset](Get-Date).ToUniversalTime()).ToUnixTimeSeconds()
        $JWTEnd = ([DateTimeOffset](Get-Date).AddHours(1).ToUniversalTime()).ToUnixTimeSeconds()

        $JWTPayLoad = @{
            'aud' = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            'exp' = $JWTEnd
            'iss' = $AppId
            'jti' = $guid
            'nbf' = $JWTStart
            'sub' = $AppId
        } | ConvertTo-Json -Compress

        $EncodeJWTHeaderBytes = $null
        $EncodeJWTHeaders = $null

        $EncodeJWTPayLoadBytes = $null
        $EncodeJWTPayLoad = $null

        $JWTToken = $null
        $ToSign = $null

        $RSACryptoSP = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $HashAlgo = [System.Security.Cryptography.SHA256CryptoServiceProvider]::new()
        $SHA256Oid = [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA256");

        $HashBytes = $null
        $SignedBytes = $null
        $Signature = $null
    }

    process {
        $EncodeJWTHeaderBytes = [system.text.encoding]::UTF8.GetBytes($JWTHeaders)
        $EncodeJWTHeaders = [system.convert]::ToBase64String($EncodeJWTHeaderBytes) -replace '\+','-' -replace '/','_' -replace '='

        $EncodeJWTPayLoadBytes = [system.text.encoding]::UTF8.GetBytes($JWTPayLoad)
        $EncodeJWTPayLoad = [system.convert]::ToBase64String($EncodeJWTPayLoadBytes) -replace '\+','-' -replace '/','_' -replace '='

        $JWTToken = $EncodeJWTHeaders + '.' + $EncodeJWTPayLoad
        $ToSign = [system.text.encoding]::UTF8.GetBytes($JWTToken)

        $RSACryptoSP.FromXmlString($Cert.PrivateKey.ToXmlString($true))
        $HashBytes = $HashAlgo.ComputeHash($ToSign)
        $SignedBytes = $RSACryptoSP.SignHash($HashBytes, $SHA256Oid)
        $Signature = [Convert]::ToBase64String($SignedBytes) -replace '\+','-' -replace '/','_' -replace '=' 

        $JWTToken = $JWTToken + '.' + $Signature
    }

    end {
        return $JWTToken
    }
}
function Save-AccessToken {
    [cmdletbinding()]
    param (
        [parameter(Mandatory, Position=0)]
        [string]$Path,

        [parameter(Mandatory, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken
    )

    process {
        Write-Verbose "Save-AccessToken: Attempting to save access token to path $Path..."
        try {
            $AccessToken | Set-Content -Path $Path -Force
        } catch {
            Throw "Save-AccessToken: Failed to save access token at path $Path"
        }
    }
}
function Remove-AccessToken {
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false)]
        [string]$TokenPath = "C:\Windows\Temp\token$($Env:USERNAME).txt"
    )

    process {
        if (Test-Path -Path $TokenPath) {
            Write-Log -EntryType Information -Message "Remove-AccessToken: Deleting Access token at path $TokenPath."
            Remove-Item -Path $TokenPath -Force -ErrorAction Stop
        } else {
            Write-Log -EntryType Information -Message "Remove-AccessToken: Access Token does not exist at path $TokenPath."
        }
    }
}
function Get-AccessToken {
    [cmdletbinding()]
    param (
        [string]$uri = 'https://login.microsoftonline.com',
        [parameter(Mandatory)]
        [string]$TenantId,
        [string]$scope = 'https://graph.microsoft.com/.default',
        [parameter(Mandatory)]
        [string]$ClientId,
        [string]$ClientAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        [parameter(Mandatory)]
        [string]$ClientAssertion,
        [string]$TokenPath = "C:\Windows\Temp\token$($Env:USERNAME).txt"
    )

    begin {
        $Body = @{
            scope = $scope
            client_id = $ClientId
            client_assertion_type = $ClientAssertionType
            client_assertion = $ClientAssertion
            grant_type = 'client_credentials'
        }
        $token = $null
        $NewToken = $true

        # Check if we have a token file
        # If we do, see if it's still usable so we do not have to keep making new access tokens
        if ($null -ne $TokenPath) {
            if (Test-Path -Path $TokenPath) {
                $File = Get-Item -Path $TokenPath
                if ($File.LastWriteTime -gt (Get-Date).AddMinutes(-50)) {
                    Write-Verbose "Get-AccessToken: We can still use the token to make API calls, reading token from file..."
                    $NewToken = $false
                }
            }
        }
    }

    process {
        if ($NewToken) {
            Write-Verbose "Get-AccessToken: Retrieving a new access token..."
            try {
                $Token = Invoke-WebRequest -Uri $($Uri + "/$TenantId/oauth2/v2.0/token") -Method POST -Body $Body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -ErrorAction Stop

                if ($null -ne $token) {
                    $Token = ($Token.Content | ConvertFrom-Json).access_token
                }
            } catch {
                Throw "Get-AccessToken: Failed to get access token because of Error $_"
            }
            Write-Verbose "Get-AccessToken: Saving token for later usage..."
            # Save token to file securely
            try {
                Save-AccessToken -Path $TokenPath -AccessToken ($Token | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString) -ErrorAction Stop
            } catch {
                Throw "Get-AccessToken: Failed to save access token to file due to $_"
            }
            
        } else {

            # Reusing old token, convert the string and make it usable.
            try {
                $Token = (Get-Content -Path $TokenPath -ErrorAction Stop | ConvertTo-SecureString)
                if ($null -ne $Token) {
                    $Token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token))
                }
            } catch {
                Throw "Get-AccessToken: Failed to read access token from file due to error $_"
            }
        }
    }

    end {
        return $token
    }
}
function Get-FilterStringForAttachments {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [string]$Email,
        [parameter(Mandatory=$false)]
        [boolean]$HasAttachments = $true,
        [parameter(Mandatory=$false)]
        [int]$Days = 1,
        [parameter(Mandatory=$false)]
        [int]$Hours = 0
    )
    begin {
        $EmailsAfterThisDate = $null
        if ($null -eq $Hours) {
            $Hours = 0
        }
        if ($null -eq $Days) {
            $Days = 0
        }
        $FilterCount = 0
        $FilterString = "users/$Email/mailfolders/Inbox/messages?`$filter="
    }

    process {
        # Convert the date format if user provided a timeframe
        $TotalHours = ($Days * 24) + $Hours
        if ($TotalHours -gt 0) {
            $EmailsAfterThisDate = (Get-Date).AddHours(-$TotalHours)
            # Convert date format to something graph api can understand
            $EmailsAfterThisDate = Get-Date($EmailsAfterThisDate) -format s
            # Turns the date string into this: 2022-12-11T09:22:52Z
            $EmailsAfterThisDate = $EmailsAfterThisDate + 'Z'
        }

        # Match the from address if provided
        if ($HasAttachments) {
            $FilterString = $FilterString + "hasAttachments eq true"
            $FilterCount += 1
        }

        # Filter by received by x date
        if ($TotalHours -gt 0) {
            if ($FilterCount -gt 0) {
                $FilterString = $FilterString + " and (receivedDateTime ge $EmailsAfterThisDate)"
            } else {
                $FilterString = "(receivedDateTime ge $EmailsAfterThisDate)"
            }
            $FilterCount += 1
        }

         # The API should respond with the subject line, and ID of the attachment
         # Example filter string: $filter=hasAttachments eq true and (receivedDateTime ge 2022-12-10T09:22:52Z)&$select=subject,id
         $FilterString = $FilterString + "&Select=Subject,From,id"
    }

    end {
        return $FilterString
    }
}
function Get-FilterStringAttachmentIDs {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [string]$Email,

        [parameter(Mandatory)]
        [string]$ID
    )
    end {
        return "users/$Email/mailfolders/Inbox/messages/$ID/attachments/"
    }
}

function Get-FilterStringAttachmentData {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [string]$Email,
        
        [parameter(Mandatory)]
        [string]$ID,

        [parameter(Mandatory)]
        [string]$AttachmentID
    )

    end {
        # The $value outputs the email into base 64 encode
        return "users/$Email/mailfolders/Inbox/messages/$ID/attachments/$AttachmentID/?`$expand=microsoft.graph.itemattachment/item"
    }
}

function Write-Log {
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory,
            Position=0)]
            [ValidateNotNullOrEmpty()]
        [String]$Message,

        [Parameter(Mandatory=$false,
            Position=1)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('Verbose', 'Information', 'Warning', 'Error', 'Debug')]
        [String]$EntryType = 'Information',

        [parameter(Mandatory=$false,
            Position=2)]
            [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ErrorRecord]$ErrorInfo,

        [parameter(Mandatory=$false,
            Position=3)]
        [string]$Path = $script:LOG_PATH
    )

    begin {
        $Content = "[$(Get-Date -f g)] [$EntryType] - $Message"

        # Create the default Hash Table (Ordered is added so the columns will be displayed as they are stored in the table)
        [pscustomobject]$Log = [ordered]@{
            Time = (Get-Date -f g)
            ComputerName = $env:ComputerName
            EntryType = $EntryType
            Message = $Message
        }

        # If the log file doesn't exist, we'll need to populate the first row regardless if there's an error or not
        if (-not (Test-Path -Path $Path)) {
            <#if ($EntryType -eq "Error" -and $null -ne $ErrorInfo) {
                $Log.Add('ErrorFullyQualifiedErrorID', (($ErrorInfo).FullyQualifiedErrorId))
                $Log.Add('ErrorMessage', (($ErrorInfo).Exception.Message))
                $Log.Add('ErrorCategory', (($ErrorInfo).CategoryInfo.Category))
                $Log.Add('ErrorScriptStackTrace', (($ErrorInfo).ScriptStackTrace))
            } else {
                # File doesn't exist but we don't have an error. Populate columns with an empty row
                $Log.Add('ErrorFullyQualifiedErrorID', '')
                $Log.Add('ErrorMessage', '')
                $Log.Add('ErrorCategory', '')
                $Log.Add('ErrorScriptStackTrace', '')
            }#>
            
        } else {

            <# File exists, only add the error information if necessary
            if ($EntryType -eq 'Error' -and ($null -ne $ErrorInfo)) {
                $Log.Add('ErrorFullyQualifiedErrorID', (($ErrorInfo).FullyQualifiedErrorId))
                $Log.Add('ErrorMessage', (($ErrorInfo).Exception.Message))
                $Log.Add('ErrorCategory', (($ErrorInfo).CategoryInfo.Category))
                $Log.Add('ErrorScriptStackTrace', (($ErrorInfo).ScriptStackTrace))
            }#>
        }    
    }
    process
    {
        $Content | Out-file -FilePath $Path -Append -Force -ErrorAction SilentlyContinue

        # Save data from the hash table into the log file
        # NOTE: If the file is opened with Excel, you will get an error. 
        if ($null -ne $Path -and $Path -ne "") {
            #$Log | Set-Content -Path $Path -Append -Force
        }
        
        # Output to Console depending on the given EntryType
        switch ($EntryType)
        {
            'Verbose'       {
                Write-Verbose -Message $Message
                
                }
            'Information'   {Write-Output $Message}
            'Warning'       {Write-Warning -Message $Message}
            'Debug'         {Write-Debug -Message $Message}
            'Error'         {
                # Output Error information onto the console
                if ($null -ne $ErrorInfo) {
                    Write-Error -Message @"
                    `nScript Stack Trace: $(($ErrorInfo).ScriptStackTrace)
                    `nFully Qualified ErrorID: $($ErrorInfo.FullyQualifiedErrorId)
                    'nError FullName: $(($ErrorInfo).Exception.GetType().FullName)
                    `nError Message: $(($ErrorInfo).Exception.Message)
                    `nError Category: $(($ErrorInfo).CategoryInfo.Category)
                    `n$Message
"@
                } else {
                    # ErrorInfo wasn't provided, just output the provided message.
                    Write-Error -Message $Message
                } 
            }
        }
    }
}
function Send-APICall {
    [cmdletbinding()]
    param (
        [parameter(Mandatory, Position=0, ParameterSetName = 'FirstURL')]
        [parameter(Mandatory, Position=0, ParameterSetName = 'NextURL')]
        [string]$AccessToken,
        [parameter(Mandatory, Position=1, ParameterSetName = 'FirstURL')]
        [string]$Filter,
        [parameter(Mandatory, Position=1, ParameterSetName = 'NextURL')]
        [string]$NextURL
    )
    begin {

        $StatusCode = $null
        $RetryCount = 0
        $Response = $null

        if ($PSCmdlet.ParameterSetName -eq 'FirstURL') {
            $URI = "https://graph.microsoft.com/v1.0/$Filter"
        } elseif ($PSCmdlet.ParameterSetName -eq 'NextURL') {
            $URI = $NextURL
        }

        $Params = @{
            'method' = 'GET'
            'Uri' = $URI
            'contentType' = 'application/json'
            'Headers' = @{Authorization=("bearer {0}" -f $AccessToken)}
            'ErrorAction' = 'SilentlyContinue'
        }
    }

    process {
        do {
            Write-Log -EntryType Verbose -Message "Send-APICall: Attempting to send API call..."
            $Response = Invoke-WebRequest @Params -UseBasicParsing
            $StatusCode = $Response.StatusCode
            if ($StatusCode -ne $null -and $StatusCode -ne 200 -and $StatusCode -ne 403) {
                Write-Log -EntryType Verbose -Message "Send-APICall: API failed with StatusCode $StatusCode, trying again in 5 seconds..."
                $RetryCount += 1
                Start-Sleep -Seconds 5
            } 
            
        } until ($StatusCode -eq $null -or $StatusCode -eq 200 -or $StatusCode -eq 403 -or $RetryCount -gt 4)
    }

    end {
        if ($StatusCode -eq "200") {
            Write-Log -EntryType Verbose -Message "Send-APICall: Successfully sent API call to $URI"
            return ($response.Content | ConvertFrom-Json)
        } elseif ($StatusCode -eq "403") {
            Write-Log -EntryType Warning -Message "Send-APICall: Warning, you do not have permissions to send an API call to $URI"
            return $StatusCode
        } elseif ($SstatusCode -eq $null) {
            Write-Log -EntryType Warning -Message "Send-APICall: Warning, API returned null. This can happen during 400 responses, may not be anything."
            return $Null
        } else {
            Write-Log -EntryType Warning -Message "Send-APICall: Failed making the API Call to $URI 5 times. Last status code was $StatusCode"
            return $null
        }
    }
}
function Get-DirectoryForAttachments {
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false)]
        [string]$Path,

        [parameter(Mandatory)]
        [string]$DefaultPath
    )
    begin {
        $Location = $null
    }

    process {
        if ($PSBoundParameters.ContainsKey('Path')) {
            if (-not (Test-Path -Path $Path)) {
                $Location = $DefaultPath
            } else {
                $Location = $Path
            }
        }
        if ($null -eq $Location) {
            $Location = $DefaultPath
        }
    }
    end {
        return $Location
    }
}
function New-DirectoryForAttachments {
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false)]
        [string]$Path,

        [parameter(Mandatory)]
        [string]$DefaultPath
    )

    begin {
        $Success = $false
    }

    process {
        if ($PSBoundParameters.ContainsKey('Path')) {
            if (-not (Test-Path -Path $Path)) {
                Write-Log -Message "New-DirectoryForAttachments: Attempting to create directory $Path" -EntryType Verbose
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

                # Verify it exists
                if (Test-Path -Path $Path) {
                    Write-Log -EntryType Verbose -Message "New-DirectoryForAttachments: Successfully created directory $Path"
                    $Success = $true
                } else {
                    Write-Log -Message "New-DirectoryForAttachments: Failed creating directory $Path, resulting to $DefaultPath." -EntryType Verbose
                }
            } else {
                Write-Log -Message "New-DirectoryForAttachments: Directory $Path already exists!"
            }
        }
        # IF path wasn't provided or it failed creating the new custom path, try to create the default one.
        if (-not ($Success)) {
            if (-not (Test-Path -Path $DefaultPath)) {
                New-Item -Path $DefaultPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

                if (Test-Path -Path $DefaultPath) {
                    Write-Log -EntryType Verbose -Message "New-DirectoryForAttachments: Successfully created directory $DefaultPath"
                    $Success = $true
                }
            } else {
                Write-Log -Message "New-DirectoryForAttachments: Directory $DefaultPath already exists!"
            }
        }
    }
    end {
        return $Success
    }
}
function New-FileFromBytes {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]$Data,

        [parameter(Mandatory)]
        [string]$Path
    )

    process {
        # Iterate through the attachment data
        for ($i = 0; $i -lt $Data.Length; $i++) {

            # The array has the byte that in a string, we'll first need to store the data from the array in here
            $StringBytes = $null
            # StringBytes will be converted from Unicode and stored into this variable
            $Bytes = $null
            # Bytes will be converted from Base64 (which creates the file as files are usually just base64 binary)
            $FileFromBytes = $null

            # Finally, we'll export the FileFromBytes to the path of this variable
            $FileName = $null

            # Verify both Name & Bytes aren't null
            if ($null -ne $Data[$i].name -and $data[$i].name -ne "") {

                if ($null -ne $Data[$i].ContentBytes -and $data[$i].ContentBytes -ne "") {
                    $StringBytes = $Data[$i].contentBytes

                    # Remove the ending / of Path if that was provided
                    if ($Path[-1] -eq '/' -or $Path[-1] -eq '\') {
                        $Path = $Path.Substring(0,$Path.Length-1)
                    }

                    # Replace .gz with .zip
                    if ($Data[$i].name -like '*.gz') {
                        $FileName = $Path + "\" + $(($Data[$i].name).replace('.gz','.zip'))
                    } else {
                        $FileName = $Path + "\" + $($Data[$i].name)
                    }
                    
                    Write-Log -EntryType Verbose -Message "New-FileFromBytes: File Name: $FileName"
                }
            }
            if ($null -ne $FileName -and $FileName -ne "") {
                Write-Log -EntryType Verbose -Message "New-FileFromBytes: Attempting to Export file to $FileName..."
                
                #$Bytes = [System.Text.Encoding]::Unicode.GetBytes($StringBytes)
                $Bytes = [Convert]::FromBase64String($StringBytes)
                [IO.File]::WriteAllBytes($FileName, $Bytes)
            }

            if (Test-Path -Path $FileName) {
                Write-Log -EntryType Verbose -Message "New-FileFromBytes: Successfully exported file $FileName."
            } else {
                Write-Log -EntryType Warning -Message "New-FileFromBytes: Did not create file $FileName for some reason..."
            }
        }
    }
}

function Extract-Attachments {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [System.object[]]$Files
    )

    begin {
        $Extension = $null
        $SevenZIPExe = "C:\Program Files\7-Zip\7z.exe"
    }
    process {
        foreach($File in $Files) {
            # Get the file type
            $Extension = $File.Extension
            switch($Extension) {
                '.gz' {
                    <# Arguments are:
                        e = extract
                        $($File.FullName) = full path of the archive
                        -y = Accept the extracted file name
                        -o = Where should the file be extracted to
                        -i! = What file types do you want to include
                    #>
                    Start-Process -FilePath $SevenZIPExe -ArgumentList "e $($File.FullName) -y -o$($File.DirectoryName) -i!*.xml -i!*.txt -i!*.json" -NoNewWindow -RedirectStandardOutput $script:LOG_Path
                }
                '.zip' {
                    <# Arguments are:
                        e = extract
                        $($File.FullName) = full path of the archive
                        -y = Accept the extracted file name
                        -o = Where should the file be extracted to
                        -i! = What file types do you want to include
                    #>
                    Start-Process -FilePath $SevenZIPExe -ArgumentList "e $($File.FullName) -y -o$($File.DirectoryName) -i!*.xml -i!*.txt -i!*.json" -NoNewWindow -RedirectStandardOutput $script:LOG_Path
                }
                default {
                    Write-Log -EntryType Warning -Message "Extract-Attachments: Missing archive extension $Extension, may need to add it to function Extract-Attachments"
                }
            }
        }
    }
}

function Get-DMARCDataFromFile {
    [cmdletbinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [System.Object[]]$Files,
        
        [parameter(Mandatory, Position = 1)]
        [ValidateSet("Basic", "Advanced")]
        [string]$Analysis, 

        [parameter(Mandatory, Position = 2)]
        [ValidateSet("Pass", "Fail", "Both")]
        [string]$DisplayResults
    )

    begin {
        $Data = $null
        $Extension = $null
        $SPF = $null
        $DMARC = $null
        $DKIM = $null
        $SourceIP = $null
        $Domain = $null
        $HeaderFrom = $null
        $SPFAuthResult = $null
        $DKIMAuthResult = $null
        # Sample array entry = 'website.com', 'DMARC: PASS"
        $BasicAnalysis = "" | Select-Object SourceIP, Domain, DMARC, FileName
        # Sample Array Entry: 'website.com', 'SourceIP: 123.23.23.123', 'DMARC: FAIL', 
        # 'DKIM: FAIL, DKIM Auth Results: none', 'SPF: PASS, SPF Auth Results: pass', 'HeaderFrom: starkbros.com''
        $AdvAnalysis = "" | Select-Object Domain, SourceIP, DMARC, DKIM, SPF, HeaderFrom, FileName
        $DMARCData = @()
    }

    process {
        Write-Log -EntryType Verbose -Message "Get-DMARCDataFromFile: Using $Analysis Analysis."
        $Files = $ExtractedFiles
        foreach ($File in $Files) {
            $Data = $null
            $SPF = $null
            $DMARC = $null
            $DKIM = $null
            $SourceIP = $null
            $Domain = $null
            $HeaderFrom = $null
            $SPFAuthResult = $null
            $DKIMAuthResult = $null
            $Extension = $File.Extension

            $BasicAnalysis = "" | Select-Object SourceIP, Domain, DMARC, FileName
            $AdvAnalysis = "" | Select-Object Domain, SourceIP, DMARC, DKIM, SPF, HeaderFrom, FileName

            switch($Extension) {
                '.xml' {
                    $Data = Select-XML -Path $($File.FullName) -XPath '/feedback' -ErrorAction SilentlyContinue
                    
                    if ($null -ne $Data) {
                        # We may be given more than 1 record (not usually) but it happens.
                        $Records = $Data.Node.record
                        foreach ($Record in $Records) {

                            # These need to be reset after each iteration
                            $BasicAnalysis = "" | Select-Object SourceIP, Domain, DMARC, FileName
                            $AdvAnalysis = "" | Select-Object Domain, SourceIP, DMARC, DKIM, SPF, HeaderFrom, FileName

                            $FileName = $File.FullName
                            # Records used by both Basic & Advanced Analysis
                            $Domain = $Record.auth_results.spf.domain
                            $DKIM = $Record.row.policy_evaluated.dkim
                            $SPF = $Record.row.policy_evaluated.spf
                            $DMARC = if ($DKIM -eq 'pass' -or $SPF -eq 'pass') {
                                'PASS'
                            } else {
                                'FAIL'
                            }

                            # Advanced Detail
                            $SourceIP = $Record.row.source_ip
                            $HeaderFrom = $Record.identifiers.header_from
                            $SPFAuthResult = $Record.auth_results.spf.result
                            $DKIMAuthResult = $Record.auth_results.dkim.result
                        
                            if ($Analysis -eq 'Basic') {
                                $BasicAnalysis.SourceIP = $SourceIP
                                $BasicAnalysis.DMARC = $DMARC
                                $BasicAnalysis.Domain = $Domain
                                $BasicAnalysis.FileName = $FileName
                                
                            } else {
                                $AdvAnalysis.Domain = $Domain

                                $AdvAnalysis.SourceIP = $SourceIP
                                $AdvAnalysis.DKIM = "$DKIM, Auth Result: $DKIMAuthResult"
                                $AdvAnalysis.SPF = "$SPF, Auth Result: $SPFAuthResult"
                                $AdvAnalysis.dmarc = $DMARC
                                $AdvAnalysis.HeaderFrom = $HeaderFrom
                                $AdvAnalysis.FileName = $FileName
                            }

                            if ($Analysis -eq 'Basic') {
                                if ($null -ne $BasicAnalysis.DMARC) {

                                    if ($PSBoundParameters.ContainsValue('Pass') -and $BasicAnalysis.DMARC -eq 'PASS') {
                                        $DMARCData += $BasicAnalysis
                                    } elseif ($PSBoundParameters.ContainsValue('Fail') -and $BasicAnalysis.DMARC -eq 'FAIL') {
                                        $DMARCData += $BasicAnalysis
                                    } elseif ($PSBoundParameters.ContainsKey('Both')) {
                                        $DMARCData += $BasicAnalysis
                                    }
                                    
                                } else {
                                    Write-Log -EntryType Verbose -Message "Get-DMARCDataFromFile: File $File did not give the array any DMARC info."
                                }
                                
                            } else {
                                if ($null -ne $AdvAnalysis.DMARC) {
                                    if ($PSBoundParameters.ContainsValue('Pass') -and $AdvAnalysis.DMARC -eq 'PASS') {
                                        $DMARCData += $AdvAnalysis
                                    } elseif ($PSBoundParameters.ContainsValue('Fail') -and $AdvAnalysis.DMARC -eq 'FAIL') {
                                        $DMARCData += $AdvAnalysis
                                    } elseif ($PSBoundParameters.ContainsKey('Both')) {
                                        $DMARCData += $AdvAnalysis
                                    }
                                } else {
                                    Write-Log -EntryType Verbose -Message "Get-DMARCDataFromFile: File $File did not give the array any DMARC info."
                                }
                            }
                        }
                    } else {
                        Write-Log -EntryType Verbose -Message "Get-DMARCDataFromFile: File $File is empty."
                    }
                }
                default {
                    Write-Log -EntryType Warning -Message "Get-DMARCDataFromFile: Extension $Extension not yet supported."
                }
            }
        }
    }
    end {
        return $DMARCData
    }
}
function Get-UniqueValues {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [System.Object[]]$Data,

        [parameter(Mandatory)]
        [ValidateSet("Basic", "Advanced")]
        [string]$Analysis
    )

    begin {
        Write-Log -EntryType Verbose -Message "Get-UniqueValues: Selecting unique values from DMARC Data..."
    }
    end {
        if ($Analysis -eq 'Basic') {
            return ($Data | Sort-Object | Select-Object -Property SourceIP, Domain, DMARC, FileName | Sort-Object -Property SourceIP -Unique)
        } else {
            return ($Data | Sort-Object | Select-Object -Property Domain, SourceIP, DMARC, DKIM, SPF, HeaderFrom, FileName | Sort-Object -Property SourceIP -Unique)
        }
    }
}

function Format-DMARCData {
    [cmdletbinding()]
    param (
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position = 0)]
        [System.Object[]]$Data,

        [parameter(Mandatory,
            Position = 1)]
        [ValidateSet('Basic', 'Advanced')]
        [string]$Analysis,

        [parameter(Mandatory, 
            Position = 2)]
        [ValidateSet("Pass", "Fail", "Both")]
        [string]$DisplayResults
    )

    BEGIN {
        # Create an empty array
        $SortedData = New-Object System.Collections.ArrayList @()
    }

    PROCESS {
        # Grab the To, From, and Subject from said emails
        if ($Analysis -eq 'Basic') {
            if ($PSBoundParameters.ContainsValue('Fail')) {
                $SortedData = ($Data | Where-Object DMARC -eq 'FAIL' | Sort-Object -Property DMARC | Select-Object @{Name="IP"; Expression = {$_.SourceIP}}, Domain, @{Name="Dmarc Results"; Expression = {$_.DMARC}})
            } elseif ($PSBoundParameters.ContainsValue('Pass')) {
                $SortedData = ($Data | Where-Object DMARC -eq 'PASS' | Sort-Object -Property DMARC | Select-Object @{Name="IP"; Expression = {$_.SourceIP}}, Domain, @{Name="Dmarc Results"; Expression = {$_.DMARC}})
            } else {
                $SortedData = ($Data | Sort-Object -Property DMARC | Select-Object @{Name="IP"; Expression = {$_.SourceIP}}, Domain, @{Name="Dmarc Results"; Expression = {$_.DMARC}})
            }
            
        } else {
            if ($PSBoundParameters.ContainsValue('Fail')) {
                $SortedData = ($Data | Where-Object DMARC -eq 'FAIL' | Sort-Object -Property DMARC | Select-Object Domain, @{Name="IP"; Expression = {$_.SourceIP}}, @{Name="Dmarc Results"; Expression = {$_.DMARC}}, DKIM, SPF, @{Name="Header"; Expression = {$_.HeaderFrom}})
            } elseif ($PSBoundParameters.ContainsValue('Pass')) {
                $SortedData = ($Data | Where-Object DMARC -eq 'PASS' | Sort-Object -Property DMARC | Select-Object Domain, @{Name="IP"; Expression = {$_.SourceIP}}, @{Name="Dmarc Results"; Expression = {$_.DMARC}}, DKIM, SPF, @{Name="Header"; Expression = {$_.HeaderFrom}})
            } else {
                $SortedData = ($Data | Sort-Object -Property DMARC | Select-Object Domain, @{Name="IP"; Expression = {$_.SourceIP}}, @{Name="Dmarc Results"; Expression = {$_.DMARC}}, DKIM, SPF, @{Name="Header"; Expression = {$_.HeaderFrom}})
            }
        }
    }

    END {
        return $SortedData
    }
}

function Send-Email {
    [cmdletbinding()]
    param (
        [string]$From = "DMARC Report Analyzer <Server.Notifications@starkbros.com>",
        [string]$SMTPServer = "starkbros-com.mail.protection.outlook.com",
        [string]$Subject,
        [String]$Body,
        [System.Object[]]$Data,
        [string[]]$EmailAddresses,
        [parameter(Mandatory)]
        [string]$Analysis
    )
    
    BEGIN {
        $Body = $null  

        $IP = $null
        $Domain = $null
        $Results = $null
        $DKIM = $null
        $SPF = $null
        $Header = $null
    }

    PROCESS {
        if ($PSBoundParameters.ContainsValue('Basic')) {
            $body = @"
                <table style="table-layout:fixed; border-collapse: collapse; border: 1px solid #008080; width:60%">
                    <tbody>
                        <tr>
                            <th colspan="2" bgcolor="#175ddc" style="width:20%;padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">IP</th>
                            <th colspan="2" bgcolor="#175ddc" style="width:20%;padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">Domain</th>
                            <th colspan="2" bgcolor="#175ddc" style="width:20%;padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">DMARC Results</th>
                        </tr>
"@
            
            foreach ($Dat in $Data) {
                $IP = $Dat.IP
                $Domain = $Dat.Domain
                $Results = $Dat.'Dmarc results'

                $Body += "`n<tr>"
                # Add IP row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:20%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$IP</td>"
                # Add Domain Row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:20%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$Domain</td>"
                # Add DMARC Result Row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:20%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$Results</td>"

                $Body += "`n</tr>"
                # Reset
                $IP = $null
                $Domain = $null
                $Results = $null
            }

            # Once completed, add the last HTML lines
            $Body += "`n</tbody>"
            $Body += "`n</table>"
        } else {
            # Advanced analysis email
            #$SortedData = ( DKIM, SPF, @{Name="Header"; Expression = {$_.HeaderFrom}})
            $body = @"
                <table style="table-layout:fixed; border-collapse: collapse; border: 1px solid #008080; width:100%">
                    <tbody>
                        <tr>
                            <th colspan="2" bgcolor="#175ddc" style="width:15%; padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">IP</th>
                            <th colspan="2" bgcolor="#175ddc" style="width:15%; padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">Domain</th>
                            <th colspan="2" bgcolor="#175ddc" style="width:15%; padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">DMARC Results</th>
                            <th colspan="2" bgcolor="#175ddc" style="width:15%; padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">DKIM</th>
                            <th colspan="2" bgcolor="#175ddc" style="width:20%; padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">SPF</th>
                            <th colspan="2" bgcolor="#175ddc" style="width:20%; padding-left: 5px; color: #FFFFFF; font-size: medium; height: 30px;">Header</th>
                        </tr>
"@
            
            foreach ($Dat in $Data) {
                $IP = $Dat.IP
                $Domain = $Dat.Domain
                $Results = $Dat.'Dmarc results'
                $DKIM = $Dat.DKIM
                $SPF = $Dat.SPF
                $Header = $Dat.Header

                $Body += "`n<tr>"
                # Add IP row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:15%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$IP</td>"
                # Add Domain Row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:15%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$Domain</td>"
                # Add DMARC Result Row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:15%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$Results</td>"
                # Add DKIM Row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:15%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$DKIM</td>"
                # Add SPF Row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:20%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$SPF</td>"
                # Add Header Row
                $Body += "`n<td colspan=`"2`" style=`"border-bottom: 2px solid #8ebf42; width:20%; padding-bottom: 1px; font-size: small; height: 25px; text-align: center`">$Header</td>"
                
                $Body += "`n</tr>"

                # Reset
                $IP = $null
                $Domain = $null
                $Results = $null
                $DKIM = $null
                $SPF = $null
                $Header = $null
            }

            # Once completed, add the last HTML lines
            $Body += "`n</tbody>"
            $Body += "`n</table>"
        }
            
    }

    END {
        Send-MailMessage -To $EmailAddresses -From $From -Subject $Subject -BodyAsHtml -Body $Body -SmtpServer $SMTPServer
    }
}
function Send-Email2 {
    [cmdletbinding()]
    param (
        [string]$From = "DMARC Report Analyzer <Server.Notifications@starkbros.com>",
        [string]$SMTPServer = "starkbros-com.mail.protection.outlook.com",
        [string]$Subject,
        [String]$Body,
        [System.Object[]]$Data,
        [string[]]$EmailAddresses
    )
    
    BEGIN {
        if (-not $Body) {
            $Body = ""
        }
    }

    PROCESS {
        $Body += "<p>$($Data | ConvertTo-Html -Fragment)</p>"
    }

    END {
        Send-MailMessage -To $EmailAddresses -From $From -Subject $Subject -BodyAsHtml -Body $Body -SmtpServer $SMTPServer
    }
}
#endregion

#region Preconditions
# Check if 7Zip is installed
if ($null -eq (Get-Command -name '7z.exe' -ErrorAction SilentlyContinue) -and (-not (Test-Path -Path "C:\Program Files\7-Zip\7z.exe"))) {
    Write-Log -EntryType Warning "Main: You need 7-Zip installed to run this script, stopping."
    exit $exitcode_Missing7ZIP
}
#endregion
#region Connect to Azure Application
try {
    Write-Log -Message "Main: Attempting to import Module AZ.Accounts..." -EntryType Verbose
    if (Test-Path -Path "C:\Program Files\WindowsPowerShell\Modules\Az.Accounts") {
        Import-Module 'C:\Program Files\WindowsPowerShell\Modules\Az.Accounts' -ErrorAction SilentlyContinue
    } else {
        Import-AZ -Module 'AZ.Accounts' -ErrorAction Stop
    }
} catch {
    Write-Log -Message "Main: Failed to Import Module Az.Accounts" -EntryType Error -ErrorInfo $_
    exit $exitCode_MissingPowerShellModuleAZ
}
# Get Tenant Id
if ($null -eq $TenantId) {
    Write-Log -EntryType Verbose -Message "Main: A tenantID wasn't provided. Let's try to retrieve it from Azure."
    try {
        $TenantId = (Get-AzSubscription -ErrorAction Stop | Where-Object Name -Match 'StarkBros').TenantId
        if ($null -eq $TenantId) {
            Write-Log -Message "Main: Failed to retrieve TenantId, you may need to run the commant Connect-AzAccount and run (Get-AzSubscription -ErrorAction Stop | Where-Object Name -Match 'StarkBros').TenantId again." -EntryType Error
            exit $exitcode_FailedGettingTenantIDFromAzureSubscription
        }
    } catch {
        Write-Log -Message "Main: Failed to get TenantIT." -EntryType Error -ErrorInfo $_
        exit $exitcode_FailedGettingTenantIDFromAzureSubscription
    }
}

# Get Application Id
if ($null -eq $AppId) {
    if ($null -ne $AppName -and $AppName -ne "") {
        Write-Log -EntryType Verbose -Message "Main: An AppdID wasn't given but an AppName was. Let's see if we can find the AppID from Azure with the provided AppName $AppName."
        $AppId = (Get-AzADApplication -DisplayNameStartWith $AppName).AppId
        if ($null -eq $AppId) {
            Write-Log -Message "Main: Failed to get Application ID in Azure using AppName $AppName." -EntryType Error
            exit $exitcode_FailedGettingAppIDWithAppNameFromAzure
        }
    } else {
        Write-Log -Message "Main: An AppName is required if an AppId wasn't provided." -EntryType Error
        exit $exitcode_FailedGivingAppNameOrAppID
    }
}

# Get certificate for authentication with Application
if ($null -eq $Cert) {
    try {
        Write-Log -Message "Main: Attempting to retrieve certificate with subject: $CertSubject..." -EntryType Verbose
        $Cert = Get-Cert -CertPath $CertPath -CertSubject $CertSubject -ErrorAction Stop
    } catch {
        Write-Log -Message "Main: Failed to retrieve Certificate at path $CertPath with Subject $CertSubject" -EntryType Error -ErrorInfo $_
        exit $exitcode_FailedGettingCertificateFromStore
    }
}

# Get Certificate Thumbprint
try {
    Write-Log -Message "Main: Retrieving certificate thumbprint from certificate..." -EntryType Verbose
    if ($null -eq $Cert) {
        $Thumbprint = Get-CertThumbPrint -CertPath $CertPath -Subject $CertSubject -ErrorAction Stop
    } else {
        $Thumbprint = Get-CertThumbPrint -Cert $Cert -ErrorAction Stop
    }
} catch {
    Write-Log -Message "Main: Failed to retrieve certificate thumbprint." -EntryType Error -ErrorInfo $_
    exit $exitcode_FailedGettingThumbprintFromCertificate
}

try {
    Write-Log -Message "Main: Attempting to connect to Azure with our Application's credentials..." -EntryType Verbose
    # Connect using the application's credentials
    Connect-AzAccount -ServicePrincipal `
    -CertificateThumbprint $Thumbprint `
    -ApplicationId $AppId `
    -TenantId $TenantId -ErrorAction Stop | Out-Null
} catch {
    Write-Log -Message "Main: Failed to connect to application in Azure." -EntryType Error -ErrorInfo $_
    exit $exitcode_FailedConnectingToAzure
}

if ($null -eq $JWT) {
    Write-Log -Message "Main: Creating a JWT Token..." -EntryType Verbose
    # Create a Json Web Token using the certificate on this machine
    try {
        $JWT = New-JWToken -Cert $Cert -AppId $AppId -TenantId $TenantId -Guid (New-Guid).Guid -ErrorAction Stop
    } catch {
        Write-Log -Message "Main: Failed creating JWT with Cert: $Cert, AppID: $AppId, and TenantID: $TenantID." -EntryType Error -ErrorInfo $_
        exit $exitcode_FailedCreatingJWTToken
    }
    
}

# Get an Access Token with the provided TenantId, AppId, and JWT. (Save the token if not done so already)
try {
    Write-Log -Message "Main: Attempting to retrieve access token..." -EntryType Verbose
    $AccessToken = Get-AccessToken -TenantId $TenantId -ClientId $AppId -ClientAssertion $JWT -ErrorAction Stop

    if ($null -eq $AccessToken -or $AccessToken -eq "") {
        Write-Log -Message "Main: AccessToken is null or empty, stopping." -EntryType Error -ErrorInfo ""
        exit $exitcode_FailedGettingAccessTokenFromAzure
    }
} catch {
    Write-Log -Message "Main: Failed to retrieve access token because" -EntryType Error -ErrorInfo $_
    exit $exitcode_FailedGettingAccessTokenFromAzure
}
#endregion

# Iterate through each DMARC Email
foreach ($Email in $DmarcEmails) {
    
    Write-Log -EntryType Verbose -Message "`nMain: Starting iteration on email $Email..."
    Start-Sleep -Seconds 5
    # Array to hold the parameters for the first search filter
    $Filter = @{}
    # The search filter for the initiating API Call to the $Email inbox.
    $SearchFilterForEmailsWithAttachments = $null
    # This will be set to true if we're done making API Calls
    $WeDone = $false
    # API Call Results
    $APICallResults = $null

    # This variable will hold the URL for the next page
    $NextPageURL = $null
    # The number of API pages we've queried
    $Pages = 1
    # The API Call that uses $SearchFilterForEmailsWithAttachments will store its results in this variable. If successful, it should store EmailIDs that match the search filter.
    $EmailIDs = @()
    # This will be an array to hold all attachment file names and their corresponding bytes
    $AllAttachmentData = $null
    # this search filter is used to grab the attachment data from an email (which uses the EmailID grabbed from earlier as you have to go through emails one-by-one).
    $SearchFilterForAttachments = $null
    # Attachments holds the API Response from the above Search filter. It should hold the necesssary attachment data.
    $Attachments = $null
    # Iterating through the above attachments, we'll need an array to store the necessary info for the attachment in said email. This will later be stored in the AllAttachmentData array.
    $AttachmentData = $null
    # This search filter is in case the original API Call stored in attachments does not have the BYTES immediately within said API Call. Essentially, there's a 'dig deeper' api call we can use to get said bytes.
    $SearchFilterForAttachmentData = $null
    # Similar to AttachmentData, this just holds the necessary attachment info for the 'dig deeper' api call. If this is used, it'll be stored on the AttachmentData array like the other.
    $AttachmentDataDigging = $null
    # This variable will hold the boolean that determines if we successfully created our directory to store our archives. 
    $CreatedDirectory = $null
    # This variable stores the path of the created directory for our attachments as we'll need to gather our attachments later.
    $GetAttachmentLocation = $null
    # This variable is used to hold the locations of our attachments that reside in our GetAttachmentLocation. These will be the files marked for extraction as they will be archive files.
    $ExtractTheseAttachments = $null
    # This variable will hold the location of our extracted files. As we just extracted $ExtractTheseAttachments, we'll need to store the extracted files into a variable to interpret later.
    $ExtractedFiles = $null
    # Upon reading the extracted files, we'll need a variable to hold the queried data from our extracted files. Specifically, DMARC data.
    $DMARCData = $null
    # There's going to be a lot of duplicate entries in DMARCData, so this variable will hold only the unique values.
    $UniqueEntries = $null
    # This variable will hold our DMARCData but in a pretty format.
    $FormatData = $null

    #region Get Attachment Data
    # Build the first search filter to make the initial API call
    Write-Log -Message "Main: Generating search filter..." -EntryType Verbose
    if ($days -gt 0) {
        $Filter.Add('days', $Days)
    } else {
        $Filter.Add('days', 0)
    }
    if ($Hours -gt 0) {
        $Filter.Add('hours', $Hours)
    } else {
        $Filter.Add('hours', 0)
    }
    $Filter.Add('Email', $Email)

    if ($days -eq 0 -and $hours -eq 0) {
        Write-Log -Message "Main: You must give an hour amount or day amount. Otherwise, leave it blank and we'll use the defauls." -EntryType Warning
        exit $exitcode_FailedProvidingHoursOrDays
    }
    # The search filter for the initial API Call
    $SearchFilterForEmailsWithAttachments = Get-FilterStringForAttachments @Filter

    do {
        $APICallResults = $null
        # Make API Call to retrieve Emails with attachments
       
        if ($null -eq $NextPageURL) {
            Write-Log -Message "Main: Attempting to retrieve Email IDs of Emails that have Attachments using filter $SearchFilterForEmailsWithAttachments" -EntryType Verbose
            $APICallResults = Send-APICall -AccessToken $AccessToken -Filter $SearchFilterForEmailsWithAttachments
        } else {
            Write-Log -EntryType Verbose -Message "Main: Attempting to access page $Pages of API Call Results..."
            $APICallResults = Send-APICall -AccessToken $AccessToken -NextURL $NextPageURL
        }
        
        # Check the status code or if it's null
        # (Send-API will respond with 403 from the function if we're forbidden to do these calls)
        # (Send-API will result in null if it's failed more than 4 times)
        # Otherwise, the api was a success
        if ($APICallResults -eq 403) {
            $Results = $resultCode_ForbiddenReadingEmails
            $WeDone = $true
        } elseif ($null -eq $APICallResults) {
            $Results = $resultCode_OtherIssuesReadingEmails
            $WeDone = $true
        } else {
            $Results = 0
        }

        if ($Results -eq 0) {
            Write-Log -EntryType Verbose -Message "Main: Successfully made the API call, adding email IDs into array!"
            $EmailIDs += $APICallResults.value

            # Check if we have another page
            if ($APICallResults.'@odata.nextLink') {
                # Reset next page
                $NextPageURL = $null
                $Pages += 1
                Write-Log -EntryType Verbose -Message "Main: We have another page to go through. Current Page $Pages."
                # Retrieve the next page URL for next API Call
                $NextPageURL = $APICallResults.'@odata.nextLink'
                Start-Sleep -Seconds 1
            } else {
                # Finally finished!
                $WeDone = $true
            }
        }
    } until ($WeDone)

    # Results -eq 0 and a non-null EmailIDs implies we're good to keep going
    if ($Results -eq 0 -and $null -ne $EmailIDs) {

        # Create an array to hold the attachment data
        $AllAttachmentData = @()

        Write-Log -EntryType Verbose -Message "Main: We have email IDs!"

        # Iterate through each email
        #region Email Iteration
        foreach ($EmailID in $EmailIDs) {
            
            $SearchFilterForAttachments = $null
            $Attachments = $null

            # Objective of this loop is to get an array of Attachments
            Write-Log -EntryType Verbose -Message "Main: Creating search filter to retrieve attachments from an email..."
            $SearchFilterForAttachments = Get-FilterStringAttachmentIDs -Email $Email -ID $EmailID.ID
            
            Write-Log -EntryType Verbose -Message "Main: Sending API call to gather attachments from Email message..."
            $Attachments = Send-APICall -AccessToken $AccessToken -Filter $SearchFilterForAttachments
            if ($Attachments -eq 403) {
                $Results = $resultCode_ForbiddenGettingAttachmentsFromEmail
            } elseif ($null -eq $Attachments) {
                $Results = $resultCode_OtherIssuesReadingAttachmentsFromEmail
            } else {
                $Results = 0
            }
            
            # If results are 0 and Attachments aren't null, proceed
            if ($Results -eq 0 -and $null -ne $Attachments) {

                # Iterate through each attachment
                #region Attachment Iteration
                foreach ($Attachment in $Attachments) {
                    $AttachmentData = "" | Select-Object Name, ContentBytes
                    $AttachmentDataDigging = $null
                    $SearchFilterForAttachmentData = $null

                    # No need to dig deeper as we have the base64 encode (file data)
                    if ($null -ne $Attachment.contentBytes) {

                        Write-Log -EntryType Verbose -Message "Main: Found ContentBytes for this attachment, storing into array for later."
                        # We have the data, store in the AttachmentData array
                        $AttachmentData.Name = ($Attachment.name.replace(' ',''))
                        $AttachmentData.ContentBytes = $Attachment.ContentBytes

                        # Add the name and contextBytes (file data) to the array
                        $AllAttachmentData += $AttachmentData
                    } elseif ($null -ne $Attachment.value.contentbytes) {
                        Write-Log -EntryType Verbose -Message "Main: Found ContentBytes for this attachment, storing into array for later."
                        # We have the data, store in the AttachmentData array
                        $AttachmentData.Name = ($Attachment.value.name.replace(' ',''))
                        $AttachmentData.ContentBytes = $Attachment.value.ContentBytes

                        # Add the name and contextBytes (file data) to the array
                        $AllAttachmentData += $AttachmentData
                    } else {
                        # Need to dig deeper into grabbing the Bytes of the attachment
                        $SearchFilterForAttachmentData = Get-FilterStringAttachmentData -Email $Email -ID $EmailID.ID -AttachmentID $Attachment.Value.ID
                        $AttachmentDataDigging = Send-APICall -AccessToken $AccessToken -Filter $SearchFilterForAttachmentData

                        # Check the status code or if it's null
                        # (Send-API will respond with 403 from the function if we're forbidden to do these calls)
                        # (Send-API will result in null if it's failed more than 4 times)
                        # Otherwise, the api was a success
                        if ($AttachmentDataDigging -eq 403) {
                            $Results = $resultCode_ForbiddenGettingAttachmentsFromDeeperInspection
                        } elseif ($null -eq $AttachmentDataDigging) {
                            $Results = $resultCode_OtherIssuesGettingAttachmentsFromDeeperInspection
                        } else {
                            $Results = 0
                        }
                        if ($Results -eq 0 -and $null -ne $AttachmentDataDigging) {
                            if ($null -ne $Attachment.value.contentBytes) {

                                # We have the data, store in the AttachmentData array
                                Write-Log -EntryType Verbose -Message "Main: After digging deeper, we found data for this attachment."
                                $AttachmentData.Name = ($Attachment.value.name.replace(' ',''))
                                $AttachmentData.ContentBytes = $Attachment.value.ContentBytes
                                
                                # Add the name and contextBytes (file data) to the array
                                $AllAttachmentData += $AttachmentData
                            } else {
                                Write-Log -EntryType Verbose -Message "Main: Could not find ContentBytes for API Call $SearchFilterForAttachmentData or it could be a blank attachment."
                            }
                        }
                    }
                }
                #endregion
            } else {
                Write-Log -EntryType Warning -Message "Main: Somehow we found emails with attachments but no attachment IDs?"
                Write-Log -EntryType Verbose -Message "Main: Search Filter for above warning: $SearchFilterForAttachmentIDs"
                $Results = 2
            }
        }
        #endregion
    }
    #endregion

    #region Create Attachments from Attachment Data
    if ($AllAttachmentData) {
        Write-Log -EntryType Verbose -Message "Main: We have attachment data, time to convert it into actual files."

        # Create a dedicated directory for the attachments
        if ($PSBoundParameters.ContainsKey('AttachmentDirectory')) {
            $CreatedDirectory = New-DirectoryForAttachments -Path $AttachmentDirectory -DefaultPath $DEFAULT_ATTACHMENT_DIRECTORY       
        } else {
            $CreatedDirectory = New-DirectoryForAttachments -DefaultPath $DEFAULT_ATTACHMENT_DIRECTORY
        }

        if ($CreatedDirectory) {
            if ($PSBoundParameters.ContainsKey('AttachmentDirectory')) {
                $GetAttachmentLocation = Get-DirectoryForAttachments -Path $AttachmentDirectory -DefaultPath $DEFAULT_ATTACHMENT_DIRECTORY 
            } else {
                $GetAttachmentLocation = Get-DirectoryForAttachments -DefaultPath $DEFAULT_ATTACHMENT_DIRECTORY
            }
            Write-Log -EntryType Verbose -Message "Main: Now that we have a directory, begin creating the attachments and placing them in this directory"
            if ($null -ne $GetAttachmentLocation) {
                New-FileFromBytes -Data $AllAttachmentData -Path $GetAttachmentLocation
            } else {
                # No attachment directory somehow
                $Results = $resultCode_FailedGettingNewDirectoryForAttachments
            }

        } else {
            Write-Log -EntryType Warning -Message "Main: Failed creating new directory for attachments."
            $Results = $resultCode_FailedCreatingNewDirectory
        }
    } else {
        Write-Log -EntryType Verbose -Message "Main: We were able to get emails and attachments but no data? Might want to read the log at $script:LOG"
    }   
    #endregion

    #region Extract Attachments
    $ExtractTheseAttachments = Get-ChildItem -Path $GetAttachmentLocation -ErrorAction SilentlyContinue -Exclude "*.xml", "*.txt", "*.json"
    if ($null -ne $ExtractTheseAttachments) {
        Write-Log -EntryType Verbose -Message "Main: We have our attachments saved onto our computer, let's extract them."
        Extract-Attachments -Files $ExtractTheseAttachments
    } else {
        # Exported our attachments but can't find them...
        $Results = $resultCode_ExtractedAttachmentsButCantFindThem
    }
    #endregion

    #region Read Attachments
    Start-Sleep -Seconds 5
    if (Test-Path -Path $GetAttachmentLocation) {
        Write-Log -EntryType Verbose "Path $GetAttachmentLocation exists!"
    } else {
        Write-Log -EntryType Warning "Path $GetAttachmentLocation does NOT exist!"
    }
    $ExtractedFiles = Get-ChildItem -Path $GetAttachmentLocation -Include "*.json", "*.xml", "*.txt" -Recurse -ErrorAction SilentlyContinue
    if ($null -ne $ExtractedFiles) {
        Write-Log -EntryType Verbose -Message "Main: Begin gathering DMARC Data from the extracted files..."
        $DMARCData = Get-DMARCDataFromFile -Files $ExtractedFiles -Analysis $Analysis -DisplayResults $DisplayResults
    } else {
        # Read our files but returned zero data
        Write-Log -EntryType Warning -Message "Main: We extracted files but we couldn't find them at Path $GetAttachmentLocation"
        $Results = $resultCode_ReadingExtractedFilesGaveZeroData
    }
    #endregion

    #region Filter Unique Entries
    if ($DMARCData.Count -gt 0) {
        Write-Log -EntryType Verbose -Message "Main: Begin Filtering DMARC Data for unique entries..."
        $uniqueEntries = Get-UniqueValues -Data $DMARCData -Analysis $Analysis
    }
    #endregion


    #region Fortmat Data 
    if ($UniqueEntries.Count -gt 0) {
        Write-Log -EntryType Verbose -Message "Main: Begin Formatting DMARC Data..."
        $FormatData = Format-DMARCData -Data $UniqueEntries -Analysis $Analysis -DisplayResults $DisplayResults
    }
    #endregion

    #region Send Email
    if ($null -ne $FormatData) {
        Write-Log -EntryType Verbose -Message "Main: Sending off DMARC Data to $EmailAddresses..."
        try {
            # Send off the email with the sorted Emails
            Send-Email -EmailAddresses $EmailAddresses -Subject "DMARC Analysis Report for $Email" -Data $FormatData -Analysis $Analysis -ErrorAction Stop
        } catch {
            Write-Log -Message "Main: Failed sending Email of sorted Dmarc Reports." -EntryType Error -ErrorInfo $_
            $Results = $resultCode_FailedSendingEmail
        }
    } else {
        Write-Log -EntryType Verbose -Message "Main: Sending an email with empty data would be dumb, skipping."
    }
    #endregion

    #region Cleanup DMARC files
    if (Test-Path -Path $GetAttachmentLocation) {
        if ($KeepFailFiles) {
            $FilesToKeep = $UniqueEntries | Where-Object DMARC -eq 'FAIL' | Select-Object -ExpandProperty FileName -Unique
            Write-Log -EntryType Verbose -Message "Main: Cleaning up passing DMARC Files.."
            Get-ChildItem -Path $GetAttachmentLocation -Recurse | Where-Object {$FilesToKeep -notcontains $_.FullName} | Remove-Item -Force
        }
        Write-Log -EntryType Verbose -Message "Main: Cleaning up DMARC Attachment Files.."
        Remove-Item -Path $GetAttachmentLocation -Recurse -Force
    }
    Start-Sleep -Seconds 5
    #endregion
}

#region Disconnect from Azure
Write-Log -EntryType Verbose -Message "Main: Disconnecting from Azure.."
Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
#endregion
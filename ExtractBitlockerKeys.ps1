# File name          : ExtractBitLockerKeys.ps1
# Author             : Podalirius (@podalirius_)
# Date created       : 21 September 2023

Param (
    [parameter(Mandatory=$true)][string]$dcip = $null,
    [parameter(Mandatory=$false,ParameterSetName="Credentials")][System.Management.Automation.PSCredential]$Credentials,
    [parameter(Mandatory=$false,ParameterSetName="Credentials")][Switch]$UseCredentials,
    [parameter(Mandatory=$false)][string]$LogFile = $null,
    [parameter(Mandatory=$false)][switch]$Quiet,
    [parameter(Mandatory=$false)][string]$ExportToCSV = $null,
    [parameter(Mandatory=$false)][string]$ExportToJSON = $null,
    [parameter(Mandatory=$false)][int]$PageSize = 5000,
    [parameter(Mandatory=$false)][string]$SearchBase = $null,
    [parameter(Mandatory=$false)][switch]$LDAPS,
    [parameter(Mandatory=$false)][switch]$Help
)

If ($Help) {
    Write-Host "[+]========================================================"
    Write-Host "[+] Powershell ExtractBitLockerKeys v1.3     @podalirius_  "
    Write-Host "[+]========================================================"
    Write-Host ""

    Write-Host "Required arguments:"
    Write-Host "  -dcip             : LDAP host to target, most likely the domain controller."
    Write-Host ""
    Write-Host "Optional arguments:"
    Write-Host "  -Help             : Displays this help message"
    Write-Host "  -Quiet            : Do not print keys, only export them."
    Write-Host "  -UseCredentials   : Flag for asking for credentials to authentication"
    Write-Host "  -Credentials      : Providing PSCredentialObject for authentication"
    Write-Host "  -PageSize         : Sets the LDAP page size to use in queries (default: 5000)."
    Write-Host "  -LDAPS            : Use LDAPS instead of LDAP."
    Write-Host "  -LogFile          : Log file to save output to."
    Write-Host "  -ExportToCSV      : Export Bitlocker Keys in a CSV file."
    Write-Host "  -ExportToJSON     : Export Bitlocker Keys in a JSON file."
    exit 0
}

If ($LogFile.Length -ne 0) {
    # Init log file
    $Stream = [System.IO.StreamWriter]::new($LogFile)
    $Stream.Close()
}

if($UseCredentials -and ([string]::IsNullOrEmpty($Credentials))){
    $Credentials = Get-Credential
}



Function Write-Logger {
    [CmdletBinding()]
    [OutputType([Nullable])]
    Param
    (
        [Parameter(Mandatory=$true)] $Logfile,
        [Parameter(Mandatory=$true)] $Message
    )
    Begin
    {
        Write-Host $Message
        If ($LogFile.Length -ne 0) {
            $Stream = [System.IO.StreamWriter]::new($LogFile, $true)
            $Stream.WriteLine($Message)
            $Stream.Close()
        }
    }
}

Function Get-ComputerNameFromLDAPDN {
    [CmdletBinding()]
    [OutputType([Nullable])]
    param ([string]$ldapDN)

    Begin
    {
        $ldapDNParts = $ldapDN -split ','
        if ($ldapDNParts[1] -match '^CN=([^,]+)$') {
            return $matches[1]
        } else {
             return ""
        }
    }
}

Function Get-DomainFromLDAPDN {
    [CmdletBinding()]
    [OutputType([Nullable])]
    param ([string]$ldapDN)

    Begin
    {
        $domain = ""

        [System.Collections.ArrayList]$ldapDNParts = @();
        foreach ($part in ($ldapDN -split ',')) { $ldapDNParts.Add($part) | Out-Null }
        $ldapDNParts.Reverse() | Out-Null

        foreach ($part in $ldapDNParts) {
            if ($part -match '^DC=([^,]+)$') {
                $domain = $matches[1] + "." + $domain
            } else {
                # Check if the domain ends with a period
                if ($domain.EndsWith('.')) {
                    # Remove the trailing period
                    $domain = $domain.TrimEnd('.')
                }

                return $domain
            }
        }
        return $domain
    }
}


Function Get-VolumeGuidFromLDAPDN {
    [CmdletBinding()]
    [OutputType([Nullable])]
    param ([string]$ldapDN)

    Begin
    {
        $ldapDNParts = $ldapDN -split '/'
        $ldapDNParts = $ldapDNParts[3] -split ','
        if ($ldapDNParts[0] -match '^CN=([^,]+){([^,]+)}$') {
            return $matches[2]
        } else {
             return ""
        }
    }
}


Function Get-CreatedAtFromLDAPDN {
    [CmdletBinding()]
    [OutputType([Nullable])]
    param ([string]$ldapDN)

    Begin
    {
        $ldapDNParts = $ldapDN -split '/'
        $ldapDNParts = $ldapDNParts[3] -split ','
        if ($ldapDNParts[0] -match '^CN=([^,]+)$') {
            $createdAt = ($matches[1] -split '{')
            return $createdAt[0]
        } else {
             return ""
        }
    }
}


Function Invoke-LDAPQuery {
    [CmdletBinding()]
    [OutputType([Nullable])]
    Param
    (
        [Parameter(Mandatory=$true)] $connectionString,
        [parameter(Mandatory=$false,ParameterSetName="Credentials")][System.Management.Automation.PSCredential] $Credentials,
        [Parameter(Mandatory=$false)] $PageSize
    )
    Begin
    {
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("{0}/RootDSE" -f $connectionString);
        $defaultNamingContext = $rootDSE.Properties["defaultNamingContext"].ToString();
        Write-Logger -Logfile $Logfile -Message "[+] Authentication successful!";
        Write-Logger -Logfile $Logfile -Message "[+] Targeting defaultNamingContext: $defaultNamingContext";
        $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
        if ($Credentials.UserName) {
            # Connect to Domain with credentials
            Write-Logger -Logfile $Logfile -Message ("[+] Connecting to {0}/{1} with specified account" -f $connectionString, $defaultNamingContext)
            $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext), $Credentials.UserName, $($Credentials.Password | ConvertFrom-Securestring -AsPlaintext))
        } else {
            # Connect to Domain with current session
            Write-Logger -Logfile $Logfile -Message ("[+] Connecting to {0}/{1} using current session" -f $connectionString, $defaultNamingContext)
            $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext))
        }
        $ldapSearcher.SearchScope = "Subtree"
        if ($PageSize) {
            $ldapSearcher.PageSize = $PageSize
        } else {
            Write-Logger -Logfile $Logfile -Message "[+] Setting PageSize to $PageSize";
            $ldapSearcher.PageSize = 5000
        }

        Write-Logger -Logfile $Logfile -Message "[+] Extracting BitLocker recovery keys ...";
        $ldapSearcher.Filter = "(objectClass=msFVE-RecoveryInformation)"
        $ldapSearcher.PropertiesToLoad.Add("msFVE-KeyPackage") | Out-Null ;  # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-keypackage
        $ldapSearcher.PropertiesToLoad.Add("msFVE-RecoveryGuid") | Out-Null ;  # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-recoveryguid
        $ldapSearcher.PropertiesToLoad.Add("msFVE-RecoveryPassword") | Out-Null ;  # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-recoverypassword
        $ldapSearcher.PropertiesToLoad.Add("msFVE-VolumeGuid") | Out-Null ;  # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-volumeguid
        $results = [ordered]@{};
        Foreach ($item in $ldapSearcher.FindAll()) {
            if (!($results.Keys -contains $item.Path)) {
                $results[$item.Path] = $item.Properties;
            } else {
                Write-Logger -Logfile $Logfile -Message "[debug] key already exists: $key (this shouldn't be possible)"
            }
        }

        $bitlocker_keys = Foreach ($distinguishedName in $results.Keys) {
            Foreach ($recoveryKey in $results[$distinguishedName]["msFVE-RecoveryPassword"]) {
                $domainName = (Get-DomainFromLDAPDN $distinguishedName)
                $createdAt = (Get-CreatedAtFromLDAPDN $distinguishedName)
                $volumeGuid = (Get-VolumeGuidFromLDAPDN $distinguishedName)
                $computerName = (Get-ComputerNameFromLDAPDN $distinguishedName)
                [PSCustomObject]@{
                    domainName = $domainName
                    computerName = $computerName
                    recoveryKey = $recoveryKey
                    volumeGuid = $volumeGuid
                    createdAt = $createdAt
                    distinguishedName = $distinguishedName
                }
            }
        }
        return $bitlocker_keys
    }
}

#===============================================================================

Write-Logger -Logfile $Logfile -Message  "[+]========================================================"
Write-Logger -Logfile $Logfile -Message  "[+] Powershell ExtractBitLockerKeys v1.3     @podalirius_  "
Write-Logger -Logfile $Logfile -Message  "[+]========================================================"
Write-Logger -Logfile $Logfile -Message  ""

# Handle LDAPS connection
$connectionString = "LDAP://{0}:{1}";
If ($LDAPS) {
    $connectionString = ($connectionString -f $dcip, "636");
} else {
    $connectionString = ($connectionString -f $dcip, "389");
}
Write-Verbose "Using connectionString: $connectionString"

# Connect to LDAP
try {
    $bitlocker_keys = Invoke-LDAPQuery -connectionString $connectionString -Credentials $Credentials -PageSize $PageSize

    If (!($Quiet)) {
        Foreach ($entry in $bitlocker_keys) {
            $domainName = $entry.domainName.PadRight(20," ")
            $computerName = $entry.computerName.PadRight(20," ")
            $recoveryKey = $entry.recoveryKey.PadRight(20," ")
            $createdAt = $entry.createdAt
            Write-Logger -Logfile $Logfile -Message ("| {0} | {1} | {2} | {3} " -f $domainName, $computerName, $recoveryKey, $createdAt)
        }
    }
    Write-Logger -Logfile $Logfile -Message ("[>] Extracted {0} BitLocker recovery keys!" -f $bitlocker_keys.Length)
    If ($ExportToCSV) {
        Write-Logger -Logfile $Logfile -Message "[>] Exporting Bitlocker recovery keys in CSV in $ExportToCSV ..."
        $bitlocker_keys | Export-CSV -Path $ExportToCSV -NoTypeInformation
    }
    If ($ExportToJSON) {
        Write-Logger -Logfile $Logfile -Message "[>] Exporting Bitlocker recovery keys in JSON in $ExportToJSON ..."
        $bitlocker_keys | ConvertTo-Json -Depth 100 -Compress | Out-File -FilePath $ExportToJSON
    }

} catch {
    Write-Verbose $_.Exception
    Write-Logger -Logfile $Logfile -Message -Logfile $Logfile -Message ("[!] (0x{0:X8}) {1}" -f $_.Exception.HResult, $_.Exception.InnerException.Message)
    exit -1
}
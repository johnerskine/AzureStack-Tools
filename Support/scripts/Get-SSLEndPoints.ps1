<#
.SYNOPSIS
    Display certificate inventory for Public SSL EndPoints
.DESCRIPTION
    Probes SSL endpoints of an Azure Stack deployment to gather external certificate inventory. 
    It then displays certificate inventory for Public SSL EndPoints. 
    Endpoints not accessible will return blank information.
    User can optionally add ADFS, AppServices, SQLAdapter and MySQLAdapter.
    User can exclude certain endpoints also.
.EXAMPLE
    PS C:\> .\Get-SSLEndPoints.ps1 -FQDN "east.azurestack.contoso.com"
    Seeds public endpoints with east.azurestack.contoso.com and attempts gather certificate inventory from each endpoint
.EXAMPLE
    PS C:\> .\Get-SSLEndPoints.ps1 -FQDN "east.azurestack.contoso.com" -exclude adfs,graph,adminvault
    Seeds public endpoints with east.azurestack.contoso.com and attempts gather certificate inventory from each endpoint, except adfs, graph and adminvault.
.EXAMPLE
    PS C:\> .\Get-SSLEndPoints.ps1 -FQDN "east.azurestack.contoso.com" -UsePaaS -exclude AppServices
    Seeds public endpoints with east.azurestack.contoso.com and attempts gather certificate inventory from each endpoint includes PaaS endpoints except for AppServices.
.PARAMETER FQDN
    String. Specifies FQDN (region.domain.com) of the AzureStack deployment.
.PARAMETER UseADFS
    Switch. Add ADFS and Graph services to be scanned
.PARAMETER UsePaaS
    Switch. Add PaaS services to be scanned
.PARAMETER UseADFS
    Switch. Add ADFS and Graph services to be scanned
.PARAMETER exclude
    String Array. Specifies endpoints that should be skipped. 
    Valid (any/all) values 'adminportal','adminmanagement','queue','table','blob','adminvault','adfs','graph','mysqladapter','sqladapter','appservice' 
    Tenant facing services; portal, management and vault, cannot be excluded.  If these are not reachable the script will not error, but the output will be empty.
.PARAMETER PassThru
    Switch. Returns a custom object (PSCustomObject) that contains the test results.
.OUTPUTS
    PSCustomObject
.NOTES
    When checking wildcard endpoints, the script generates a random GUID to test against, this ensures uniqueness, the GUID is then replaced with 'certtest' so output to the screen is more tidy.
#>

param (
    [Parameter(Mandatory = $true, HelpMessage = "Provide the FQDN for azure stack environment e.g. regionname.domain.com")]
    [string]
    $FQDN,
    [Parameter(Mandatory = $false, HelpMessage = "Provide number of days (default 90) warning for expiring certificates.")]
    [int]
    $ExpiringInDays = 90,
    [Parameter(Mandatory = $false, HelpMessage = "Include ADFS and Graph services")]
    [switch]
    $UseADFS,
    [Parameter(Mandatory = $false, HelpMessage = "Include PaaS services")]
    [switch]
    $UsePaaS,
    [Parameter(Mandatory = $false, HelpMessage = "Optionally remove services")]
    [ValidateSet('adminportal', 'adminmanagement', 'queue', 'table', 'blob', 'adminvault', 'adfs', 'graph', 'mysqladapter', 'sqladapter', 'appservice')]
    [string[]]
    $exclude,
    [Parameter(Mandatory = $false, HelpMessage = "Return PSObject")]
    [switch]
    $PassThru
)

# endpoint data
$allendPoints = @( 
    "portal.$FQDN"
    "adminportal.$FQDN"
    "management.$FQDN"
    "adminmanagement.$FQDN"
    "$(new-guid).queue.$FQDN"
    "$(new-guid).table.$FQDN"
    "$(new-guid).blob.$FQDN"
    "$(new-guid).vault.$FQDN"
    "$(new-guid).adminvault.$FQDN"
)

if ($UseADFS) {
    $allendPoints += @( 
        "adfs.$FQDN"
        "graph.$FQDN"
    )
}

if ($UsePaaS) {
    $allendPoints += @( 
        "mysqladapter.dbadapter.$FQDN"
        "sqladapter.dbadapter.$FQDN"
        "ftp.appservice.$FQDN"
        "sso.appservice.$FQDN"
        "$(new-guid).appservice.$FQDN"
        "$(new-guid).scm.appservice.$FQDN"
        "$(new-guid).sso.appservice.$FQDN"
        "api.appservice.$FQDN"
    )
}

# filter on exclude
if ($exclude) {
    $excludelist = $exclude -join '|'
    $endPoints = $allendPoints.Where( {$_ -notmatch $excludeList})
}
else {
    $endPoints = $allendPoints
}

$results = @()

foreach ($endPoint in $endPoints) {
    $result = New-Object -TypeName PSCustomObject @{
        Name       = $endPoint
        Thumbprint = $null
        Subject    = $null
        Expires    = $null
        Issuer     = $null
        Notes      = $null
        State      = $null
    }
    if (Resolve-DnsName -Name $endPoint -ErrorAction SilentlyContinue) {
        #try and retrieve certificate inventory from SSL endpoint
        $SSLEndPoint = "https://{0}" -f $endPoint
        try {
            $null = Invoke-WebRequest $SSLEndPoint -TimeoutSec 3 -ErrorAction SilentlyContinue
        }
        catch {
            $null
        }
        #create service connection point to the target SSL endpoint
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint($SSLEndPoint)

        # Cosmetic: change guid to testcert to ensure uniqueness in the call but tidy the screen output.
        $pattern = '(\{|\()?[A-Za-z0-9]{4}([A-Za-z0-9]{4}\-?){4}[A-Za-z0-9]{12}(\}|\()?'
        $endPoint = [regex]::replace($endPoint, $pattern, "testcert")
        $result.Name = $endPoint
        if ($servicePoint.Certificate) {
            $result.Thumbprint = $servicePoint.Certificate.GetCertHashString()
            $result.Expires = $servicePoint.Certificate.GetExpirationDateString()
            $result.Issuer = $servicePoint.Certificate.Issuer
            $result.Subject = $servicePoint.Certificate.Subject
            # calculate expiry days and check against threshold.
            $actualExpiryDays = ((Get-Date $result.Expires) - (Get-Date)).Days
            if ((Get-Date $result.Expires) -lt (Get-Date)) {
                $result.notes = "Renew Certificate. Certificate expired {0}" -f $result.Expires
                $result.State = "EXPIRED"
            }
            elseif ($actualExpiryDays -lt $ExpiringInDays) {
                $result.notes = "CONSIDER RENEWING: Certificate expires in {0} days" -f $actualExpiryDays
                $result.State = "EXPIRING"
            }
            else {
                $result.notes = "Certificate expires in {0} days" -f $actualExpiryDays
                $result.State = "OK"
            }
        }
        else {
            $result.notes = "Unable to connect to SSL endpoint {0}" -f $endPoint    
        }
    }
    else {
        $result.notes = "Cannot resolve name {0}" -f $endPoint
    }
    $results += $result
}

#Function to display colour-coded table
function Write-Table {
    param ([Parameter(ValueFromPipeline = $True)]
        $object,
        [int]$padright = 15
    )
    
    process {
        foreach ($obj in $object) {
            Write-Host "`n"
            foreach ($key in $obj.keys) {
                Write-Host ("{0}: " -f $key).PadRight($padright) -NoNewline
                Write-Host (": " -f $key) -NoNewline
                if ($obj.State -like 'EXPIRING') {
                    Write-Host ("   {0}" -f $obj.$key) -ForegroundColor Yellow
                }
                elseif ($obj.State -like 'EXPIRED') {
                    Write-Host ("   {0}" -f $obj.$key) -ForegroundColor Red
                }
                else {
                    Write-Host ("   {0}" -f $obj.$key) -foreground Green
                }
            }
        }
    }
}

# if the PSEdition is desktop and the user doesn't use passthru colour-code the output in a table
# otherwise just return the object
if ($PSEdition -eq 'Desktop' -AND -not $passThru) {
    $results | Write-Table -padright 15
}
else {
    $results | ForEach-Object { [pscustomobject] $_ }
}
# SIG # Begin signature block
# MIIdpwYJKoZIhvcNAQcCoIIdmDCCHZQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQb3/8boyCn8MMocitsGRLBUL
# ioWgghhTMIIEwTCCA6mgAwIBAgITMwAAANd4Xn6sPypBiwAAAAAA1zANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTcxMDAyMjI1NzU3
# WhcNMTkwMTAyMjI1NzU3WjCBsTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEMMAoGA1UECxMDQU9DMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo5
# NkZGLTRCQzUtQTdEQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0R8WghBzWrkgfD
# oLwDByma12IHhlSPBbAGiWXRc2ixEiXWFkoH5IDW4fNnINAgbfCWThv3zAknQDa3
# H9IkZcvHSKEPgt7/MpC2LzuYiBGS7osE1YFJru5o3eQ15jRt+//Sk8j4fwis41Aj
# CNiePkK8wCHusRFyEOABoMC2KjUwrAEQbsMCCcm9AYq3QXc7tvvDncJfnmSfK8KY
# 1isAuPJcfIOsh7ugzUoklOUbkByfrwc51oWxyRhZTMGyJcvskauQzpqw8QIPJi4U
# pv/cW8ylaXvDD5rd+J7hJzkWpl/eg21LssBR2TdIVfJs48u99rvgf+ka05hE2lSL
# nnd67RUCAwEAAaOCAQkwggEFMB0GA1UdDgQWBBTYj8Ia8/dzgo7zIAVoJi/V/PwV
# PTAfBgNVHSMEGDAWgBQjNPjZUkZwCu1A+3b7syuwwzWzDzBUBgNVHR8ETTBLMEmg
# R6BFhkNodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
# aWNyb3NvZnRUaW1lU3RhbXBQQ0EuY3JsMFgGCCsGAQUFBwEBBEwwSjBIBggrBgEF
# BQcwAoY8aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3Nv
# ZnRUaW1lU3RhbXBQQ0EuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3
# DQEBBQUAA4IBAQBtoYxTxcEg/Q/A+oGoitT3aME8OF7a1OAQqSPnV3OLGFLv3uPY
# X8nvdOTnhbKV6BIsW/DGukZflJjCo9I5D9+wz0s9hICPFEqvfpqZumy2T94K7veD
# 21BOZ59xfVauLrbWtBpISdd2kmGsaYacwd/Bf7ih4gmRKWdpGeLcYvN9d8fb68bt
# qwJLKb0B161HcM0SYJ9VxYkvDVqc8YtcH5CszKWLnR2lzBBXR8447n3RY/2ulRFW
# FD82SsbqpWVUo7JnVaphz9qR5Jn9iarO/SNmtmobYwDPwVpmq4ef2w6iypR3Nrn/
# PaDv6e7qm3mYnkYtM13zQXbBBQ6DgWferczAMIIGATCCA+mgAwIBAgITMwAAAMTp
# ifh6gVDp/wAAAAAAxDANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWdu
# aW5nIFBDQSAyMDExMB4XDTE3MDgxMTIwMjAyNFoXDTE4MDgxMTIwMjAyNFowdDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEeMBwGA1UEAxMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAiIq4JMMHj5qAeRX8JmD8cogs+vSjl4iWRrejy1+JLzozLh6RePp8qR+CAbV6
# yxq8A8pG68WZ9/sEHfKFCv8ibqHyZz3FJxjlKB/1BJRBY+zjuhWM7ROaNd44cFRv
# O+ytRQkwScG+jzCZDMt2yfdzlRZ30Yu7lMcIhSDtHqg18XHC4HQAS4rS3JHr1nj+
# jfqtYIg9vbkfrmKXv8WEsZCu1q8r01T7NdrNcZLmHv/scWvLfwh2dOAQUUjU8QDI
# SEyjBzXlWQ39fJzI5lrjhfXWmg8fjqbkhBfB1sqfHQHH/UinE5IzlyFIMvjCJKIA
# sr5TyoNuKVuB7zhugPO77BML6wIDAQABo4IBgDCCAXwwHwYDVR0lBBgwFgYKKwYB
# BAGCN0wIAQYIKwYBBQUHAwMwHQYDVR0OBBYEFMvWYoTPYDnq/2fCXNLIu6u3wxOY
# MFIGA1UdEQRLMEmkRzBFMQ0wCwYDVQQLEwRNT1BSMTQwMgYDVQQFEysyMzAwMTIr
# YzgwNGI1ZWEtNDliNC00MjM4LTgzNjItZDg1MWZhMjI1NGZjMB8GA1UdIwQYMBaA
# FEhuZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFf
# MjAxMS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEA
# BhYf21fCUMgjT6JReNft+P3NvdXA8fkbVu1TyGlHBdXEy+zi/JlblV8ROCjABUUT
# 4Jp5iLxmq9u76wJVI7c9I3hBba748QBalJmKHMwJldCaHEQwqaUWx7pHW/UrNIuf
# j1g3w04cryLKEM3YghCpNfCuIsiPJKaBi98nHORmHYk+Lv9XA03BboOgMuu0sy9Q
# Vl0GsRWMyB1jt3MM49Z6Jg8qlkWnMoM+lj5XSXcjif6xEMeK5QgVUcUrWjFbOWqW
# qKSIa5Yob/HEruq9RRfMYk6BtVQaR46YpW3AbifG+CcfyO0gqQux8c4LmpTiap1p
# g6E2120g/oXV/8O4lzYJ/j0UwZgUqcCGzO+CwatVJEMYtUiFeIbQ+dKdPxnZFInn
# jZ9oJIhoO6nHgE4m5wghTGP9nJMVTTO1VmBP10q5OI7/Lt2xX6RDa8l4z7G7a4+D
# bIdyquql+5/dGtY5/GTJbT4I5XyDsa28o7p7z5ZWpHpYyxJHYtIh7/w8xDEL9y8+
# ZKU3b2BQP7dEkE+gC4u+flj2x2eHYduemMTIjMtvR+HALpTtsfawMG3sakmo6ZZ2
# yL0IxP479a5zNwayVs8Z1Lv1lMqHHPKAagFPthuBc7PTWyI/OlgY34juZ8RJpy/c
# JYs9XtDsNESRHbyRDHaCPu/E2C2hBAKOSPnv3QLPA6IwggYHMIID76ADAgECAgph
# Fmg0AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20x
# GTAXBgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0
# MDMxMzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# ITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP
# 7tGn0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySH
# nfL0Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUo
# Ri4nrIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABK
# R2YRJylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSf
# rx54QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGn
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMP
# MAsGA1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQO
# rIJgQFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZ
# MBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJv
# b3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1Ud
# HwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYI
# KwYBBQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# cm9zb2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3
# DQEBBQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKi
# jG1iuFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV
# 3U+rkuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5
# nGctxVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tO
# i3/FNSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbM
# UVbonXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXj
# pKh0NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh
# 0EPpK+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLax
# aj2JoXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWw
# ymO0eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma
# 7kng9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TCCB3ow
# ggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkwOVoX
# DTI2MDcwODIxMDkwOVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBNNLry
# tlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJDXlk
# h36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv56sI
# UM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN1Vx5
# pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+sYxd
# 6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzluZH9T
# upwPrRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKuHCOn
# qWbsYR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8rAKC
# X9vAFbO9G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43sTUkw
# p6uO3+xbn6/83bBm4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/dygo
# 8e1twyiPLI9AN0/B4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCIF96e
# TvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIBADAd
# BgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAweCgBT
# AHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgw
# FoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0
# MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKG
# Qmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0
# MjAxMV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3LgMw
# gYMwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# ZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwA
# XwBwAG8AbABpAGMAeQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0B
# AQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw++MNy
# 0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS0LD9
# a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELukqQUM
# m+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q3fMO
# r5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgycSca
# f7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8VfUWn
# duVAKmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbRBrF1
# HxS+YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/QACnF
# sZulP0V3HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL/9az
# I2h15q/6/IvrC4DqaTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9BCrE/
# +6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xggS+MIIE
# ugIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgw
# JgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAAxOmJ
# +HqBUOn/AAAAAADEMAkGBSsOAwIaBQCggdIwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFD3hpe6Z5OS4xOyQ9UVGXaOFLQmIMHIGCisGAQQBgjcCAQwxZDBioEiARgBN
# AGkAYwByAG8AcwBvAGYAdAAgAEEAegB1AHIAZQBTAHQAYQBjAGsAIABQAGEAcgB0
# AG4AZQByAFQAbwBvAGwAawBpAHShFoAUaHR0cDovL0NvZGVTaWduSW5mbyAwDQYJ
# KoZIhvcNAQEBBQAEggEAKhTq2IPxvYM6bfB7PyAVTkHlrD09O+eUYXVxcr8ABrKQ
# XF2Ti4G6vz0mazN+uxwKchjtJOfhMdlO/+zOBolRkzLV2tpA3ofICceSSCyNGWzn
# m0rxoiqudrvneCAW9k8exKx3je0ASgVTK3OYFxbGRyR8Rpl6te/Lpr/HPDPiRXC1
# MDJ1QG3KSe6N/YcpAPz1yGYv5vUrFnQeREHjIRuh4pyvOuh2VldVHDCkkJcnGSr8
# Pp292VvMfEBoM744l6fDO2QQNRrZYhVjnkE8SebHVc99cZ5YYJz40YnBhbH9pO49
# KZIaj8dnv0nGM2aLcvJg4QkkvjD/FvPWwhLQWL7c7aGCAigwggIkBgkqhkiG9w0B
# CQYxggIVMIICEQIBATCBjjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0ECEzMAAADX
# eF5+rD8qQYsAAAAAANcwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE4MDYxMjAzMDE1MFowIwYJKoZIhvcNAQkE
# MRYEFGir1QhE25t2u1cly6XfYNFf4XswMA0GCSqGSIb3DQEBBQUABIIBAAw8V7iH
# uvsBImxMIpmK7z+gI+9pZzJEVlyiHS0t+qeOJ7cShOmxtMc5K7Nm74s8sE5lpOB2
# kDUgEqG3G++I4c6DAOpYA9C2f3ovaCaZvrW2GoaFy4rF7Zne+xyttSjKaB0k9qWx
# u9thbk6LXsAJLuf390MqnyoSjjnFMuPMhCzV3k8VK+/j8ENMlHwUIIullkv0aIh6
# JQVKfNtpTEfBtc2TTyTVFH3OpVcfte8LmL+vINtR3XV+lZZ2/jDj7z6MuxvhdCoI
# ugH9GmVillRvKTzd6SO7ubl/Wz5ew95s/gmvwNTSVBwPU+IX/GDFDgIBE/QcgQe5
# VjTKRxwxUUA/0kQ=
# SIG # End signature block

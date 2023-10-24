<#
.SYNOPSIS
This PowerShell script automates several administrative tasks to help you manage script execution policies and code-signing in PowerShell.

.DESCRIPTION
The script performs the following tasks:
1. Retrieves the current PowerShell execution policies for various scopes (Process, CurrentUser, LocalMachine).
2. Displays these policies to the user for review.
3. Prompts the user for permission to change these policies to 'RemoteSigned', if they are not already set to that.
4. Changes the execution policies to 'RemoteSigned' for each scope if the user gives consent.
5. Summarizes the changes made, if any.
6. Uses a file dialog to allow the user to select a PowerShell (.ps1) script file.
7. Creates a self-signed certificate, if necessary.
8. Signs the selected PowerShell script with the self-signed certificate.

.PARAMETERS
None

.INPUTS
User interaction is needed to proceed with changing execution policies and to select a PowerShell script for signing.

.OUTPUTS
Console output will show the status of execution policies, certificate creation, and script signing.

.EXAMPLE
To run this script, simply navigate to its location in PowerShell and execute it.

.NOTES
Make sure to run this script with administrative privileges for full functionality.
#>


# Function to get current execution policies
# Function to get current execution policies
function Get-CurrentExecutionPolicies {
    $scopes = @("Process", "CurrentUser", "LocalMachine")
    $policies = @{}
    foreach ($scope in $scopes) {
        $currentPolicy = Get-ExecutionPolicy -Scope $scope
        $policies[$scope] = $currentPolicy
    }
    return $policies
}

# Function to display summary of execution policies
function Show-ExecutionPolicySummary {
    param (
        [hashtable]$currentPolicies,
        [string]$message = "Summary of execution policies:"
    )
    Write-Host $message
    foreach ($scope in $currentPolicies.Keys) {
        Write-Host "$scope scope: $($currentPolicies[$scope])"
    }
}

# Function to set execution policy for a specific scope
function Set-ExecutionPolicyAtScope {
    param (
        [string]$scope
    )
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope $scope -Force
    $finalPolicy = Get-ExecutionPolicy -Scope $scope
    $script:updatedPolicies[$scope] = $finalPolicy
}

# Initialize the summary hashtables
$oldPolicies = Get-CurrentExecutionPolicies
$script:updatedPolicies = @{}

# Initial check and display of current policies
Show-ExecutionPolicySummary -currentPolicies $oldPolicies

# Main workflow
Write-Host "WARNING: Changing execution policy settings might expose you to the security risks of running unsigned scripts."
$userConsent = Read-Host "Type 'proceed' to check and possibly change execution policy settings at different scopes."
if ($userConsent -ne 'proceed') {
    Write-Host "User chose not to proceed. Exiting."
    exit 2
}

$scopes = @("Process", "CurrentUser", "LocalMachine")
foreach ($scope in $scopes) {
    Set-ExecutionPolicyAtScope -scope $scope
}

# Display the old and new policy summaries
Show-ExecutionPolicySummary -currentPolicies $updatedPolicies -message "Summary of updated execution policies:"
Show-ExecutionPolicySummary -currentPolicies $oldPolicies -message "Summary of previous execution policies:"

# Add necessary .NET assembly for GUI
Add-Type -AssemblyName System.Windows.Forms

# Function to create a self-signed code signing certificate
function Create-SelfSignedCert {
    $cert = New-SelfSignedCertificate -Type CodeSigning -Subject "CN=PowerShell Code Signing" -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(5)
    Write-Host "Created new Self-Signed Certificate with thumbprint: $($cert.Thumbprint)"
    
    $certDir = "C:\temp"
    $certPath = "$certDir\tempCert.cer"
    if (-Not (Test-Path $certDir)) {
        $null = New-Item -ItemType Directory -Path $certDir
    }

    try {
        $null = Export-Certificate -Cert $cert -FilePath $certPath
        $null = Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\Root
        $null = Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
        $null = Remove-Item -Path $certPath
    }
    catch {
        Write-Host "An error occurred: $_"
    }

    return $cert
}

# Function to sign a PowerShell script with a given certificate
function Sign-Script {
    param (
        [string]$scriptPath,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate
    )
    Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $certificate
    Write-Host "Successfully signed script: $scriptPath"
}

# Main Program Execution

# Create File Picker dialog
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1"

# Show File Picker dialog and get selected file
$OpenFileDialog.ShowDialog() | Out-Null
$scriptToSign = $OpenFileDialog.FileName

# Validate the script path
if (Test-Path -Path $scriptToSign -PathType Leaf) {
    # Create or get a self-signed certificate
    $cert = Create-SelfSignedCert

    # Sign the script with the self-signed certificate
    Sign-Script -scriptPath $scriptToSign -certificate $cert
} else {
    Write-Host "The specified path does not exist or is not a file. Please check the path and try again."
}

Read-Host -Prompt "Press Enter to exit"


# SIG # Begin signature block
# MIIFhQYJKoZIhvcNAQcCoIIFdjCCBXICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDpIcfhNZuBb4qlKQv6Gjv/QE
# u1egggMYMIIDFDCCAfygAwIBAgIQF6lGsytBPZtKoGPdSkj9zTANBgkqhkiG9w0B
# AQsFADAiMSAwHgYDVQQDDBdQb3dlclNoZWxsIENvZGUgU2lnbmluZzAeFw0yMzEw
# MjQxNjEyNTRaFw0yODEwMjQxNjIyNTRaMCIxIDAeBgNVBAMMF1Bvd2VyU2hlbGwg
# Q29kZSBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuiYQ
# t6YsXrwU4L3DTAsYxOenfO8hYbmPmagccGZ0vAbFS22A0KvajIYZIByskv9Yp6D9
# g685Q/RpJyFgbhStlFURwJYHS3gDNoLjw2UY7UBxVG3mb6CHqhOkfYYgYdgNSFPD
# XJWZXNUAURU0CihahqcBFzWkOrPulOeVNF+Jwyx7EMYCvAVysWZVMX8KKJRG9XcO
# /dZEKjU6bDUMBuhGzHhsQUEcqAri/Ferh4eimNN9Tqztqb7oePFroGIqPKB14BPu
# lcvUz8Kooof1VLIMBYWQBBs69DzvbhmeKKuySh7ICYodlLmuDv/NK/NaBWmd9MZQ
# 8HSWF8SE8mye2grv3QIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
# CgYIKwYBBQUHAwMwHQYDVR0OBBYEFOntZMXGafgIysCKpE5KT8KyqYuaMA0GCSqG
# SIb3DQEBCwUAA4IBAQCvEoeSKroe26aeLesd4NLOr+JroenuxPZ8/pSurnVuoTfI
# cmDoZ4Ux18RjaH5ew7/Lk4iEWPk4fZv5z4oTjOcmbdPfwHEhGUQuu2JpLvVeZU1N
# mdPn/1w2c9P4fyyDwcKiKpzNB9TIhcAnazOGCHbvXmdsnUvHM3YRMMa+Rzo0nX+0
# DEX/GP7SjlBoHnuuQnd6pZz+Ebav6IaKUwLspIo5yfJUNGsbu3EcIKli5F7ye/eM
# Kot14F+SFep4Ow7pdcl2HE4+GUiHc6CLMJSGud3GaIcHdUhu/hKqlIY556f/fCEB
# Ept6yPOi2HZKCcE6f7+DgaGF4+CuhFQnUaMix87lMYIB1zCCAdMCAQEwNjAiMSAw
# HgYDVQQDDBdQb3dlclNoZWxsIENvZGUgU2lnbmluZwIQF6lGsytBPZtKoGPdSkj9
# zTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAjBgkqhkiG9w0BCQQxFgQUQ0o8rc0keBcnViv2EURe/6XwmZMwDQYJKoZIhvcN
# AQEBBQAEggEATThRbbb6PDLCyppYN9XCp8ZkY/IZn92PYnhufghf3j0SlMUGmWMc
# ebOtQYzktVq/SW8JAiFwRzT2zT/sAVleZXEtbC193+4b2GhiX3fcaahd1zRE4xHU
# xiyux4u1qZsx38mabOhhFGWMGMIW/VEL8700zdhAwiUfbMvPwrikVv4S++h2PlyD
# fDbVbjtuqBAKTtifKKrS3CEO6YXC9zocuQ0PbEb8tt+DAqLc7I8LBpGeSpopgevc
# L3FcILo3hBA/xzkmVYN9oPhTHlB/iyfv6r/ycOLT9dji+PkcriEc2uT6Py1ji3RC
# O/pwWw3qJCIU/qN7+wnCxkJzjjWs1KYyTQ==
# SIG # End signature block

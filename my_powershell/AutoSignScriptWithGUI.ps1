<#
.SYNOPSIS
This PowerShell script automates several administrative tasks to help you manage script execution policies and code-signing in PowerShell. // TODO test

.DESCRIPTION
The script performs the following tasks:
1. Retrieves the current PowerShell execution policies for various scopes (Process, CurrentUser, LocalMachine).
2. Displays these policies to the user for review.
3. Prompts the user for permission to change these policies to 'AllSigned', if they are not already set to that.
4. Changes the execution policies to 'AllSigned' for each scope if the user gives consent.
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
    try {
        Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope $scope -Force -ErrorAction Stop
        $finalPolicy = Get-ExecutionPolicy -Scope $scope
        $script:updatedPolicies[$scope] = $finalPolicy
    }
    catch {
        Write-Host "Failed to set policy for ${scope}: $_"
    }
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

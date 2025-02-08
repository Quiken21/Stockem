# Function to check if the service's binary path is suspicious
function IsSuspiciousPath($path) {
    return ($path -like "C:\Users\*")
}

# Function to check if the service's binary is unsigned
function IsUnsigned($path) {
    try {
        # Remove any arguments (everything after the first space)
        $path = $path.Split(" ")[0]

        # Ensure the path is enclosed in quotes if it contains spaces
        if ($path -match " ") {
            $path = "`"$Path`""  # Add quotes around the path
        }

        # Check the signature of the file
        $Signatures = Get-AuthenticodeSignature -FilePath $path
        return ($Signatures.Status -ne "Valid")
    }
    catch {
        # If the file is not found, consider it unsigned
        Write-Host "File not found: $path"
        return $true
    }
}

# Function to calculate the entropy of a string
function CalculateEntropy($input) {
    if ($input -isnot [string]) {
        Write-Host "Input is not a string: $input"
        return 0  # Return a default entropy value
    }

    $inputChars = $input.ToCharArray()
    $charCount = $inputChars.Length
    $charFrequency = @{ }
    foreach ($char in $inputChars) {
        $charFrequency[$char]++
    }
    [double]$entropy = 0
    foreach ($frequency in $charFrequency.Values) {
        $probability = $frequency / $charCount
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    return $entropy
}

# Function to check if the service has a high entropy name
function IsHighEntropyName($name) {
    $entropy = CalculateEntropy($name)
    return ($entropy -gt 3.5)
}

# Function to check if the service has a suspicious file extension
function HasSuspiciousExtension($path) {
    $suspiciousExtensions = @('.vbs', '.js', '.bat', '.cmd', '.scr')
    $extension = [IO.Path]::GetExtension($path)
    return ($suspiciousExtensions -contains $extension)
}

# Get all services on the local machine
$AllServices = Get-CimInstance -ClassName Win32_Service

# Create an empty array to store detected suspicious services
$DetectedServices = New-Object System.Collections.ArrayList

# Iterate through all services
foreach ($Service in $AllServices) {
    $BinaryPathName = $Service.PathName.Trim('"')

    # Debugging: Check the path being checked
    Write-Host "Checking path: $BinaryPathName"
    $PathSuspicious = IsSuspiciousPath($BinaryPathName)
    Write-Host "Path suspicious: $PathSuspicious"

    $LocalSystemAccount = ($Service.StartName -eq "LocalSystem")
    $NoDescription = ([string]::IsNullOrEmpty($Service.Description))
    $Unsigned = IsUnsigned($BinaryPathName)

    $ShortName = $false
    $ShortDisplayName = $false
    $HighEntropyName = $false
    $HighEntropyDisplayName = $false
    $SuspiciousExtension = $false
    $extraChecks = $true  # For testing

    if ($extraChecks) {
        $ShortName = ($Service.Name.Length -le 5)
        $ShortDisplayName = ($Service.DisplayName.Length -le 5)
        $HighEntropyName = IsHighEntropyName($Service.Name)
        $HighEntropyDisplayName = IsHighEntropyName($Service.DisplayName)
        $SuspiciousExtension = HasSuspiciousExtension($BinaryPathName)
    }

    # If any of the suspicious characteristics are found, add the service to the list of detected services
    if ($PathSuspicious -or $LocalSystemAccount -or $NoDescription -or $Unsigned -or $ShortName -or $ShortDisplayName -or $HighEntropyName -or $HighEntropyDisplayName -or $SuspiciousExtension) {
        $DetectedServices.Add($Service) | Out-Null
    }
}

# Output the results
if ($DetectedServices.Count -gt 0) {
    Write-Host "Potentially Suspicious Services Detected"
    Write-Host "----------------------------------------"
    foreach ($Service in $DetectedServices) {
        Write-Host "Name: $($Service.Name) - Display Name: $($Service.DisplayName) - Status: $($Service.State) - StartName: $($Service.StartName) - Description: $($Service.Description) - Binary Path: $($Service.PathName.Trim('"'))"
    }
} else {
    Write-Host "No potentially suspicious services detected."
}

# Author: Dylan Harvey (modified from Joshua Wright's Original, see URL)
# Script for finding hidden services.
# https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services/

# Get the list of running processes
$processes = Get-Process

# Loop through each process and check if it has been hollowed
foreach ($process in $processes) {
    # Skip the WUDFRd process
    if ($process.Name -eq 'WUDFRd') {
        Write-Host "Skipping process $($process.Name) with PID $($process.Id) (excluded)"
        continue
    }

    # Get the process memory size directly
    $meminfo = $process.VirtualMemorySize64

    # Initialize $path to $null
    $path = $null

    # Attempt to get the process image file path
    try {
        $path = $process.Path
        if (-not $path) {
            Write-Host "No path available for process with PID $($process.Id) ($($process.Name))"
            continue
        }
    } catch {
        Write-Host "Error: Could not get path of process with PID $($process.Id) ($($process.Name))"
        continue
    }

    # Get the hash of the process image file, if path exists
    if ($path) {
        try {
            $hash = (Get-FileHash $path -Algorithm SHA256).Hash
        } catch {
            Write-Host "Error: Could not get hash of $path for PID $($process.Id)"
            continue
        }
    }

    # Check if the process has been hollowed
    $hollowed = $false
    $process.Modules | ForEach-Object {
        $sectionSize = $_.ModuleMemorySize
        $sectionBaseAddress = $_.BaseAddress.ToInt64()
        $sectionEndAddress = $sectionBaseAddress + $sectionSize

        # Check if section matches criteria for hollowing (this logic can be refined based on your specific detection method)
        if ($sectionSize -lt $meminfo -and ($sectionBaseAddress -eq 0 -or $sectionEndAddress -eq $meminfo)) {
            $hollowed = $true
        }
    }

    # If the process has been hollowed, print its details
    if ($hollowed) {
        Write-Host "Process $($process.Name) with PID $($process.Id) has been hollowed"
        Write-Host "Image File: $path"
        Write-Host "Image Hash: $hash"
    }
}


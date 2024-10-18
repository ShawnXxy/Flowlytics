param (
    [int]$ParallelWorker = 2
)

# Function to download the Convert-PcapToCsv script
function Download-Script {
    param (
        [string]$url,
        [string]$destinationPath
    )

    try {
        Invoke-WebRequest -Uri $url -OutFile $destinationPath
        Write-Host "Script downloaded successfully."
    } catch {
        Write-Host "Failed to download the script: $_"
        return $false
    }
    return $true
}

# Function to get all PCAP files from a specified folder
function Get-PcapFiles {
    param (
        [string]$folderPath
    )

    return Get-ChildItem -Path $folderPath -Filter *.pcap | Select-Object -ExpandProperty FullName
}

# Function to convert PCAP files to CSV using parallel processing
function Convert-PcapFiles {
    param (
        [string[]]$pcapFiles,
        [string]$targetPath,
        [string]$scriptPath
    )

    $pcapFiles | ForEach-Object -Parallel {
        # Load the script in the parallel execution
        . $using:scriptPath

        Write-Host "Converting: $_"
        if ([string]::IsNullOrWhiteSpace($using:targetPath)) {
            Convert-PcapToCsv -SourcePath $_
        } else {
            Convert-PcapToCsv -SourcePath $_ -TargetFolderPath $using:targetPath
        }
    } -ThrottleLimit $ParallelWorker
}

# Main script execution
$scriptUrl = "https://raw.githubusercontent.com/ShawnXxy/Flowlytics/main/Convert-PcapToCsv.ps1"
$tempScriptPath = Join-Path $env:TEMP "Convert-PcapToCsv.ps1"

if (Download-Script -url $scriptUrl -destinationPath $tempScriptPath) {
    $folderPath = Read-Host "Enter the path to your PCAP file or folder containing PCAP files"
    $pcapFiles = Get-PcapFiles -folderPath $folderPath

    if ($pcapFiles.Count -eq 0) {
        Write-Host "No PCAP files found in the directory."
    } else {
        Write-Host "Found $($pcapFiles.Count) PCAP files."
        
        $targetPath = Read-Host "Enter the target folder path (optional, press Enter to use default)"
        Convert-PcapFiles -pcapFiles $pcapFiles -targetPath $targetPath -scriptPath $tempScriptPath
    }
}

# Clean up: remove the temporary script file
if (Test-Path $tempScriptPath) {
    Remove-Item $tempScriptPath
}

# Keep the console window open
Read-Host "Press Enter to exit"

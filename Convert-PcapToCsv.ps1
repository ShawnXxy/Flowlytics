function Initialize-LoggingEnvironment {
    $Global:TempLogFolder = Join-Path $env:TEMP "flowlytics"
    if (-not (Test-Path $Global:TempLogFolder)) {
        New-Item -ItemType Directory -Force -Path $Global:TempLogFolder | Out-Null
    }
    $timestamp = Get-Date -Format "yyMMddHHmmss"
    $Global:TempLogFile = Join-Path $Global:TempLogFolder "conversion_log_$timestamp.log"
    Write-Host "Temp log folder: $Global:TempLogFolder"
    Write-Host "Temp log file: $Global:TempLogFile"
}

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
    $coloredMessage = switch ($Level) {
        "Info"    { $Message }
        "Warning" { Write-Host -ForegroundColor Yellow "[$timestamp UTC] $Message"; $Message }
        "Error"   { Write-Host -ForegroundColor Red "[$timestamp UTC] $Message"; $Message }
        "Success" { Write-Host -ForegroundColor Green "[$timestamp UTC] $Message"; $Message }
    }
    $logMessage = "[$timestamp UTC] [$Level] $Message"
    Add-Content -Path $Global:TempLogFile -Value $logMessage
    if ($Level -eq "Info") {
        Write-Host $logMessage
    }
}

function Get-FileSize {
    param ([string]$FilePath)
    $file = Get-Item $FilePath
    return "{0:N2} MB" -f ($file.Length / 1MB)
}

function Test-WindowsOS {
    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        Write-Log "Operating System: Windows" -Level Info
        return $true
    } else {
        Write-Log "Error: This script is designed to run on Windows OS only." -Level Error
        Write-Log "Current Operating System: $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)" -Level Error
        return $false
    }
}

function Find-Tshark {
    $tsharkPath = $null
    
    # Try to find tshark in common installation directories
    $commonPaths = @(
        "C:\Program Files\Wireshark",
        "C:\Program Files (x86)\Wireshark"
    )
    
    foreach ($path in $commonPaths) {
        $possiblePath = Join-Path $path "tshark.exe"
        if (Test-Path $possiblePath) {
            $tsharkPath = $possiblePath
            break
        }
    }
    
    # If not found in common paths, try to find it in PATH
    if (-not $tsharkPath) {
        $tsharkPath = Get-Command "tshark.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    }
    
    return $tsharkPath
}

function Convert-SinglePcap {
    param (
        [string]$SourcePcapPath,
        [string]$TargetFolderPath,
        [string]$TsharkPath
    )

    Write-Log "Starting Convert-SinglePcap function" -Level Info
    Write-Log "Source PCAP: $SourcePcapPath" -Level Info
    Write-Log "Target Folder: $TargetFolderPath" -Level Info
    Write-Log "Tshark Path: $TsharkPath" -Level Info

    # Check if source file exists
    if (-not (Test-Path $SourcePcapPath)) {
        Write-Log "Warning: Source file not found: $SourcePcapPath" -Level Warning
        return @{
            Source = $SourcePcapPath
            Target = $null
            Status = "Failed"
            Reason = "Source file not found"
        }
    }
    Write-Log "Source file exists" -Level Info

    # Log source file size
    $sourceSize = Get-FileSize -FilePath $SourcePcapPath
    Write-Log "Source PCAP file size: $sourceSize" -Level Info

    $sourceFileName = [System.IO.Path]::GetFileNameWithoutExtension($SourcePcapPath)
    $TargetCsvPath = Join-Path $TargetFolderPath "$sourceFileName.csv"
    Write-Log "Target CSV Path: $TargetCsvPath" -Level Info

    # Convert pcap to csv using tshark
    try {
        Write-Log "Starting PCAP to CSV conversion for: $SourcePcapPath" -Level Info

        # Convert pcap to csv
        Write-Log "Preparing tshark arguments for conversion" -Level Info
        $tsharkArgs = @(
            "-r", $SourcePcapPath,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "_ws.col.Info",
            "-E", "header=y",
            "-E", "quote=d",
            "-E", "separator=,"
        )
        Write-Log "Tshark arguments: $($tsharkArgs -join ' ')" -Level Info

        Write-Log "Starting tshark conversion process" -Level Info
        $output = & $TsharkPath $tsharkArgs
        Write-Log "Tshark execution completed" -Level Info
        
        if ($output) {
            Write-Log "Tshark produced output. Writing to file: $TargetCsvPath" -Level Info
            $output | Out-File -FilePath $TargetCsvPath -Encoding utf8
            Write-Log "File write operation completed" -Level Info
            
            # Check if the file was actually created
            if (Test-Path $TargetCsvPath) {
                $targetSize = Get-FileSize -FilePath $TargetCsvPath
                Write-Log "Conversion completed successfully." -Level Success
                Write-Log "Source: $SourcePcapPath" -Level Info
                Write-Log "Target: $TargetCsvPath" -Level Info
                Write-Log "Generated CSV file size: $targetSize" -Level Info
                
                # Add validation step
                Write-Log "Starting validation" -Level Info
                Validate-Conversion -SourcePcapPath $SourcePcapPath -TargetCsvPath $TargetCsvPath -TsharkPath $TsharkPath
                Write-Log "Validation completed" -Level Info
            } else {
                throw "CSV file was not created at the expected location: $TargetCsvPath"
            }
        }
        else {
            Write-Log "Tshark did not produce any output" -Level Error
            throw "tshark did not produce any output"
        }

        # Verify the CSV file is not empty
        $fileInfo = Get-Item $TargetCsvPath
        if ($fileInfo.Length -eq 0) {
            Write-Log "Generated CSV file is empty" -Level Error
            throw "The generated CSV file is empty"
        }
        Write-Log "CSV file is not empty. Size: $($fileInfo.Length) bytes" -Level Info
    }
    catch {
        Write-Log "Error: An error occurred during the conversion of $SourcePcapPath" -Level Error
        Write-Log "Error details: $_" -Level Error
        Write-Log "Error stack trace: $($_.ScriptStackTrace)" -Level Error
        return @{
            Source = $SourcePcapPath
            Target = $null
            Status = "Failed"
            Reason = $_.Exception.Message
        }
    }

    Write-Log "Finished processing file: $SourcePcapPath" -Level Info

    # Return conversion result
    return @{
        Source = $SourcePcapPath
        Target = $TargetCsvPath
        Status = "Success"
    }
}

function Validate-Conversion {
    param (
        [string]$SourcePcapPath,
        [string]$TargetCsvPath,
        [string]$TsharkPath
    )

    Write-Log "Validating conversion for $SourcePcapPath" -Level Info

    # Count packets in PCAP file
    $pcapPacketCount = & $TsharkPath -r $SourcePcapPath -T fields -e frame.number | Measure-Object -Line | Select-Object -ExpandProperty Lines
    Write-Log "PCAP file contains $pcapPacketCount packets" -Level Info

    # Count lines in CSV file (excluding header)
    $csvLineCount = (Get-Content $TargetCsvPath | Measure-Object -Line).Lines - 1
    Write-Log "CSV file contains $csvLineCount lines (excluding header)" -Level Info

    if ($pcapPacketCount -ne $csvLineCount) {
        Write-Log "Warning: Packet count mismatch. PCAP: $pcapPacketCount, CSV: $csvLineCount" -Level Warning
    }

    # Check for essential fields
    $essentialFields = @("frame.number", "frame.time", "ip.src", "ip.dst", "_ws.col.Protocol", "frame.len", "_ws.col.Info")
    $csvHeader = Get-Content $TargetCsvPath -TotalCount 1
    $missingFields = $essentialFields | Where-Object { $csvHeader -notmatch $_ }
    
    if ($missingFields) {
        Write-Log "Warning: Missing essential fields in CSV: $($missingFields -join ', ')" -Level Warning
    }

}

function Convert-PcapToCsv {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Files")]
        [string[]]$SourcePcapPaths,

        [Parameter(Mandatory = $true, ParameterSetName = "Folder")]
        [string]$SourceFolderPath,

        [Parameter(Mandatory = $false)]
        [string]$TargetFolderPath
    )

    # Initialize logging environment
    Initialize-LoggingEnvironment

    # Validate OS environment
    if (-not (Test-WindowsOS)) {
        Write-Log "Aborting: This script requires Windows OS." -Level Error
        return
    }

    Write-Log "Starting PCAP to CSV conversion process" -Level Info

    # Find tshark
    Write-Log "Searching for tshark executable" -Level Info
    $tsharkPath = Find-Tshark

    # Check if tshark is found
    if (-not $tsharkPath) {
        Write-Log "Error: tshark not found" -Level Error
        Write-Log @"
tshark is not found. Here's some diagnostic information:
Current PATH: $env:PATH

To install tshark:
1. Download and install Wireshark from https://www.wireshark.org/download.html
2. During installation, ensure you select the option to install TShark
3. After installation, add the Wireshark installation directory (usually C:\Program Files\Wireshark) to your system PATH
4. Restart your PowerShell session

For more information, visit: https://tshark.dev/setup/install/
"@ -Level Error
        return
    }
    else {
        Write-Log "Found tshark at: $tsharkPath" -Level Success
    }

    # If TargetFolderPath is not provided, use the Downloads folder
    if (-not $TargetFolderPath) {
        $TargetFolderPath = [System.Environment]::GetFolderPath("UserProfile") + "\Downloads"
        Write-Log "Target folder not specified. Using Downloads folder: $TargetFolderPath" -Level Info
    }

    # Create the target directory if it doesn't exist
    Write-Log "Ensuring target directory exists" -Level Info
    if (-not (Test-Path $TargetFolderPath)) {
        New-Item -ItemType Directory -Path $TargetFolderPath -Force | Out-Null
        Write-Log "Created target directory: $TargetFolderPath" -Level Success
    }

    # If SourceFolderPath is provided, get all .pcap files from that folder
    if ($PSCmdlet.ParameterSetName -eq "Folder") {
        Write-Log "Searching for .pcap files in folder: $SourceFolderPath" -Level Info
        $SourcePcapPaths = Get-ChildItem -Path $SourceFolderPath -Filter "*.pcap" | Select-Object -ExpandProperty FullName
        Write-Log "Found $($SourcePcapPaths.Count) .pcap files" -Level Info
    }

    # Confirm with user if multiple files are to be converted
    if ($SourcePcapPaths.Count -gt 1) {
        Write-Log "The following $($SourcePcapPaths.Count) files will be converted:" -Level Info
        $SourcePcapPaths | ForEach-Object { Write-Log "  - $_" -Level Info }
        
        Write-Log "Warning: Converting multiple files will use multiple threads and may impact system performance." -Level Warning
        $confirmation = Read-Host "Do you want to proceed? (Y/N)"
        
        if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
            Write-Log "Operation cancelled by user." -Level Warning
            return
        }
    }

    # Determine the number of threads to use
    $MaxThreads = [Math]::Min($SourcePcapPaths.Count, [Environment]::ProcessorCount)
    Write-Log "Using $MaxThreads thread(s) for conversion" -Level Info

    # Create and start jobs for each PCAP file
    $jobs = @()
    foreach ($SourcePcapPath in $SourcePcapPaths) {
        $jobScript = {
            param($SourcePcapPath, $TargetFolderPath, $TsharkPath, $WriteLogString, $GetFileSizeString, $ConvertSinglePcapString, $ValidateConversionString, $TempLogFile)

            # Import required functions
            ${function:Write-Log} = [ScriptBlock]::Create($WriteLogString)
            ${function:Get-FileSize} = [ScriptBlock]::Create($GetFileSizeString)
            ${function:Convert-SinglePcap} = [ScriptBlock]::Create($ConvertSinglePcapString)
            ${function:Validate-Conversion} = [ScriptBlock]::Create($ValidateConversionString)

            # Set the global temp log file for this job
            $Global:TempLogFile = $TempLogFile

            # Determine the target folder for this specific file
            $fileTargetFolder = if ($TargetFolderPath) {
                $TargetFolderPath
            } else {
                [System.IO.Path]::GetDirectoryName($SourcePcapPath)
            }

            $result = Convert-SinglePcap -SourcePcapPath $SourcePcapPath -TargetFolderPath $fileTargetFolder -TsharkPath $TsharkPath
            return @{
                Result = $result
                Logs = $Global:LogMessages
            }
        }

        $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList @(
            $SourcePcapPath, 
            $TargetFolderPath, 
            $tsharkPath, 
            ${function:Write-Log}.ToString(),
            ${function:Get-FileSize}.ToString(),
            ${function:Convert-SinglePcap}.ToString(),
            ${function:Validate-Conversion}.ToString(),
            $Global:TempLogFile
        )
        
        # Limit the number of concurrent jobs
        while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxThreads) {
            Start-Sleep -Milliseconds 500
        }
    }

    # Wait for all jobs to complete
    $jobs | Wait-Job

    # Process job results
    $conversionResults = @()
    foreach ($job in $jobs) {
        $jobOutput = Receive-Job -Job $job
        $conversionResults += $jobOutput.Result
        $jobOutput.Logs | ForEach-Object {
            if ($_ -match '\[(Info|Warning|Error|Success)\]') {
                $level = $matches[1]
                $message = $_ -replace "\[$level\] ", ''
                Write-Log $message -Level $level
            } else {
                Write-Host $_
            }
        }
    }

    # Check for any errors in the jobs and process results
    $failedJobs = $jobs | Where-Object { $_.State -eq 'Failed' }

    if ($failedJobs -or ($conversionResults | Where-Object { $_.Status -eq "Failed" })) {
        Write-Log "The following files failed to convert:" -Level Error
        $failedJobs | ForEach-Object {
            Write-Log "Job ID: $($_.Id), Error: $($_.ChildJobs[0].JobStateInfo.Reason.Message)" -Level Error
        }
        $conversionResults | Where-Object { $_.Status -eq "Failed" } | ForEach-Object {
            Write-Log "Source: $($_.Source), Reason: $($_.Reason)" -Level Error
        }
        Write-Log "PCAP to CSV conversion process finished with errors. Some files may not have been converted successfully." -Level Warning
    } else {
        $successfulConversions = $conversionResults | Where-Object { $_.Status -eq "Success" }
        if ($successfulConversions) {
            Write-Log "Successfully converted the following files:" -Level Success
            $successfulConversions | ForEach-Object {
                Write-Log "Source: $($_.Source)" -Level Info
                if ($_.Target) {
                    Write-Log "Target: $($_.Target)" -Level Info
                } else {
                    Write-Log "Target: Not specified (using source directory)" -Level Info
                }
            }
            
            # Open the target folder(s)
            $foldersToOpen = $successfulConversions | ForEach-Object { 
                if ($_.Target) { 
                    Split-Path -Parent $_.Target 
                } else { 
                    Split-Path -Parent $_.Source 
                }
            } | Select-Object -Unique
            
            foreach ($folder in $foldersToOpen) {
                Write-Log "Opening folder: $folder" -Level Info
                Start-Process "explorer.exe" -ArgumentList $folder
            }
        }
        Write-Log "PCAP to CSV conversion process finished for all files" -Level Success
    }

    # Open the temp log folder
    Write-Log "Opening temp log folder: $Global:TempLogFolder" -Level Info
    Start-Process "explorer.exe" -ArgumentList $Global:TempLogFolder

    # Clean up jobs
    $jobs | Remove-Job
}

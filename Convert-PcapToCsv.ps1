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
        [string]$Level = "Info",
        [string]$JobId = ""
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
    $jobPrefix = if ($JobId) { "[Job-$JobId] " } else { "" }
    $logMessage = "[$timestamp UTC] [$Level] $jobPrefix $Message"
    
    # Write to file if TempLogFile is defined
    if ($Global:TempLogFile) {
        Add-Content -Path $Global:TempLogFile -Value $logMessage
    }
    
    # Write to console with color
    switch ($Level) {
        "Info"    { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error"   { Write-Host $logMessage -ForegroundColor Red }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
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

    $startTime = Get-Date

    Write-Log "[ConvertSinglePcapActor] Starting Convert-SinglePcap: " -Level Info
    Write-Log "     Source PCAP: $SourcePcapPath" -Level Info
    Write-Log "     Target Folder: $TargetFolderPath" -Level Info

    # Check if source file exists
    if (-not (Test-Path $SourcePcapPath)) {
        Write-Log "[ConvertSinglePcapActor] Warning: Source file not found: $SourcePcapPath" -Level Warning
        return @{
            Source = $SourcePcapPath
            Target = $null
            Status = "Failed"
            Reason = "Source file not found"
        }
    }
    Write-Log "[ConvertSinglePcapActor] Source file exists" -Level Info

    # Log source file size
    $sourceSize = Get-FileSize -FilePath $SourcePcapPath
    Write-Log "[ConvertSinglePcapActor] Source PCAP file size: $sourceSize" -Level Info

    $sourceFileName = [System.IO.Path]::GetFileNameWithoutExtension($SourcePcapPath)
    $TargetCsvPath = Join-Path $TargetFolderPath "$sourceFileName.csv"
    Write-Log "[ConvertSinglePcapActor] Target CSV Path: $TargetCsvPath" -Level Info

    # Convert pcap to csv using tshark
    try {
        Write-Log "[ConvertSinglePcapActor] Starting PCAP to CSV conversion for: $SourcePcapPath" -Level Info

        # Convert pcap to csv
        Write-Log "[ConvertSinglePcapActor] Preparing tshark arguments for conversion" -Level Info
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
        Write-Log "[ConvertSinglePcapActor] Tshark arguments: $($tsharkArgs -join ' ')" -Level Info

        Write-Log "[ConvertSinglePcapActor] Starting tshark conversion process" -Level Info
        $output = & $TsharkPath $tsharkArgs
        Write-Log "[ConvertSinglePcapActor] Tshark execution completed" -Level Info
        
        if ($output) {
            Write-Log "Tshark produced output. Writing to file: $TargetCsvPath" -Level Info
            $output | Out-File -FilePath $TargetCsvPath -Encoding utf8
            Write-Log "[ConvertSinglePcapActor] File write operation completed" -Level Info
            
            # Check if the file was actually created
            if (Test-Path $TargetCsvPath) {
                $targetSize = Get-FileSize -FilePath $TargetCsvPath
                Write-Log "[ConvertSinglePcapActor] Conversion completed successfully." -Level Success
                Write-Log "[ConvertSinglePcapActor] Source: $SourcePcapPath" -Level Info
                Write-Log "[ConvertSinglePcapActor] Target: $TargetCsvPath" -Level Info
                Write-Log "[ConvertSinglePcapActor] Generated CSV file size: $targetSize" -Level Info
                
                # Add validation step
                Write-Log "[ConvertSinglePcapActor] Starting validation" -Level Info
                Validate-Conversion -SourcePcapPath $SourcePcapPath -TargetCsvPath $TargetCsvPath -TsharkPath $TsharkPath
                Write-Log "[ConvertSinglePcapActor] Validation completed" -Level Info
            } else {
                throw "CSV file was not created at the expected location: $TargetCsvPath"
            }
        }
        else {
            Write-Log "[ConvertSinglePcapActor] Tshark did not produce any output" -Level Error
            throw "tshark did not produce any output"
        }

        # Verify the CSV file is not empty
        $fileInfo = Get-Item $TargetCsvPath
        if ($fileInfo.Length -eq 0) {
            Write-Log "[ConvertSinglePcapActor] Generated CSV file is empty" -Level Error
            throw "The generated CSV file is empty"
        }
        Write-Log "[ConvertSinglePcapActor] CSV file is not empty. Size: $($fileInfo.Length) bytes" -Level Info
    }
    catch {
        $endTime = Get-Date
        $timeSpan = $endTime - $startTime
        $timeUsed = [math]::Round($timeSpan.TotalSeconds, 2)

        Write-Log "Error: An error occurred during the conversion of $SourcePcapPath" -Level Error
        Write-Log "Error details: $_" -Level Error
        Write-Log "Error stack trace: $($_.ScriptStackTrace)" -Level Error
        return @{
            Source = $SourcePcapPath
            Target = $null
            Status = "Failed"
            Reason = $_.Exception.Message
            TimeUsed = $timeUsed
        }
    }

    Write-Log "Finished processing file: $SourcePcapPath" -Level Info

    $endTime = Get-Date
    $timeSpan = $endTime - $startTime
    $timeUsed = [math]::Round($timeSpan.TotalSeconds, 2)

    # Return conversion result
    return @{
        Source = $SourcePcapPath
        Target = $TargetCsvPath
        Status = "Success"
        TimeUsed = $timeUsed
    }
}

function Validate-Conversion {
    param (
        [string]$SourcePcapPath,
        [string]$TargetCsvPath,
        [string]$TsharkPath
    )

    Write-Log "[ValidateConversionActor] Validating conversion for $SourcePcapPath" -Level Info

    # Count packets in PCAP file
    $pcapPacketCount = & $TsharkPath -r $SourcePcapPath -T fields -e frame.number | Measure-Object -Line | Select-Object -ExpandProperty Lines
    Write-Log "[ValidateConversionActor] PCAP file contains $pcapPacketCount packets" -Level Info

    # Count lines in CSV file (excluding header)
    $csvLineCount = (Get-Content $TargetCsvPath | Measure-Object -Line).Lines - 1
    Write-Log "[ValidateConversionActor] CSV file contains $csvLineCount lines (excluding header)" -Level Info

    if ($pcapPacketCount -ne $csvLineCount) {
        Write-Log "[ValidateConversionActor] Warning: Packet count mismatch. PCAP: $pcapPacketCount, CSV: $csvLineCount" -Level Warning
    }

    # Check for essential fields
    $essentialFields = @("frame.number", "frame.time", "ip.src", "ip.dst", "_ws.col.Protocol", "frame.len", "_ws.col.Info")
    $csvHeader = Get-Content $TargetCsvPath -TotalCount 1
    $missingFields = $essentialFields | Where-Object { $csvHeader -notmatch $_ }
    
    if ($missingFields) {
        Write-Log "[ValidateConversionActor] Warning: Missing essential fields in CSV: $($missingFields -join ', ')" -Level Warning
    }

}

# Add this new function to format and display the results table
function Format-ConversionResultsTable {
    param (
        [array]$Results
    )
    $table = @()
    foreach ($result in $Results) {
        $sourceSize = Get-FileSize -FilePath $result.Source
        $sourceName = Split-Path $result.Source -Leaf
        $sourcePath = Split-Path $result.Source -Parent
        
        if ($result.Status -eq "Success") {
            $targetSize = Get-FileSize -FilePath $result.Target
            $targetName = Split-Path $result.Target -Leaf
            $targetPath = Split-Path $result.Target -Parent
            $timeUsed = "$($result.TimeUsed) seconds"
        } else {
            $targetSize = "N/A"
            $targetName = "N/A"
            $targetPath = "N/A"
            $timeUsed = "N/A"
        }
        
        $table += [PSCustomObject]@{
            'Job ID' = $result.JobId
            'Source File' = $sourceName
            'Source Path' = $sourcePath
            'Source Size' = $sourceSize
            'Target File' = $targetName
            'Target Path' = $targetPath
            'Target Size' = $targetSize
            'Time Used' = $timeUsed
            'Status' = $result.Status
        }
    }
    
    $table | Format-Table -AutoSize -Wrap
}

function Convert-PcapToCsv {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$SourcePath,

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

    # Determine if SourcePath is a file or folder
    if (Test-Path $SourcePath -PathType Leaf) {
        if ($SourcePath -like "*.pcap") {
            $SourcePcapPaths = @($SourcePath)
            Write-Log "Source is a single PCAP file: $SourcePath" -Level Info
        } else {
            Write-Log "Error: Source file is not a .pcap file: $SourcePath" -Level Error
            return
        }
    }
    elseif (Test-Path $SourcePath -PathType Container) {
        Write-Log "Searching for .pcap files in folder: $SourcePath" -Level Info
        $SourcePcapPaths = Get-ChildItem -Path $SourcePath -Filter "*.pcap" -Recurse | Select-Object -ExpandProperty FullName
        if ($SourcePcapPaths.Count -eq 0) {
            Write-Log "Error: No .pcap files found in the specified folder: $SourcePath" -Level Error
            return
        }
        Write-Log "Found $($SourcePcapPaths.Count) .pcap files in $SourcePath" -Level Info
    }
    else {
        Write-Log "Error: The specified source path does not exist or is not accessible: $SourcePath" -Level Error
        return
    }

    # Validate TargetFolderPath
    if (-not $TargetFolderPath) {
        $TargetFolderPath = [System.Environment]::GetFolderPath("UserProfile") + "\Downloads"
        Write-Log "Target folder path not specified or not found. Using Downloads directory: $TargetFolderPath" -Level Info
    } else {
        Write-Log "Target folder pathspecified: $TargetFolderPath" -Level Info
    }

    # Create the target directory if it doesn't exist
    if (-not (Test-Path $TargetFolderPath)) {
        Write-Log "Creating target folder..." -Level Info
        New-Item -ItemType Directory -Path $TargetFolderPath -Force | Out-Null
        Write-Log "Created target directory: $TargetFolderPath" -Level Success
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
    Write-Log "Using $MaxThreads thread(s) for conversion because there are $($SourcePcapPaths.Count) pcap files to convert" -Level Info

    # Create and start jobs for each PCAP file
    $jobs = @()
    $jobCount = 0
    foreach ($SourcePcapPath in $SourcePcapPaths) {
        $jobCount++
        Write-Log "Starting job $jobCount of $($SourcePcapPaths.Count) for file: $SourcePcapPath" -Level Info
        
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

            Write-Log "Executing Convert-SinglePcap. Starting conversion for file: $SourcePcapPath" -Level Info
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

    }

    # Monitor jobs
    Monitor-ConversionJobs -Jobs $jobs

    Write-Log "All jobs completed. Processing results..." -Level Info

    # Process job results
    $conversionResults = @()
    foreach ($job in $jobs) {
        Write-Log "Processing results for job $($job.Id)" -Level Info
        $jobOutput = Receive-Job -Job $job
        $jobOutput.Result.JobId = $job.Id  # Add JobId to the result
        $conversionResults += $jobOutput.Result
        $jobOutput.Logs | ForEach-Object {
            if ($_ -match '\[(Info|Warning|Error|Success)\]') {
                $level = $matches[1]
                $message = $_ -replace "\[$level\] ", ''
                Write-Log $message -Level $level -JobId $job.Id
            } else {
                Write-Host $_
            }
        }
    }

    Write-Log "All job results processed. Analyzing outcomes..." -Level Info

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
        Write-Log "PCAP to CSV conversion process finished for all files successfully." -Level Success
    }

    # Display the results table
    Write-Log "Conversion Results Summary:" -Level Info
    Format-ConversionResultsTable -Results $conversionResults

    # Open the target folder(s)
    $foldersToOpen = $conversionResults | Where-Object { $_.Status -eq "Success" } | ForEach-Object { 
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

    # Open the temp log folder
    Write-Log "Opening temp log folder: $Global:TempLogFolder" -Level Info
    Start-Process "explorer.exe" -ArgumentList $Global:TempLogFolder

    # Clean up jobs
    $jobs | Remove-Job
}

function Monitor-ConversionJobs {
    param (
        [array]$Jobs,
        [int]$IntervalSeconds = 10
    )
    $totalJobs = $Jobs.Count
    $completedJobs = 0

    while ($Jobs | Where-Object { $_.State -eq 'Running' }) {
        $runningJobs = $Jobs | Where-Object { $_.State -eq 'Running' }
        $completedJobs = ($Jobs | Where-Object { $_.State -eq 'Completed' }).Count

        $runningJobIds = $runningJobs | ForEach-Object { $_.Id }
        Write-Log "[StatusCheckActor] Progress: $completedJobs of $totalJobs jobs completed. $($runningJobs.Count) jobs still running. Running job IDs: $($runningJobIds -join ', ')" -Level Info
        
        Start-Sleep -Seconds $IntervalSeconds
    }

    Write-Log "All jobs completed." -Level Success
}

# sample call
 Convert-PcapToCsv -SourcePath "C:\Users\xixia\Downloads\client side.pcap"
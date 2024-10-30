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

function Monitor-ConversionJobs {
    param (
        [array]$Jobs,
        [int]$IntervalSeconds = 10
    )
    $countTotalJobs = $Jobs.Count
    $completedJobs = 0

    while ($Jobs | Where-Object { $_.State -eq 'Running' }) {
        $runningJobs = $Jobs | Where-Object { $_.State -eq 'Running' }
        $completedJobs = $Jobs | Where-Object { $_.State -eq 'Completed' }
        $pendingJobs = $countTotalJobs - $runningJobs.Count - $completedJobs.Count

        $runningJobIds = $runningJobs | ForEach-Object { $_.Id }
        Write-Log "[StatusCheckActor] Progress: $($completedJobs.Count) of $countTotalJobs jobs completed. $($runningJobs.Count) jobs still running. Running job IDs: $($runningJobIds -join ', '). Currently $pendingJobs job(s) pending. " -Level Info
        
        Start-Sleep -Seconds $IntervalSeconds
    }

    Write-Log "All jobs completed." -Level Success
}

function Get-FileSize {
    param ([string]$FilePath)
    $file = Get-Item $FilePath
    return "{0:N2} MB" -f ($file.Length / 1MB)
}


function Validate-SourcePath {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$SourcePaths
    )

    begin {
        $validPcapPaths = @()
    }

    process {
        foreach ($SourcePath in $SourcePaths) {
            if (Test-Path $SourcePath -PathType Leaf) {
                if ($SourcePath -like "*.pcap" -or $SourcePath -like "*.cap") {
                    Write-Log "Source is a single PCAP file: $SourcePath" -Level Info
                    $validPcapPaths += $SourcePath
                } else {
                    Write-Log "Error: Source file is not a .pcap file: $SourcePath" -Level Error
                }
            }
            elseif (Test-Path $SourcePath -PathType Container) {
                Write-Log "Searching for .pcap files in folder: $SourcePath" -Level Info
                $pcapFiles = Get-ChildItem -Path $SourcePath -Filter "*.pcap" -Recurse | Select-Object -ExpandProperty FullName
                if ($pcapFiles.Count -eq 0) {
                    Write-Log "Error: No .pcap files found in the specified folder: $SourcePath" -Level Error
                } else {
                    Write-Log "Found $($pcapFiles.Count) .pcap files in $SourcePath" -Level Info
                    $validPcapPaths += $pcapFiles
                }
            }
            else {
                Write-Log "Error: The specified source path does not exist or is not accessible: $SourcePath" -Level Error
            }
        }
    }

    end {
        return $validPcapPaths
    }
}

function Validate-TargetPath {
    param (
        [string]$TargetPath
    )

    # If no target path is specified, set the default path
    if (-not $TargetPath) {
        $TargetPath = Join-Path ([System.Environment]::GetFolderPath("UserProfile") + "\Downloads") "Flowlytics_Output"
        Write-Log "Target path not specified. Attempting to create default folder: $TargetPath" -Level Info
        
        # Attempt to create the default directory
        try {
            if (-not (Test-Path $TargetPath)) {
                New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
                Write-Log "Successfully created directory: $TargetPath" -Level Success
            } else {
                Write-Log "Directory already exists: $TargetPath" -Level Info
            }
        } catch {
            Write-Log "Error creating directory: $_" -Level Error
            return $null
        }
    }
    elseif (Test-Path $TargetPath -PathType Container) {
        Write-Log "Target is a directory: $TargetPath" -Level Info
    }
    elseif (Test-Path $TargetPath -PathType Leaf) {
        Write-Log "Target is a file: $TargetPath" -Level Info
        $TargetPath = Split-Path $TargetPath -Parent
        Write-Log "Using parent directory as target: $TargetPath" -Level Info
    }
    else {
        Write-Log "Invalid target path. Attempting to create new directory: $TargetPath" -Level Warning
        try {
            New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
            Write-Log "Successfully created directory: $TargetPath" -Level Success
        } catch {
            Write-Log "Error creating directory: $_" -Level Error
            return $null
        }
    }

    # Check if the target path is accessible
    if (-not (Test-Path $TargetPath)) {
        Write-Log "Error: Unable to create or access target directory: $TargetPath" -Level Error
        return $null
    }

    Write-Log "Target folder: $TargetPath" -Level Info
    return $TargetPath
}

function Split-LargePcap {
    param (
        [string]$SourcePcapPath,
        [string]$WiresharkPath,
        [int]$MaxPackets = 3000000  # Set the maximum packets per file
    )

    Write-Log "[SplitLargePcapActor] Starting to split large PCAP file: $SourcePcapPath" -Level Info
    $sourceFileName = [System.IO.Path]::GetFileNameWithoutExtension($SourcePcapPath)
    $sourceDir = [System.IO.Path]::GetDirectoryName($SourcePcapPath)
    $splitDir = Join-Path $sourceDir "$sourceFileName-split"

    if (-not (Test-Path $splitDir)) {
        New-Item -ItemType Directory -Path $splitDir | Out-Null
        Write-Log "[SplitLargePcapActor] Created split directory: $splitDir" -Level Info
    }

    $editcapPath = Join-Path $WiresharkPath "editcap.exe"
    if (-not (Test-Path $editcapPath)) {
        Write-Log "[SplitLargePcapActor] Error: editcap.exe not found at $editcapPath" -Level Error
        return $null
    }

    $splitFilePattern = Join-Path $splitDir "${sourceFileName}_flowlytics_chunk_"

    $splitArgs = @(
        "-c", $MaxPackets,  # Use the maximum packets per file
        $SourcePcapPath,
        "$splitFilePattern.pcap"
    )

    Write-Log "[SplitLargePcapActor] Executing editcap to split file. Command: $editcapPath $($splitArgs -join ' ')" -Level Info
    $output = & $editcapPath $splitArgs 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Log "[SplitLargePcapActor] Error splitting PCAP file: $output" -Level Error
        return $null
    }

    $splitFiles = Get-ChildItem -Path $splitDir -Filter "*.pcap"
    
    if ($splitFiles.Count -eq 0) {
        Write-Log "[SplitLargePcapActor] Error: No split files were created." -Level Error
        return $null
    }
    
    Write-Log "[SplitLargePcapActor] Split complete. Created $($splitFiles.Count) files:" -Level Success
    $totalSize = 0
    $splitFiles | ForEach-Object {
        $fileSize = $_.Length / 1MB
        $totalSize += $fileSize
        $fileSizeFormatted = "{0:N2} MB" -f $fileSize
        Write-Log "  - $($_.Name) ($fileSizeFormatted)" -Level Info
    }
    
    $originalSize = (Get-Item $SourcePcapPath).Length / 1MB
    Write-Log "[SplitLargePcapActor] Original file size: $("{0:N2} MB" -f $originalSize)" -Level Info
    Write-Log "[SplitLargePcapActor] Total size of split files: $("{0:N2} MB" -f $totalSize)" -Level Info

    return $splitFiles.FullName
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
    try {
        $sourceSize = Get-FileSize -FilePath $SourcePcapPath
        Write-Log "[ConvertSinglePcapActor] Source PCAP file size: $sourceSize" -Level Info
    } catch {
        Write-Log "[ConvertSinglePcapActor] Error getting file size: $_" -Level Error
        return @{
            Source = $SourcePcapPath
            Target = $null
            Status = "Failed"
            Reason = "Unable to read source file size"
        }
    }

    $sourceFileName = [System.IO.Path]::GetFileNameWithoutExtension($SourcePcapPath)
    $isSplitFile = $sourceFileName -match "_flowlytics_chunk_\d+$"
    if ($isSplitFile) {
        $originalFileName = $sourceFileName -replace "_chunk_\d+$", ""
        $TargetCsvPath = Join-Path $TargetFolderPath "$sourceFileName.csv"
    } else {
        $TargetCsvPath = Join-Path $TargetFolderPath "$sourceFileName.csv"
    }
    Write-Log "[ConvertSinglePcapActor] Target CSV Path: $TargetCsvPath" -Level Info


    # Convert pcap to csv using tshark
    try {
        Write-Log "[ConvertSinglePcapActor] Starting PCAP to CSV conversion for: $SourcePcapPath" -Level Info

        # Convert pcap to csv
        
        Write-Log "[ConvertSinglePcapActor] Preparing tshark arguments for conversion" -Level Info
        $tsharkArgs = @(
            "-r", $SourcePcapPath,
            "-T", "fields",
            # https://www.wireshark.org/docs/dfref/f/frame.html         
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.time_utc",
            "-e", "frame.time",
            "-e", "frame.time_delta",
            "-e", "frame.len",
            "-e", "frame.protocols",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.id",
            # https://www.wireshark.org/docs/dfref/t/tcp.html
            "-e", "tcp.seq",
            "-e", "tcp.ack",
            "-e", "tcp.stream",          
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "_ws.col.Info",
            "-e", "_ws.col.Protocol",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ipv6.src",
            "-E", "header=y",
            "-E", "quote=d",
            "-E", "separator=,"
        )
        Write-Log "[ConvertSinglePcapActor] Tshark arguments: $($tsharkArgs -join ' ')" -Level Info

        Write-Log "[ConvertSinglePcapActor] Starting tshark conversion process" -Level Info
        $output = & $TsharkPath $tsharkArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "[ConvertSinglePcapActor] Error during tshark execution: $output" -Level Error
            throw "Tshark execution failed"
        }


        Write-Log "[ConvertSinglePcapActor] Tshark execution completed" -Level Info
        
        if ($output) {
            Write-Log "Tshark produced output. Writing to file: $TargetCsvPath" -Level Info
            try {
                $output | Out-File -FilePath $TargetCsvPath -Encoding utf8 -ErrorAction Stop
                Write-Log "[ConvertSinglePcapActor] File write operation completed" -Level Info
            } catch {
                Write-Log "[ConvertSinglePcapActor] Error writing to CSV file: $_" -Level Error
                throw "Failed to write output to CSV"
            }
            
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
    
    # Format the table as a string
    $tableString = $table | Format-Table -AutoSize -Wrap | Out-String

    # Write to log file
    Write-Log "Conversion Results Table:" -Level Info
    Write-Log $tableString -Level Info
}

function Convert-PcapToCsv {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]]$SourcePath,

        [Parameter(Mandatory = $false)]
        [string]$TargetFolderPath,

        [Parameter(Mandatory = $false)]
        [int]$MaxConcurrentJobs = 8
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
    Write-Log "Found tshark at: $tsharkPath" -Level Success

    # Find Wireshark installation path
    $wiresharkPath = Split-Path $tsharkPath -Parent
    Write-Log "Wireshark installation path: $wiresharkPath" -Level Info
    
    # Validate source paths and split large files if necessary
    $SourcePcapPaths = @()
    foreach ($path in $SourcePath) {
        $validatedPaths = Validate-SourcePath -SourcePaths $path
        foreach ($validPath in $validatedPaths) {
            $fileSize = (Get-Item $validPath).Length / 1MB
            if ($fileSize -gt 500) {
                Write-Log "Large file detected ($fileSize MB): $validPath" -Level Info
                $splitFiles = Split-LargePcap -SourcePcapPath $validPath -WiresharkPath $wiresharkPath -MaxSizeMB 500
                if ($splitFiles) {
                    Write-Log "Successfully split file into $($splitFiles.Count) parts." -Level Success
                    $SourcePcapPaths += $splitFiles
                } else {
                    Write-Log "Failed to split large file: $validPath. Will process the original file." -Level Warning
                    $SourcePcapPaths += $validPath
                }
            } else {
                $SourcePcapPaths += $validPath
            }
        }
    }

    if ($SourcePcapPaths.Count -eq 0) {
        Write-Log "No valid PCAP files found in the specified source path(s)." -Level Error
        return
    }

    # Validate target path
    $TargetFolderPath = Validate-TargetPath -TargetPath $TargetFolderPath
    if (-not $TargetFolderPath) {
        return
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
    $MaxThreads = $SourcePcapPaths.Count
    Write-Log "Need $MaxThreads thread(s) for conversion because there is/are $($SourcePcapPaths.Count) .pcap files to convert" -Level Info
    if ($MaxThreads -ge $MaxConcurrentJobs) {
        $MaxThreads = $MaxConcurrentJobs
        Write-Log "Using $MaxThreads thread(s) for conversion to convert as max allowed." -Level Info
    } else {
        $MaxThreads = [Math]::Min([Math]::Min($SourcePcapPaths.Count, [Environment]::ProcessorCount), $MaxConcurrentJobs)
        Write-Log "Using $MaxThreads thread(s) for conversion because there is/are $($SourcePcapPaths.Count) .pcap files to convert" -Level Info
    }

    # Create and start jobs for each PCAP file
    $jobs = @()
    foreach ($SourcePcapPath in $SourcePcapPaths) {
        # Wait for available slots if the number of running jobs reaches MaxConcurrentJobs
        while ($jobs.Count -ge $MaxConcurrentJobs) {
                        
            # Monitor and remove completed jobs from the list
            $jobs = $jobs | Where-Object { $_.State -eq 'Running' }
            Start-Sleep -Seconds 1
        }

        Write-Log "Starting job for file: $SourcePcapPath" -Level Info
                
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

            $jobId = $PID  # Use the current process ID as the job ID
            Write-Log "Executing Convert-SinglePcap. Starting conversion for file: $SourcePcapPath" -Level Info
            $result = Convert-SinglePcap -SourcePcapPath $SourcePcapPath -TargetFolderPath $fileTargetFolder -TsharkPath $TsharkPath
            $result.JobId = $jobId  # Add the job ID to the result
            return @{
                Result = $result
                Logs = $Global:LogMessages
            }
        }

        $job = Start-Job -ScriptBlock $jobScript -ArgumentList @(
            $SourcePcapPath, 
            $TargetFolderPath, 
            $tsharkPath, 
            ${function:Write-Log}.ToString(),
            ${function:Get-FileSize}.ToString(),
            ${function:Convert-SinglePcap}.ToString(),
            ${function:Validate-Conversion}.ToString(),
            $Global:TempLogFile
        )

        $jobs += $job
        Write-Log "Started job (PowerShell Job ID: $($job.Id)) for file: $SourcePcapPath" -Level Info
    }

    Monitor-ConversionJobs -Jobs $jobs -IntervalSeconds 10

    # Wait for all jobs to complete
    $jobs | Wait-Job 

    Write-Log "All job(s) completed. Processing results..." -Level Info

    # Process job results
    $conversionResults = @()
    foreach ($job in $jobs) {
        Write-Log "Processing results for job $($job.Id)" -Level Info
        $jobOutput = Receive-Job -Job $job
        if ($jobOutput -and $jobOutput.Result) {
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
        } else {
            Write-Log "Job $($job.Id) did not produce any output" -Level Warning
        }
    }

    Write-Log "All job results processed. Validating outcomes..." -Level Info

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

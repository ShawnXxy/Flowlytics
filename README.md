# 🚀 Flowlytics

This PowerShell script provides a robust and flexible solution for converting PCAP (Packet Capture) files to CSV format, making network traffic analysis more accessible and manageable.

### 🙏 Acknowledgements

This project is inspired by the work of [qliu95114](https://github.com/qliu95114) in their [demystify](https://github.com/qliu95114/demystify) project, specifically the [tshark samples](https://github.com/qliu95114/demystify/blob/main/network/tshark_samples.md#sample-4---convert-pcap-to-csv-ingress-to-adx-kusto-to-analyze-trace-in-fast-fashion). We're grateful for their contribution to the network analysis community and for providing the inspiration for this tool.

## 📊 Convert Network Packet Captures to CSV with Ease!

- 📁 Convert single or multiple PCAP files
- 🗂️ Process entire folders of PCAP files
- 🚀 Multi-threaded conversion for improved performance
- 🔍 Automatic tshark detection
- 📈 Detailed logging with UTC timestamps and color-coded messages
- ✅ Built-in conversion validation

### 🛠️ Prerequisites

- Windows PowerShell
- Wireshark (with tshark) installed

### 🚀 Usage

**In order to run it without downloading the repository, you need to:**
1. Open Windows PowerShell ISE (in Administrator mode if possible)
1. Open a New Script window
1. Paste the following in the script window and run it:

    ```ps
    # GitHub raw content URL for the Convert-PcapToCsv.ps1 script
    $scriptUrl = "https://raw.githubusercontent.com/ShawnXxy/Flowlytics/main/Convert-PcapToCsv.ps1"
    
    # Temporary file path to store the downloaded script
    $tempScriptPath = Join-Path $env:TEMP "Convert-PcapToCsv.ps1"
    
    try {
        # Download the script
        Invoke-WebRequest -Uri $scriptUrl -OutFile $tempScriptPath
    
        # Check if the file was downloaded successfully
        if (Test-Path $tempScriptPath) {
            Write-Host "Script downloaded successfully."
    
            # Load the script into memory
            . $tempScriptPath
    
            # Call the Convert-PcapToCsv function
            $sourcePath = Read-Host "Enter the path to your PCAP file or folder containing PCAP files"
            $targetPath = Read-Host "Enter the target folder path (optional, press Enter to use default)"
    
            if ([string]::IsNullOrWhiteSpace($targetPath)) {
                Convert-PcapToCsv -SourcePath $sourcePath
            } else {
                Convert-PcapToCsv -SourcePath $sourcePath -TargetFolderPath $targetPath
            }
        } else {
            Write-Host "Failed to download the script."
        }
    } catch {
        Write-Host "An error occurred: $_"
    } finally {
        # Clean up: remove the temporary script file
        if (Test-Path $tempScriptPath) {
            Remove-Item $tempScriptPath
        }
    }
    
    # Keep the console window open
    Read-Host "Press Enter to exit"
    ```

Convert-PcapToCsv parallel version.

    ```
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
        }  -ThrottleLimit 4
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
    ```

### ⚠️ Limitations

- This script currently supports Windows OS only.
- Requires PowerShell and Wireshark (with tshark) to be installed on the system.

---

Happy packet analyzing! 📊🔍

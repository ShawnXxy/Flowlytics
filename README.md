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
                Convert-PcapToCsv -SourcePcapPaths $sourcePath
            } else {
                Convert-PcapToCsv -SourcePcapPaths $sourcePath -TargetFolderPath $targetPath
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


### ⚠️ Limitations

- This script currently supports Windows OS only.
- Requires PowerShell and Wireshark (with tshark) to be installed on the system.

---

Happy packet analyzing! 📊🔍

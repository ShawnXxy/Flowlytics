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

#### Example usage for multiple files
```
Convert-PcapToCsv -SourcePcapPaths @("C:\Users\xixia\Downloads\client_side1.pcap", "C:\Users\xixia\Downloads\client_side2.pcap") -TargetFolderPath "C:\Users\xixia\Downloads\ConvertedCSV"

#### Example usage for a source folder
``` 
Convert-PcapToCsv -SourceFolderPath "C:\Users\xixia\Downloads\PcapFiles" -TargetFolderPath "C:\Users\xixia\Downloads\ConvertedCSV"
```

### ⚠️ Limitations

- This script currently supports Windows OS only.
- Requires PowerShell and Wireshark (with tshark) to be installed on the system.

---

Happy packet analyzing! 📊🔍

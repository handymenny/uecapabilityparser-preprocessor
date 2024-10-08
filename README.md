# UE Capability Parser Pre Processor

UE Capability Parser Pre Processor is a tool that extracts from baseband logs or packet captures the messages used by uecapabilityparser, writing them into an "optimized pcap".<br>
Thus, it can be useful for reducing data size and converting non-compatible formats (such as PCAPNG) to compatible formats.<br>

## Description
The pre processing consists of two steps:

1. The input is converted to pcap.<br>
    a. For types `DLF, HDF, QMDL/QDML2 DIAG, SDM` baseband logs are converted to pcap by [scat](https://github.com/fgsect/scat).<br>
    b. For type `NSG JSON` the pcap header and the pcap packets are extracted from the json.<br>
    c. For types `PCAP, PCAPNG` nothing is done in this step.
2. The messages relevant for uecapabilityparser are extracted from the pcap (step 1). These messages are stored in an optimized pcap. This step uses tshark (part of Wireshark).

## Usage
1. Download the last archive from [release page](https://github.com/HandyMenny/uecapabilityparser-preprocessor/releases)
2. Decompress the archive
3. Open a terminal in the folder where the archive was extracted
4. If you're using Linux make the script executable:

    ````
    chmod +x preprocessor
    ````
5. Run the script:
    > **Note**<br>
    if you're using Windows Command Prompt (cmd) omit "./"
    ````
    ./preprocessor input.pcap
    ````
Instead of steps 3-5, you can drag & drop the input file onto preprocessor.bat (Windows) or preprocessor (Linux/Mac).

## Supported formats
| Type  | Formats |
| ------------- | ------------- |
| Baseband log  | DLF, HDF, QMDL/QDML2 DIAG, SDM, NSG JSON |
| Packet capture  | PCAP, PCAPNG  |

## Dependencies
- Python 3.7 or above
- [Scat](https://github.com/fgsect/scat)
- Tshark (part of Wireshark)


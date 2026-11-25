To run the R2 analysis on Linux:

    cd Assignment3_GitHub
    python3 r2_analysis.py

The program writes r2_analysis_output.txt. It needs the PcapTracesAssignment3
folder in the same directory.

To run the R1 analysis on the supplied fragmentation trace:

    python3 a3_analyzer.py PcapTracesAssignment3/traceroute-frag.pcap

The program writes analysis_output.txt. To choose another output file, add
-o and the output filename.

Python 3.8 or newer is required. Both programs use only Python standard
library modules. No packages need to be installed. R1 does not need
packet_struct.py.

The folder contains all supplied trace files, both Python programs, the R2
text analysis, and an extra PDF copy of the R2 analysis.

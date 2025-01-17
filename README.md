# Virus Total Report
Virus Total is an free online service that scans files and URLS using multiple antivirus engines to detect potential malware. Virus Total offers a [web-based GUI](https://www.virustotal.com/gui/home/upload), [VirusTotal CLI](https://github.com/VirusTotal/vt-cli), and [API](https://docs.virustotal.com/reference/overview).

Given an API key, `report_generator.py` uploads a file, then stores the scan and report results. In `reports/virus_total_data.csv`, there are links to the web-based GUI for each uploaded file. 

This repo could serve as a starting point for further development, or as a quick way to generate some reports and save the json data for future reference. 
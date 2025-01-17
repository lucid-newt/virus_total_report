# Virus Total Report
Virus Total is an free online service that scans files and URLS using multiple antivirus engines to detect potential malware. There is [web-based gui](https://www.virustotal.com/gui/home/upload), [VirusTotal CLI](https://github.com/VirusTotal/vt-cli), and [api access](https://docs.virustotal.com/reference/overview).

This repo uses the api to upload a file, store the scan result, and the report result. In `reports/virus_total_data.csv', there are links to the web-based gui for each uploaded file. 

This repo could serve as a starting point for further development, or as a quick way to generate some reports but save the json data. 
# Solution
## Export file
Export flag.docx from Wireshark 
```bash
Wireshark ->File ->Export Objects -> HTTP
```
## Crack the password 
```bash
office2john flag.docx > hash.txt
# remove name of file from hash.txt
.\hashcat.exe -m 9600 doc.txt rockyou.txt
```
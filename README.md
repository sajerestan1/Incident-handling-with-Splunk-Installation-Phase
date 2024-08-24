# Incident-handling-with-Splunk-Installation-Phase


## Project Report: Investigating the Cyber Attack on Wayne Enterprises

### 1. Overview

Wayne Enterprises recently experienced a significant cyber attack, during which attackers infiltrated the company's network, compromised their web server, and successfully defaced the website, http://www.imreallynotbatman.com. The site displayed a message, "YOUR SITE HAS BEEN DEFACED," along with the attackers' trademark. The organization engaged me as a Security Analyst to investigate the incident, identify the root cause, and trace all attacker activities within their network.

### 2. Installation Phase

![image](https://github.com/user-attachments/assets/af6fb92c-649b-4047-b21b-20966b5dc1e7)


In the aftermath of the exploitation phase, where we identified the webserver iamreallynotbatman.com being compromised via a brute-force attack, I focused on understanding the attacker’s next steps. The attacker had used a Python script to automate the brute-force attack, eventually gaining access to the server by finding the correct password. The IP address associated with the attack was also used to log in to the server.

This phase of the investigation concentrated on discovering any payloads or malicious programs uploaded to the server by the attacker. The attacker’s objective during this phase was likely to install a backdoor or some form of persistent application to maintain control over the compromised system.

### Task 6: Installation Phase

To kickstart this phase, I initiated an investigation by narrowing down any HTTP traffic directed towards our server (IP: 192.168.250.70) that included the term “.exe.” Although starting with a specific file extension may not always lead to concrete findings, it serves as a prudent initial step in the investigation.

Search Query:


index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe

![image](https://github.com/user-attachments/assets/de603dce-d1b8-4d4c-949f-6272acb0fd2d)


The search returned several fields of interest, including part_filename{}, which revealed two filenames: 3791.exe (an executable file) and agent.php (a PHP file). The next step was to determine whether any of these files originated from the IP addresses previously associated with the attack.

![image](https://github.com/user-attachments/assets/5551dead-cf7c-45f6-be4f-f3c6a9320ace)

By clicking on the file name 3791.exe, I added it to the search query and examined the c_ip field to identify the client IP address, which pointed to the attacker’s IP.

![image](https://github.com/user-attachments/assets/7629afa9-7cab-4553-8e67-248da53d0c96)

Search Query:

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "part_filename{}"="3791.exe"

Was this file executed on the server after being uploaded?

After confirming that 3791.exe was uploaded to the server, the next logical question was whether this file was executed on the server. To answer this, I narrowed down the search to logs from host-centric log sources.

Search Query:


index=botsv1 "3791.exe"

![image](https://github.com/user-attachments/assets/84a944d6-ae57-4c68-89bc-95a16313a94a)

This search led to the discovery of logs from various sources, including:

    Sysmon
    WinEventLog
    Fortigate_UTM

To verify the execution of the file, I leveraged Sysmon logs and specifically looked for EventCode=1, which tracks program execution.

Search Query:

index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1

![image](https://github.com/user-attachments/assets/d4867d50-6a23-4f0d-809f-2dc136fa88f9)

This query revealed that the file 3791.exe was indeed executed on the compromised server. To confirm this finding, I cross-referenced it with other host-centric log sources.

## Answering Key Questions:

 ### 1. What is the MD5 hash of the program 3791.exe?

 ![image](https://github.com/user-attachments/assets/33b8516f-acc7-472f-abc9-bf41e66c6595)

  Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0

  ### 2. Which user executed the program 3791.exe on the server?

  ![image](https://github.com/user-attachments/assets/2d04e7b3-8533-400c-b87e-419a814caa9d)

  Answer: NT AUTHORITY\IUSR

### 3. What other name is associated with this file (3791.exe) on VirusTotal?

![image](https://github.com/user-attachments/assets/6c24e7cf-76cc-48d3-a8ab-441318b0d65c)

  Answer: Answer : ab.exe 
  
  This step would involve searching the MD5 hash on VirusTotal to discover any other names or signatures associated with the file.

### 3. Conclusion

This personal project provided an in-depth analysis of a simulated cyber attack on Wayne Enterprises, allowing me to apply my skills in log analysis, search query creation, and attack investigation using Splunk. Through this investigation, I was able to uncover critical details about the attack, including the execution of a malicious executable file on the compromised server.

The findings reinforced the importance of implementing robust security measures, including strong passwords, continuous monitoring, and timely patching of vulnerabilities. By identifying the attacker’s actions at each phase of the attack, I gained valuable insights into the strategies and tools used by cybercriminals to compromise systems.

This project not only enhanced my technical skills but also highlighted the necessity of thorough log analysis in cybersecurity. It served as a practical experience in understanding attacker behavior, which is essential for anyone in the field of cybersecurity.


# Heartbreaker

## Briefing
Delicate situation alert! The customer has just been alerted about concerning reports indicating a potential breach of their database, with information allegedly being circulated on the darknet market. As the Incident Responder, it's your responsibility to get to the bottom of it. Your task is to conduct an investigation into an email received by one of their employees, comprehending the implications, and uncovering any possible connections to the data breach. Focus on examining the artifacts provided by the customer to identify significant events that have occurred on the victim's workstation.

## Evidence

 | Date	      | Time of the event | hostname    | event description                   | data source        |
 |------------|-------------------|-------------|-------------------------------------|--------------------|

---
## Files

- HeartBreaker.zip

## Questions

### Task 1
**The victim received an email from an unidentified sender. What email address was used for the suspicious email?**

### Task 2
**It appears there's a link within the email. Can you provide the complete URL where the malicious binary file was hosted?**

### Task 3
**The threat actor managed to identify the victim's AWS credentials. From which file type did the threat actor extract these credentials?**

### Task 4
**Provide the actual IAM credentials of the victim found within the artifacts.**

### Task 5
**When (UTC) was the malicious binary activated on the victim's workstation?**

### Task 6
**Following the download and execution of the binary file, the victim attempted to search for specific keywords on the internet. What were those keywords?**

### Task 7
**At what time (UTC) did the binary successfully send an identical malicious email from the victim's machine to all the contacts?**

### Task 8
**How many recipients were targeted by the distribution of the said email excluding the victim's email account?**

### Task 9
**Which legitimate program was utilized to obtain details regarding the domain controller?**

### Task 10
**Specify the domain (including sub-domain if applicable) that was used to download the tool for exfiltration.**

### Task 11
**The threat actor attempted to conceal the tool to elude suspicion. Can you specify the name of the folder used to store and hide the file transfer program?**

### Task 12
**Under which MITRE ATT&CK technique does the action described in question #11 fall?**

### Task 13
**Can you determine the minimum number of files that were compressed before they were extracted?**

### Task 14
**To exfiltrate data from the victim's workstation, the binary executed a command. Can you provide the complete command used for this action?**
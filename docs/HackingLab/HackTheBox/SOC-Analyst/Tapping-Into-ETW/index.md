---
title: "Tapping Into ETW"
authors: [asalucci]
tags: [HackTheBox, CTF, trustinveritas, alessandro]
published: 2025-04-06
categories: ["SOC", "Analyst", "Write", "Up", "HackTheBox"]
---

# Tapping Into ETW

## Detection Example 1: Detecting Strange Parent-Child Relationships

**Abnormal parent-child relationships among processes can be indicative of malicious activities**. In standard Windows environments, `certain processes never call or spawn others`. For example, it is **highly unlikely** to see "`calc.exe`" spawning "`cmd.exe`" in a normal Windows environment. Understanding these typical parent-child relationships can assist in detecting anomalies. Samir Bousseaden has shared an insightful mind map introducing common parent-child relationships, which can be referenced [here](https://twitter.com/SBousseaden/status/1195373669930983424).

![Common-Windows-Normal-Processes](img/Common-Windows-Normal-Processes.png)

### [SANS Hunt Evil Poster](https://sansorg.egnyte.com/dl/WFdH1hHnQI)

<iframe
  src="/pdfs/SANS_DFPS_FOR508_v4.11_0624.pdf"
  width="100%"
  height="700px"
  style={{ border: 'none' }}
>
  Dieses Dokument kann leider nicht angezeigt werden.
  <a href="/pdfs/SANS_DFPS_FOR508_v4.11_0624.pdf">PDF öffnen</a>
</iframe>

---

By utilizing `Process Hacker`, we can **explore parent-child relationships within Windows**. Sorting the processes by dropdowns in the Processes view reveals a hierarchical representation of the relationships.

![Process-Hacker-1](img/Process-Hacker-1.png)
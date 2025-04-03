---
slug: CrowdStrike-Falcon
title: CrowdStrike-Falcon-Überblick
authors: [asalucci]
tags: [SOC-Analyst, SOC, CrowdStrike, Falcon, EDR, trustinveritas, alessandro]
---

**CrowdStrike Falcon – Überblick**

`CrowdStrike Falcon` ist eine führende cloudbasierte Sicherheitsplattform, die primär als `Endpoint Detection & Response (EDR)`-Lösung bekannt ist. Falcon besteht aus einem `einzigen Agenten (Sensor)`, der auf Endgeräten wie Workstations und Servern installiert wird, und einer cloudbasierten Management-Konsole​.

Die Plattform verfolgt einen *„Platform“*-Ansatz:  
Sie kombiniert mehrere Sicherheitsfunktionen (Endpoint-Schutz, Threat Intelligence, IT-Schutz usw.) in `einer einheitlichen Lösung`​.  

Falcon wird oft als `AI-native SOC-Plattform` bezeichnet, da sie Künstliche Intelligenz und Machine Learning nutzt, um Bedrohungen in Echtzeit zu erkennen.

Ein **wichtiges Merkmal** ist die *Cloud-native* Architektur:  
Statt klassische On-Premises-Server zu betreiben, laufen Analyse und Speicherung der Telemetriedaten in der CrowdStrike-Cloud. Das ermöglicht eine `leichte Skalierbarkeit`, `zentralisierte Updates` und einen einheitlichen Blick auf alle Endpunkte​.
​
Die Lösung ist bei Unternehmen beliebt, weil sie mit einem leichten Agenten auskommt und für verteilte oder Remote-Infrastrukturen gut geeignet ist​

<!-- truncate -->

## Module/Funktionen von CrowdStrike Falcon
Die Falcon-Plattform umfasst verschiedene Module, die nahtlos zusammenarbeiten. Für Einsteiger sind besonders diese Komponenten relevant:

- **Next-Generation Antivirus (NGAV)**  
Falcon bietet klassischen Virenschutz auf modernem Niveau – signaturlos mit KI (Künstliche Intelligenz) / ML (Machine Learning), um sowohl bekannte Malware als auch unbekannte Bedrohungen zu blockieren​. Dieses Modul (`Falcon Prevent`) läuft ständig auf dem Endpunkt und verhindert viele Angriffe bereits präventiv.

- **Endpoint Detection & Response (EDR)**  
Das Herzstück ist die EDR-Funktion (`Falcon Insight`). Sie **überwacht kontinuierlich das Verhalten auf Endgeräten** – sammelt Daten zu laufenden Prozessen, Netzwerkverbindungen, Dateiänderungen etc. – und erkennt verdächtige Aktivitäten​. Wenn z.B. ein unbekannter Prozess im Speicher manipulative Aktionen ausführt, schlägt Falcon Alarm. Die EDR kann bei Erkennung *automatisiert reagieren*, etwa den betreffenden Endpunkt vom Netzwerk isolieren und das Sicherheitsteam alarmieren. Falcon behält also einen **detaillierten Verlaufsverlauf** aller Aktionen auf dem System bei, was für forensische Untersuchungen wichtig ist.

- **Extended Detection & Response (XDR)**  
Über die Endpunkte hinaus kann Falcon weitere Datenquellen einbeziehen (`Falcon XDR Modul`) – z.B. Logs von Firewalls, Cloud-Services oder Identity-Systemen – um einen ganzheitlichen Blick zu ermöglichen​. XDR erweitert EDR also auf die gesamte Umgebung und korreliert Ereignisse über verschiedene Quellen hinweg.

- **Threat Intelligence (`Falcon X`)**  
CrowdStrike integriert Bedrohungsinformationen aus seiner Threat Intelligence in die Plattform. Das bedeutet, erkannte Dateien oder IPs werden mit globalen Feeds abgeglichen. Im Alarmfall zeigt Falcon an, ob z.B. ein verdächtiger Hash zu einer bekannten Malwarefamilie oder APT-Kampagne gehört. Im oben genannten Beispiel (Alarm durch bekannten Hash) wurde die Erkennung durch **Falcon Intelligence Indikatoren** ausgelöst. Dieses Modul liefert Analysten **Kontext** (z.B. welcher Gegner könnte dahinterstecken, bekannte Taktiken der Gruppe usw.) und ergänzt so die Rohdaten mit wertvollem Wissen.

- **Incident Management**  
Falcon bietet Funktionen zur **Alarm- und Vorfallsbearbeitung** direkt in der Konsole. Warnmeldungen werden mit Status (neu, in Bearbeitung, eskaliert etc.) versehen, man kann Notizen hinzufügen, Zuweisungen an Analysten vornehmen und so den Workflow steuern. Dadurch wird Falcon quasi zum zentralen Ort, an dem ein SOC-Analyst seine Endpoint-bezogenen Incidents verwaltet.

- **Response- und Remediation-Funktionen**  
Über die Konsole können Analysten bei Bedarf **aktive Reaktionsmassnahmen** durchführen. Typische Aktionen sind: **System isolieren** (vom Netzwerk trennen), **bösartige Prozesse beenden**, **Dateien in Quarantäne schieben oder löschen**, **Speicherabbilder oder Dateien zur Analyse extrahieren**. Diese *Remote Response* ermöglicht es, schnell einzugreifen, ohne physischen Zugang zum Rechner. Falcon kann viele Schritte auch automatisch einleiten, z.B. ein infiziertes System sofort isolieren, um Ausbreitung zu verhindern​.

- **Weitere Module**  
CrowdStrike erweitert seine Plattform ständig. Es gibt z.B. `Falcon Complete` (ein Managed-EDR-Service, bei dem CrowdStrike-Analysten rund um die Uhr für den Kunden Alarme bearbeiten), `Falcon Discover` (IT-Hygiene wie Anwendungsinventar), `Falcon Identity Protection` (Schutz von Active Directory und Identitäten) u.v.m. Auch ein Log-Management/SIEM-ähnliches Modul namens `Falcon LogScale` (ehem. Humio) ist Teil der Plattform. All diese Komponenten werden über eine zentrale Cloud-Konsole verwaltet​, was den **Bedienungsaufwand reduziert**. SOC-Analysten müssen nicht zig Tools öffnen, sondern sehen in Falcon unterschiedliche Sicherheitsdaten vereinheitlicht.



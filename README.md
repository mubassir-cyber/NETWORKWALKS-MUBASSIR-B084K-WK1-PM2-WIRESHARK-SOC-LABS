# Wireshark SOC Labs: Network Traffic Analysis

Hands-on SOC analyst practice with Wireshark: finding attackers, reading plain-text traffic, spotting brute force and investigating a scam call.

> **Environment:** All work was done inside the provided Networkwalks virtual labs (Week 1 Extra Project, Batch B084). No real networks were tested or captured.

![Skill](https://img.shields.io/badge/Skill-Wireshark-blue) ![Skill](https://img.shields.io/badge/Skill-SOC%20Analysis-red) ![NetworkWalks](https://img.shields.io/badge/Networkwalks-B084-black)

---

## Project Overview

I investigated 6 live labs. Each lab gave a packet capture and 10 tasks. The goal was to use Wireshark display filters, Statistics, and Follow TCP Stream to answer SOC-style questions.

| # | Lab | Focus | Result |
|---|-----|-------|--------|
| 1 | Identify the Attacker's IP | SYN scan / port scan | 100/100 |
| 2 | Follow TCP Stream 1 | Plain-text office chat | 80/100 |
| 3 | Follow TCP Stream, Part 2 | Hidden data in HTTP pages | 100/100 |
| 4 | HTTP Plain Text Credentials | Credentials sent over HTTP | 100/100 |
| 5 | Catch the Brute Force Attacker | Repeated login attempts | 100/100 |
| 6 | Catch the Call Scammer | VoIP / SIP / RTP call replay | 100/100 |

*(Update the Result column with your final scores.)*

---

## Lab 1: Identify the Attacker's IP

**Scenario:** Find the machine scanning the network.

**Key filters used**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0      # only packets that start a TCP connection
ip.src == <attacker> && tcp.flags.syn == 1    # SYNs from the suspect
ip.src == <target> && tcp.flags.syn == 1 && tcp.flags.ack == 1   # open ports (SYN, ACK)
ip.src == <target> && tcp.flags.reset == 1    # closed ports (RST, ACK)
```

**Method**
1. Filtered for SYN-only packets.
2. Used **Statistics > Conversations > IPv4** to find the IP sending the long block of SYNs.
3. Checked the Info column: one source port stayed constant while the destination port changed.
4. Open ports answered with `SYN, ACK`; closed ports answered with `RST, ACK`.

**Findings**
- Attack type: **TCP SYN port scan** (reconnaissance, MITRE T1046)
- Attacker IP: `<lab IP>`
- Target IP: `<lab IP>`
- Open ports: `<ports>`
- Closed ports: `<count>`

![Screenshot](screenshots/lab1.png)

---

## Lab 2: Follow TCP Stream 1

**Scenario:** Staff use an old office chat tool that sends messages in plain text.

**Method**
1. **Statistics > Conversations > TCP** to find the one non-web port (not 80/443).
2. `tcp.port == <port>` and checked the first SYN to see who started the chat.
3. Right-click a data packet > **Follow > TCP Stream** to read the conversation.

**Findings**
- Chat port: `<port>`
- Client started the chat; client text is **red**, server text is **blue**
- Sensitive data (passwords) was readable in plain text: `[redacted]`

**Lesson:** Use encrypted tools (TLS/HTTPS). Never send passwords in clear text.

![Screenshot](screenshots/lab2.png)

---

## Lab 3: Follow TCP Stream, Part 2

**Scenario:** An admin says one intranet page has a hidden note.

**Key filters used**
```
http.request.method == "GET"
ip.addr == <staff PC> && http
```

**Method**
1. Listed the pages the staff PC requested.
2. Followed each response with **Follow > HTTP Stream**.
3. Found the hidden text inside an **HTML comment** (`<!-- ... -->`). Browsers do not show comments, but they are visible in the packet bytes.

**Findings:** `<page name>`, `<what was hidden>`

![Screenshot](screenshots/lab3.png)

---

## Lab 4: HTTP Plain Text Credentials

**Key filters used**
```
http.request.method == "POST"
```

**Method:** Filtered for POST requests, opened the login request, and read the form fields in the packet details (HTML Form URL Encoded).

**Findings:** Login page `<page>`, number of attempts `<n>`, credentials `[redacted]`

**Lesson:** Login forms must use HTTPS.

![Screenshot](screenshots/lab4.png)

---

## Lab 5: Catch the Brute Force Attacker

**Method:** Looked for one source sending many login attempts to the same service, counted failures, and found the one success.

**Findings:** Protocol `<protocol>`, attacker `<lab IP>`, target `<lab IP>`, failed logins `<n>`, failure code `<code>`, success code `<code>`

**Lesson:** Use account lockout, rate limiting, MFA and strong passwords.

![Screenshot](screenshots/lab5.png)

---

## Lab 6: Catch the Call Scammer

**Key filters used**
```
sip
rtp
```

**Method:** Used **Telephony > VoIP Calls** to find the call, read the SIP INVITE for caller details and codec, and played the call with **Play Streams**.

**Findings:** Setup protocol SIP, voice protocol RTP, codec `<codec>`, scam type `<type>`

**Lesson:** Never share card numbers or codes by phone. Verify callers through official channels.

![Screenshot](screenshots/lab6.png)

---

## Troubleshooting Experience

**Problem:** I tried to search packet contents with `frame contains "<!--"` and got the error *"frame is a protocol, not a field: it cannot be compared with a value."* Other variants also failed.

**Solution:** I stopped fighting the filter and used Wireshark's other tools instead:
1. Followed each page's response with **Follow > HTTP Stream** and read the content.
2. Used **Ctrl+F** with **Packet bytes** and **String** to search for `<!--`.
3. Compared response sizes in the packet list. The page with the hidden note was larger than the others.

**Lesson:** Display-filter syntax differs between Wireshark versions. If a filter is rejected, use Find (Ctrl+F), Follow Stream, or Export Objects.

---

## Skills Practised
Wireshark display filters, Statistics (Conversations/Endpoints), Follow TCP/HTTP Stream, port-scan detection, plain-text credential analysis, brute-force detection, VoIP analysis.

## Tools
Wireshark, Networkwalks browser labs

---

**Author:** Mubassir
**Program:** Networkwalks Cybersecurity Internship (Batch B084), Week 1 Extra Project
**Instructor:** Waqas Karim CCIE

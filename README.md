# SCANNING
SCANNING WEEK 7

## Question 1: Analyse packet1.pcap and find the flag

### 🔍 Step 1: Identify Protocol
Open `packet1.pcap` in Wireshark to examine the captured traffic.

<img width="1919" height="934" alt="image" src="https://github.com/user-attachments/assets/2ef9f122-791f-469d-b035-6e05c90f9968" />

🧠 Analysis Insight:
- The traffic is dominated by **ICMP Echo Request/Reply** packets exchanged between `172.24.20.31` and `171.64.20.62`.
- All packets are uniform at **98 bytes**, which helps identify the anomalous packet carrying the hidden payload.

### 🔍 Step 2: Apply ICMP Filter
Apply the display filter `icmp` in Wireshark to isolate only ICMP traffic.

<img width="1915" height="726" alt="image" src="https://github.com/user-attachments/assets/93f78ca2-8440-43ba-a8c3-2f135824c501" />

🧠 Analysis Insight:
- All packets are ICMP Echo Request/Reply pairs.
- One packet **(No. 37)** stands out at only **70 bytes**, indicating it carries a suspicious and different payload compared to the rest.

### 🔍 Step 3: Extract ICMP Payload
Using `tshark` to extract the raw ICMP data field in hexadecimal:

```bash
tshark -r packet1.pcap -Y icmp -T fields -e data
```

<img width="697" height="698" alt="image" src="https://github.com/user-attachments/assets/839e8e12-5c55-4c98-8845-35fef4363f45" />

🧠 Analysis Insight:
- The output is filled with repeated identical filler data.
- One unique line stands out near the bottom:
> `55315644564559794d44497a6532467058326c7a58324e7662327839`
- This suspicious string is hidden within the ICMP payload and indicates encoded data.

### 🔍 Step 4: Confirm Unique Payload
Pipe the output through `sort | uniq` to isolate unique values:

```bash
tshark -r packet1.pcap -Y icmp -T fields -e data | sort | uniq
```

<img width="661" height="82" alt="image" src="https://github.com/user-attachments/assets/86ef90e1-97c3-4a81-a016-dabb42b89019" />

🧠 Analysis Insight:
- Only **2 unique hex strings** exist in the capture — the repeated filler and the hidden payload.
- This confirms the unique string is intentionally embedded data, not random noise.

### 🔓 Step 5: Decode Hex → Base64
Decode the hex string to reveal the intermediate encoding:

```bash
echo "55315644564559794d44497a6532467058326c7a58324e7662327839" | python3 -c "import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode())"
```

<img width="818" height="69" alt="image" src="https://github.com/user-attachments/assets/fd033b4a-cc13-479b-a61d-7b55044fee17" />

> Output: `U1VDVEYyMDIze2FpX2lzX2Nvb2x9`
- The output contains only `A–Z`, `a–z`, `0–9` characters — confirming it is **Base64 encoded**.

### 🔓 Step 6: Decode Base64 → Flag
Final decoding step to reveal the flag:

```bash
echo "U1VDVEYyMDIze2FpX2lzX2Nvb2x9" | base64 -d
```

<img width="443" height="58" alt="image" src="https://github.com/user-attachments/assets/479ca966-ef71-4d48-91ce-7e5e4f902093" />

> ✅ Flag: `SUCTF2023{ai_is_cool}`

📡 Q1 Summary:
| Step | Action | Result |
| ---- | ------------------- | ------------------------- |
| 1 | Open pcap in Wireshark | ICMP traffic identified |
| 2 | Apply ICMP filter | Anomalous 70-byte packet found |
| 3 | Extract payload with tshark | Unique hex string detected |
| 4 | Sort and uniq | Confirmed 1 unique hidden string |
| 5 | Decode Hex | Base64 intermediate string |
| 6 | Decode Base64 | ✅ `SUCTF2023{ai_is_cool}` |

## Question 2: Analyse packet2.pcap and find the flag

### 🔍 Step 1: Examine Overall Traffic
Open `packet2.pcap` in Wireshark to examine the captured traffic.

<img width="1913" height="931" alt="image" src="https://github.com/user-attachments/assets/6d4fbc35-68be-4fe9-918e-7f36efa9f22d" />

🧠 Analysis Insight:
- The capture contains a mix of **ICMP** and **TCP** traffic.
- Multiple TCP streams are present across different ports, suggesting various communication channels worth investigating.

### 🔍 Step 2: Check ICMP Payloads
Extract and sort ICMP payloads to check for hidden data:

```bash
tshark -r packet2.pcap -Y icmp -T fields -e data | sort | uniq -c
```

<img width="742" height="63" alt="image" src="https://github.com/user-attachments/assets/0cd8fdcc-e25e-4c4b-b817-0d691b24fa93" />

🧠 Analysis Insight:
- All **668 ICMP packets** carry the exact same filler payload.
- No unique strings found → **ICMP is just noise. Ignore it.**

### 🔍 Step 3: Investigate TCP Port 4444
Extract data from the suspicious port 4444:

```bash
tshark -r packet2.pcap -Y "tcp.port==4444" -T fields -e data | sort | uniq
```

<img width="642" height="110" alt="image" src="https://github.com/user-attachments/assets/fdc5c526-f23d-47fe-ab81-29d96a91f3c0" />

🧠 Analysis Insight:
- Three unique hex strings were found. Decoding them reveals:

```bash
python3 -c "
strings = ['41726520796f75206120726f626f743f0a', '48656c6c6f0a', '486f772061726520796f753f0a']
for s in strings:
    print(bytes.fromhex(s).decode())
"
```

<img width="789" height="200" alt="image" src="https://github.com/user-attachments/assets/f0b01663-fafe-45fe-9581-9a38563115b0" />

> Output: `Hello`, `How are you?`, `Are you a robot?`
- This is just a normal conversation — **not the flag**. Port 4444 is a dead end.

### 🔍 Step 4: Follow TCP Streams in Wireshark
Right-click any TCP packet → **Follow → TCP Stream** and cycle through streams 0 to 10.

<img width="920" height="166" alt="image" src="https://github.com/user-attachments/assets/5c45dc40-7498-48aa-82c1-647d1a8787be" />

Stream 0:
<img width="1919" height="865" alt="image" src="https://github.com/user-attachments/assets/04ad8319-108c-4142-9301-7adf7c38687b" />

Stream 1:
<img width="1919" height="877" alt="image" src="https://github.com/user-attachments/assets/a41e48b6-d4bb-4e61-86c1-2b76f158743c" />

Stream 2:
<img width="1919" height="869" alt="image" src="https://github.com/user-attachments/assets/f19271db-c194-4280-901e-70734d8f1349" />

Stream 3:
<img width="1919" height="874" alt="image" src="https://github.com/user-attachments/assets/3401702c-206d-4cf6-909f-9f743e9237e7" />

Stream 4:
<img width="1919" height="881" alt="image" src="https://github.com/user-attachments/assets/6d88f007-9af3-4466-b541-215faff8aa7f" />

Stream 5:
<img width="1919" height="882" alt="image" src="https://github.com/user-attachments/assets/e70444e4-6882-467c-ba91-f70df44e484e" />

Stream 6:
<img width="1919" height="881" alt="image" src="https://github.com/user-attachments/assets/ea69d7d0-8cec-42c3-a481-0010bd3e8248" />

Stream 7:
<img width="1919" height="876" alt="image" src="https://github.com/user-attachments/assets/c4b475ef-e5a0-455d-bdfb-f1dc7ec052a8" />

🧠 Conclusion:
| Stream | Content |
|--------|---------|
| 0 | Greeting conversation (Hello, How are you, Are you a robot?) |
| 1 | FTP login session (anonymous login) |
| 2 | ⚠️ Hidden URL: `https://tinyurl.com/yr5zprz4` |
| 3 | "Did you ever play tic-tac-toe?" |
| 4 | "Yeah. Of course." |
| 5 | "But you don't play anymore?" |
| 6 | "No" |
| 7 | "Why?" |

### 🔍 Step 5: Find the Hidden URL
Stream 2 contains a plaintext URL — opening it reveals a tic-tac-toe cipher image.
https://tinyurl.com/yr5zprz4
<img width="1919" height="997" alt="image" src="https://github.com/user-attachments/assets/cf2874d4-1b1e-48a6-85e9-3693f055127b" />

🧠 Analysis Insight:
- The image contains **grid-like symbols** resembling a tic-tac-toe board.
- The ongoing conversation in the TCP streams about tic-tac-toe is a **hint** pointing to the cipher type used.

### 🔓 Step 6: Decode the Tic-Tac-Toe Cipher
Using the online decoder at [dcode.fr – Tic Tac Toe Cipher](https://www.dcode.fr/tic-tac-toe-cipher), input the symbols from the image exactly as they appear.

<img width="1045" height="940" alt="image" src="https://github.com/user-attachments/assets/3f4099e5-f8b4-4e5d-919f-9f394f2882c5" />

> ✅ Result: `EXMACHINAAVA`
> `This is a reference to the AI character Ava from the film Ex Machina.`

🌐 Q2 Summary:
| Step | Action | Result |
|------|--------|--------|
| 1 | Open pcap in Wireshark | Mixed ICMP + TCP traffic |
| 2 | Check ICMP payloads | All filler — noise, ignored |
| 3 | Analyse TCP port 4444 | Normal conversation, not the flag |
| 4 | Follow TCP streams 0–7 | Hidden URL found in Stream 2 |
| 5 | Open the URL | Tic-tac-toe cipher image found |
| 6 | Decode cipher on dcode.fr | ✅ `EXMACHINAAVA` |

## Question 3: Interpret an Nmap Output

| Port      | State | Service         | Version                                                  |
|-----------|-------|-----------------|----------------------------------------------------------|
| 21/tcp    | Open  | FTP             | vsftpd 2.3.4                                             |
| 22/tcp    | Open  | SSH             | OpenSSH 5.3p1                                            |
| 80/tcp    | Open  | HTTP            | Apache 2.2.8                                             |
| 139/tcp   | Open  | NetBIOS-ssn     |                                                          |
| 445/tcp   | Open  | microsoft-ds    | Windows 7 Professional 7601 Service Pack 1               |

---

**1. What can an attacker do with each port?**

| Port | Service       | Attacker Capability                                                  |
|------|---------------|----------------------------------------------------------------------|
| 21   | FTP (vsftpd)  | Log in anonymously, upload or download files, trigger backdoor shell |
| 22   | SSH           | Attempt brute-force attacks, gain remote shell if weak credentials   |
| 80   | HTTP (Apache) | Launch web-based attacks such as SQLi, XSS, or path traversal       |
| 139  | NetBIOS       | Gather network info, enumerate shares and usernames                  |
| 445  | SMB           | Access file shares, exploit critical SMB flaws like EternalBlue      |

---

**2. What vulnerabilities are likely present based on the version?**

| Service             | Vulnerability                                                                                                              |
|---------------------|----------------------------------------------------------------------------------------------------------------------------|
| vsftpd 2.3.4        | 🔥 **Backdoor vulnerability (CVE-2011-2523)** — sends root shell on port 6200 when triggered                             |
| OpenSSH 5.3p1       | Username enumeration, CVE-2016-0777, CVE-2016-0778, susceptible to brute-force due to weak encryption                     |
| Apache 2.2.8        | CVE-2011-3192 (DoS via Range Header), CVE-2007-5000 (XSS via mod_imagemap), CVE-2007-6203 (XSS on 413 error page)         |
| NetBIOS (139)       | Leaks system and network information to unauthenticated users                                                              |
| SMB (445) Windows 7 | 🔥 **MS17-010 EternalBlue (CVE-2017-0144)** — allows full remote code execution without credentials                      |

---

**3. Which one is the highest risk and why?**

The highest risk vulnerability is **EternalBlue (MS17-010)** targeting the SMB service on ports 139/445.

> Key reasons:
- **No credentials needed:** The attacker only needs network access to the target — no username or password required to exploit it.
- **Full system takeover:** A successful exploit immediately grants SYSTEM-level privileges, giving the attacker complete control over the machine.
- **Easy to execute:** Metasploit has a ready-made module for this exploit, making it accessible even to low-skilled attackers.
- **Self-spreading capability:** The exploit can be weaponized into a worm (as seen with WannaCry and NotPetya), rapidly spreading across an entire network without human interaction.

`While the vsftpd 2.3.4 backdoor is equally dangerous due to its instant root shell, EternalBlue is prioritized as the highest risk because it targets Windows SMB which is far more common in enterprise environments.`

---

**4. What attack path can be built from this?**

> A realistic attack scenario would unfold as follows:

1. **Reconnaissance:** The attacker performs an Nmap scan, discovers open ports 21, 22, 80, 139, and 445, and identifies outdated software versions running on the target.
2. **Exploitation via EternalBlue:** Using Metasploit's `exploit/windows/smb/ms17_010_eternalblue` module, the attacker targets port 445 with a reverse shell payload and gains SYSTEM-level access.
3. **Foothold Established:** A Meterpreter session is opened, giving the attacker full interactive control over the compromised Windows host.
4. **Post-Exploitation:**
   - **Credential Dumping:** Tools like Mimikatz are used to extract stored passwords and hashes from memory.
   - **Lateral Movement:** The attacker uses harvested credentials to move across other machines in the network via SMB.
   - **Persistence:** Backdoors and scheduled tasks are planted to maintain access even after reboots.
   - **Data Exfiltration:** Sensitive files including databases and config files are located and stolen.
5. **Fallback via FTP Backdoor:** If SMB is unavailable, the attacker connects to port 21, sends a username containing `:)` to trigger CVE-2011-2523, and receives a root shell on port 6200.

---

**5. What should be the remediation?**

> Recommended fixes in order of urgency:

1. **Patch SMB Immediately:**
   - Apply Microsoft's MS17-010 security bulletin patch without delay.
   - Permanently disable SMBv1 across all systems as it is an outdated and insecure protocol.

2. **Replace vsftpd 2.3.4:**
   - Remove the backdoored version immediately and reinstall from a verified, trusted source.

3. **Upgrade Apache:**
   - Move from version 2.2.8 to the latest Apache 2.4.x release to eliminate multiple known CVEs.

4. **Update OpenSSH:**
   - Upgrade to OpenSSH 9.x or later to fix enumeration vulnerabilities and strengthen encryption standards.

5. **General Security Hardening:**
   - **Firewall Rules:** Block ports 139 and 445 from external access and restrict them to trusted hosts only.
   - **Network Segmentation:** Isolate exposed services in a DMZ to limit the blast radius of any breach.
   - **Regular Patching:** Establish a patch management process to ensure no service runs an outdated version.
   - **OS Upgrade:** Retire Windows 7 immediately as it is end-of-life and no longer receives security updates from Microsoft.

## Question 4: Identify the OS (OS Fingerprinting) - TTL

🧠 TTL Quick Reference:
| TTL | OS |
|-----|----|
| TTL ≈ 64 | Linux / Unix |
| TTL ≈ 128 | Windows |
| TTL ≈ 255 | Network Devices (Cisco Router / Switch) |

---

**Image 1:**

<img width="472" height="213" alt="image" src="https://github.com/user-attachments/assets/ddd70204-d862-4823-960a-7a32eb07c576" />

**Answer:**
> `ping localhost` → TTL=128
- **OS: Microsoft Windows**
- Reason: Windows operating systems (Windows XP through Windows 10/11) use an initial TTL of **128** by default. Since we are pinging localhost on a Windows machine, the TTL value is exactly 128 with no hops reducing it.

---

**Image 2:**

<img width="497" height="165" alt="image" src="https://github.com/user-attachments/assets/ae430bbb-27b5-41ec-bc55-569ef99ede7f" />

**Answer:**
> `ping 8.8.8.8` → TTL=114
- **OS: Linux-based server (Google DNS)**
- Reason: The original TTL started at **128** (Windows) but was reduced to 114 after passing through multiple network hops between the source and Google's DNS server at 8.8.8.8. Each router hop decrements the TTL by 1, meaning approximately **14 hops** were traversed to reach the destination.

---

**Image 3:**

<img width="493" height="213" alt="image" src="https://github.com/user-attachments/assets/3ae7da58-ad3d-4cb2-a0ac-9886fe01e556" />

**Answer:**
> `ping -c5 localhost` → TTL=64
- **OS: Linux / Unix-based system**
- Reason: Initial TTL of **64** is the default for most Linux distributions, BSD, and macOS. Since this is pinged from a Kali Linux machine to localhost, the TTL remains at exactly 64 with no hops reducing it.

🧠 TTL Quick Reference:
TTL ≈ 64 → Linux / Unix
TTL ≈ 128 → Windows
TTL ≈ 255 → Network Devices (Cisco Router / Switch)

## Question 5: Analyse the Nessus File

Upload the `Network_Scan.nessus` file into Nessus and analyse the findings,
focusing on the critical vulnerability named **"Ghostcat"**.

<img width="1729" height="718" alt="image" src="https://github.com/user-attachments/assets/5a3188c0-fecc-4593-8c7a-3e3fb0d8387e" />

🧠 Analysis Insight:
- The Nessus scan was conducted against host `192.168.232.139`.
- Multiple vulnerabilities were detected across different severity levels.
- The most critical finding is the **Apache Tomcat AJP Connector vulnerability**
known as Ghostcat, which stands out due to its extremely high CVSS score.

---

<img width="1919" height="759" alt="image" src="https://github.com/user-attachments/assets/3f1df898-234c-43ed-84a2-135438e41406" />

🧠 Analysis Insight:
- Navigating into the scan results reveals the Ghostcat finding listed under
critical severity.
- The affected service is running on **port 8009** using the **AJP13 protocol**,
which is used for internal communication between a web server and Apache Tomcat.
- The vulnerability allows a remote unauthenticated attacker to read sensitive
files from the server or potentially achieve Remote Code Execution (RCE) if
file upload is enabled.

---

<img width="1919" height="621" alt="image" src="https://github.com/user-attachments/assets/863b6e68-1e88-4884-98ee-96ef1e15cb56" />

🧠 Analysis Insight:
- The full vulnerability detail confirms all key information about Ghostcat.
- Nessus was able to successfully exploit the vulnerability and read the
contents of `/WEB-INF/web.xml`, proving the system is actively vulnerable.

---

**1. What is the affected Port number?**

➡️ **8009**
- Port 8009 is the default port for the AJP connector in Apache Tomcat.
- It is intended for internal use only but was left exposed to the network,
making it accessible to external attackers.

---

**2. What is the affected protocol?**

➡️ **AJP (Apache JServ Protocol) — specifically AJP13**
- AJP is a binary protocol used for communication between a front-end web
server such as Apache HTTPD and a backend Java servlet container like Tomcat.
- When left unauthenticated and exposed, AJP becomes a critical attack surface.

---

**3. What is the CVSS Score of the vulnerability found?**

➡️ **CVSS Score: 9.8 (Critical)**

This score is extremely high due to the following factors:
- **Remote exploitation** — No physical access required, attackable over the network.
- **No authentication needed** — Any unauthenticated user can trigger the exploit.
- **High impact** — Can lead to sensitive file disclosure or full Remote Code
Execution (RCE) depending on server configuration.

---

**4. Can you find any exploit related to this vulnerability?**

➡️ **YES — Multiple exploits exist**

- **Metasploit module:**
```bash
auxiliary/admin/http/tomcat_ghostcat
```
- Public Python-based PoC scripts are available on GitHub.

What an attacker can do:
- Read sensitive configuration files such as `/WEB-INF/web.xml`
- Upload a malicious JSP file to achieve full **Remote Code Execution**
- Extract credentials, database configs, and application secrets

---

**5. Find the CVE for this vulnerability.**

➡️ **CVE-2020-1938**
- Official name: Apache Tomcat AJP File Read/Inclusion Vulnerability
- Nickname: **Ghostcat**
- Affects Apache Tomcat versions before 7.0.100, 8.5.51, and 9.0.31.

💡 Summary:
| Item       | Answer                         |
|------------|--------------------------------|
| Port       | 8009                           |
| Protocol   | AJP (AJP13)                    |
| CVSS Score | 9.8 (Critical)                 |
| Exploit    | Yes — Metasploit & public PoC  |
| CVE        | CVE-2020-1938                  |

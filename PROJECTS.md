🎯 PROJECT: SOC Investigation Assistant
Tujuan utamanya
Ketika SIEM menghasilkan security alert, sistem secara otomatis:
mengumpulkan → mengkorelasi → memperkaya → menyusun timeline → merangkum → menyajikan evidence
supaya analyst nggak perlu melakukan pekerjaan data-gathering yang repetitif dari nol.
Tetapi:
TP / FP / escalation / final response tetap menjadi keputusan analyst.
Jadi automation kita berhenti pada evidence + analysis + recommendation, bukan mengambil alih analyst.
1. Konsep besarnya
Target akhirnya:
                    ┌──────────────────────┐
                    │       ENDPOINT       │
                    │ Linux / Windows      │
                    │ SSH / PowerShell etc │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │        WAZUH         │
                    │ SIEM / Detection     │
                    └──────────┬───────────┘
                               │
                         Security Alert
                               │
                               ▼
                    ┌──────────────────────┐
                    │         n8n          │
                    │   Investigation      │
                    │    Orchestrator      │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        Event Correlation   Threat Intel    Asset Context
              │                │                │
              │          ┌─────┴──────┐         │
              │          │            │         │
              │       VirusTotal   AbuseIPDB    │
              │                                   │
              └────────────────┬──────────────────┘
                               ▼
                       Evidence Normalization
                               │
                               ▼
                        Timeline Builder
                               │
                               ▼
                        Evidence Package
                               │
                               ▼
                     ┌────────────────────┐
                     │    LLM ANALYSIS    │
                     │ Gemini / OpenRouter│
                     │ / Ollama           │
                     └─────────┬──────────┘
                               │
                               ▼
                       Investigation Report
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
              Gmail         Discord        Telegram
                              │
                              ▼
                       HUMAN ANALYST
                              │
                     ┌────────┼────────┐
                     ▼        ▼        ▼
                    TP       FP     ESCALATE
Itu north star architecture kita.
2. Pembagian tanggung jawab
Ini harus jelas dari awal.
Wazuh
Tugasnya:
Detection
Rule matching
Alert generation
Event collection
Event storage/indexing
Wazuh adalah source of security events.
n8n
Tugasnya:
Orchestration
Correlation
Data gathering
Threat-intel enrichment
Timeline construction
Routing
Notification
Case management
n8n adalah automation engine.
LLM
Tugasnya:
Summarization
Evidence interpretation
Natural-language explanation
Pattern synthesis
Recommended investigation steps
Report generation
LLM bukan source of truth.
Analyst
Tugasnya:
Validate evidence
Perform deeper investigation
Decide TP / FP
Decide escalation
Authorize response
3. Deployment architecture
Karena device lu ngelag kalau Docker jalan, n8n langsung di VPS.
Gue desain seperti ini:
                  INTERNET
                     │
                     ▼
            ┌─────────────────┐
            │   n8n VPS       │
            │                 │
            │ Ubuntu          │
            │ Docker          │
            │ n8n             │
            │ 2 vCPU / 2 GB   │
            └────────┬────────┘
                     │
       ┌─────────────┼─────────────┐
       │             │             │
       ▼             ▼             ▼
    Wazuh API     Gemini/API   Threat Intel
Jangan taruh Wazuh full stack di VM n8n kecil.
Wazuh dan n8n kita anggap sebagai dua environment berbeda.
Contohnya:
Wazuh environment
      │
      │ webhook
      ▼
AWS/VPS n8n
      │
      ├── Gemini
      ├── VirusTotal
      ├── AbuseIPDB
      ├── Gmail
      └── Database
4. LLM layer harus modular
Jangan hard-code workflow ke Gemini.
Kita desain:
                   n8n
                    │
              AI Analysis
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
    Gemini      OpenRouter     Ollama
V1
Pakai API.
Gue lebih prefer:
Gemini API
atau
OpenRouter
supaya kita fokus ke automation.
V2
Baru eksperimen:
Ollama
Kalau mau menguji local inference, bisa dilakukan terpisah lewat machine/Colab/Kaggle.
Jadi LLM hanyalah plug-in.
5. WORKFLOW 01 — Alert Intake
Ini pintu masuk.
Wazuh
 ↓
Webhook
 ↓
Authentication
 ↓
Payload validation
 ↓
Normalize
 ↓
Generate Incident ID
 ↓
Extract basic fields
 ↓
Continue
Contoh output internal:
{
  "incident_id": "INC-20261001-0001",
  "timestamp": "...",
  "rule_id": "5710",
  "rule_level": 10,
  "rule_description": "...",
  "agent_id": "001",
  "agent_name": "linux-server",
  "src_ip": "185.x.x.x",
  "dst_ip": "10.0.0.15",
  "dst_user": "root"
}
Kenapa normalize?
Karena semua workflow selanjutnya jangan bekerja dengan JSON Wazuh mentah.
Semua memakai schema milik kita.
6. WORKFLOW 02 — Deduplication
Ini penting banget.
Misalnya attacker melakukan:
200 failed SSH login
Wazuh bisa menghasilkan banyak alert.
Kita nggak mau:
200 alerts
↓
200 investigation
↓
200 email
Kita mau:
200 related alerts
↓
1 incident
↓
1 investigation
Key-nya bisa berupa kombinasi:
source IP
+
destination host
+
rule
+
time window
Misalnya:
185.x.x.x
+
server01
+
SSH brute force
+
15 minutes
→ satu incident.
7. WORKFLOW 03 — IOC Extraction
Kita extract semua observable.
IP
Domain
URL
Hash
Username
Hostname
File path
Process
Command
Destination
Contoh:
PRIMARY IOC

Source IP
185.x.x.x
Lalu:
RELATED IOC

Domain
evil-example.com

URL
https://evil-example.com/payload.sh

SHA256
abc123...

Process
/tmp/payload.sh
Tapi nggak semua observable langsung dianggap relevant.
Ini akan diputuskan oleh correlation layer.
8. WORKFLOW 04 — Automated Correlation
INI JANTUNG PROJECT KITA.
Tujuan lu tadi:
“gue nggak mau bolak-balik query terus.”
Nah, inilah bagian yang mengerjakan itu.
Misalnya alert:
Source IP = 185.x.x.x
Host = server01
Time = 03:14:22
User = root
Automation otomatis mencari:
A. Same source IP
source.ip == 185.x.x.x
B. Same host
host == server01
C. Same user
user == root
D. Temporal relation
T-15 minutes
       ↓
ALERT
       ↓
T+15 minutes
E. Related activity
authentication
process
file
network
privilege
persistence
9. Correlation jangan cuma berdasarkan “sama IP”
Ini penting.
Misalnya:
185.x.x.x
muncul 1000 kali.
Belum tentu semuanya relevan.
Kita gunakan beberapa pivot:
same source IP
same destination
same username
same process
same file
same parent process
same hash
same destination
same time window
Kemudian tiap event disimpan dengan:
relationship
reason
timestamp
source
Contoh:
{
  "event": "...",
  "related_because": [
    "same_source_ip",
    "within_5_minutes",
    "same_target_host"
  ]
}
Ini penting karena nanti analyst bisa tahu kenapa suatu event dimasukkan ke incident.
10. Event filtering
Misalnya Wazuh menemukan:
500 events
Jangan langsung kirim semua ke AI.
Pipeline:
500 raw events
       ↓
filter irrelevant
       ↓
120 candidate events
       ↓
deduplicate
       ↓
35 significant events
       ↓
timeline
       ↓
AI
Jadi AI tidak dibebani noise.
11. WORKFLOW 05 — Threat Intelligence
Setelah IOC extraction:
IP
 ↓
VirusTotal
 ↓
AbuseIPDB
Domain:
Domain
 ↓
VT / other reputation
Hash:
Hash
 ↓
VirusTotal
Output normalized:
{
  "indicator": "185.x.x.x",
  "type": "ipv4",
  "sources": {
    "virustotal": {
      "malicious": 12,
      "suspicious": 3
    },
    "abuseipdb": {
      "confidence": 92
    }
  }
}
Dan kita simpan:
source
timestamp
result
Jadi provenance tetap jelas.
12. WORKFLOW 06 — Asset Context
Selain attacker, kita juga perlu memahami victim.
Misalnya:
Host:
server01

OS:
Ubuntu

Environment:
Production

IP:
10.0.0.15

User:
root
Nanti risk context bisa berbeda antara:
Developer laptop
dan:
Production server
13. WORKFLOW 07 — Timeline Builder
Semua hasil correlation dimasukkan ke timeline.
Contoh:
03:10:00
Normal activity

03:13:40
Failed authentication #1

03:13:41
Failed authentication #2

03:14:10
47 authentication failures

03:15:03
Successful authentication

03:15:21
sudo executed

03:15:49
wget executed

03:16:04
Cron modified

03:16:30
Outbound connection
Timeline ini akan menjadi core evidence.
14. WORKFLOW 08 — Evidence Normalization
Sebelum AI:
Wazuh Alert
+
Related Events
+
IOC
+
Threat Intel
+
Asset Context
+
Timeline
+
Rule Information
digabung jadi satu object:
{
  "incident": {},
  "alert": {},
  "asset": {},
  "iocs": [],
  "related_events": [],
  "threat_intel": [],
  "timeline": [],
  "risk_context": {}
}
Ini yang masuk ke LLM.
Bukan raw Wazuh JSON.
15. WORKFLOW 09 — AI Investigation
Prompt AI harus dibuat sangat constrained.
AI diminta:
Summarize incident
Identify observed behavior
Explain attack progression
Identify suspicious patterns
Map MITRE only where supported
Provide confidence
Recommend next investigation steps
Recommend containment considerations
Dan rules:
DO NOT invent facts
DO NOT invent IOC
DO NOT invent timestamps
DO NOT invent MITRE technique
DO NOT override threat-intelligence numbers
DISTINGUISH FACT FROM INFERENCE
Output:
{
  "summary": "...",
  "observed_behavior": [],
  "potential_attack_chain": [],
  "mitre": [],
  "confidence": 0,
  "recommended_investigation": [],
  "recommended_containment": []
}
16. Bedakan tiga kategori output AI
Ini gue mau banget diterapkan.
OBSERVED
47 failed SSH attempts
1 successful login
INFERRED
Activity may represent successful brute-force intrusion.
RECOMMENDED
Verify whether root authentication was authorized.
Jadi analyst bisa langsung melihat:
mana fakta, mana interpretasi, mana saran.
17. Deterministic risk score
Gue juga mau bikin:
Threat Score
tetapi bukan berasal dari LLM.
Misalnya:
Threat Intel
+
Wazuh severity
+
successful auth
+
post-auth behavior
+
asset criticality
dimasukkan ke formula kita sendiri.
Contoh konseptual:
base score
+ TI score
+ suspicious behavior
+ successful compromise indicator
+ critical asset modifier
Output:
Risk Score = 87/100
Risk Level = HIGH
AI hanya menjelaskan score tersebut.
18. WORKFLOW 10 — Investigation Report Generator
Sekarang kita punya:
Evidence
+
Timeline
+
TI
+
AI Analysis
+
Risk Score
kemudian dibentuk menjadi:
SOC INVESTIGATION REPORT
19. Format notification yang kita mau
Ketika analyst buka Telegram/Discord/email:
🚨 SOC INCIDENT

INC-20261001-0001
HIGH

━━━━━━━━━━━━━━━━━━
DETECTION
━━━━━━━━━━━━━━━━━━

Rule:
SSH Multiple Authentication Failures

Wazuh Level:
10

Host:
server01

User:
root

━━━━━━━━━━━━━━━━━━
PRIMARY IOC
━━━━━━━━━━━━━━━━━━

Source IP:
185.x.x.x

Country:
...

ASN:
...

VirusTotal:
12 malicious

AbuseIPDB:
92 confidence

━━━━━━━━━━━━━━━━━━
CORRELATED ACTIVITY
━━━━━━━━━━━━━━━━━━

47 failed SSH attempts
1 successful login
1 sudo execution
1 remote download
1 cron modification

━━━━━━━━━━━━━━━━━━
TIMELINE
━━━━━━━━━━━━━━━━━━

03:14  Brute force
03:15  Successful login
03:15  sudo
03:15  download
03:16  persistence

━━━━━━━━━━━━━━━━━━
RELATED IOCS
━━━━━━━━━━━━━━━━━━

IP:
185.x.x.x

Domain:
evil-example.com

URL:
https://...

SHA256:
abc123...

Process:
/tmp/payload.sh

━━━━━━━━━━━━━━━━━━
AI SUMMARY
━━━━━━━━━━━━━━━━━━

The observed activity indicates...

━━━━━━━━━━━━━━━━━━
RECOMMENDED INVESTIGATION
━━━━━━━━━━━━━━━━━━

1. Verify root login
2. Inspect downloaded file
3. Review root commands
4. Investigate outbound connection

━━━━━━━━━━━━━━━━━━
DATA SOURCES
━━━━━━━━━━━━━━━━━━

Wazuh
VirusTotal
AbuseIPDB

Related events: 18
Time window: ±15 min

⚠️ Final determination remains with analyst.

Full report:
<LINK>
Itu adalah output yang gue bayangkan sejak lu menjelaskan kebutuhan lu tadi.
20. Full report harus lebih detail daripada notification
Notification:
high-level context
Full report:
incident metadata
all related IOC
timeline lengkap
raw event references
threat intel details
AI analysis
queries performed
correlation reasons
execution trace
Jadi:
Telegram/Discord
      ↓
Quick understanding

Full investigation page/report
      ↓
Deep investigation
21. WORKFLOW 11 — Case Storage
Setiap incident disimpan.
Minimal:
incidents
├── incident_id
├── timestamp
├── rule_id
├── severity
├── risk_score
├── source_ip
├── destination
├── host
├── user
├── ai_summary
├── ai_confidence
├── status
└── raw_alert
Lalu:
incident_events
incident_iocs
incident_timeline
incident_enrichment
incident_actions
Kenapa?
Supaya nanti lu punya historical case.
22. Analyst decision
Database punya:
status:
OPEN
TP
FP
ESCALATED
CLOSED
Tetapi automation tidak mengisi TP/FP.
Contoh:
Automation:
Risk = HIGH
AI confidence = 89%
Recommendation = Investigate

Analyst:
TP
atau:
Automation:
Risk = HIGH
AI confidence = 92%

Analyst:
FP
Reason:
Authorized vulnerability scanner
Nah, itu decision analyst.
23. Optional response layer
Ini full version, tapi bukan tahap pertama.
Misalnya:
Risk >= threshold
+
IP not allowlisted
+
Known malicious TI
+
Attack behavior confirmed
+
Response policy enabled
→ candidate action.
Misalnya:
block IP
Tapi:
AI says HIGH
sendirian nggak cukup.
Default:
BLOCK_ENABLED = FALSE
Jadi project tetap aman.
24. Error handling
Setiap external service harus bisa gagal.
Misalnya:
VirusTotal ❌
pipeline tidak berhenti.
Hasil:
VirusTotal = UNKNOWN
bukan:
VirusTotal = CLEAN
Begitu juga:
AbuseIPDB ❌
LLM ❌
Gmail ❌
Wazuh query ❌
Incident tetap dibuat dengan:
partial data
+
failure reason
Ini penting supaya automation punya behavior yang predictable.
25. Security layer
Karena ini security project, gue nggak mau project-nya sendiri jadi security disaster.
Minimal:
HTTPS
Webhook authentication
Credential management
No API keys in workflow text
Restricted firewall
n8n authentication/2FA
Wazuh API not publicly exposed
Least privilege
Audit logs
Dan:
Wazuh → n8n
lebih baik melalui authenticated connection daripada webhook anonim.
26. Modular n8n architecture
Gue nggak mau satu workflow 100 node.
Kita pecah:
01_SOC_Alert_Intake
02_SOC_Deduplication
03_SOC_Investigation_Orchestrator
04_SOC_Wazuh_Correlation
05_SOC_Threat_Intelligence
06_SOC_Asset_Context
07_SOC_Timeline
08_SOC_AI_Analysis
09_SOC_Report_Generator
10_SOC_Notification
11_SOC_Case_Storage
12_SOC_Response
13_SOC_Error_Handler
Orchestrator menjadi otaknya:
Alert
 ↓
Investigation Orchestrator
 ├── Correlation
 ├── Threat Intel
 ├── Asset Context
 ├── Timeline
 └── AI
      ↓
Report
 ↓
Notification
 ↓
Storage
Ini jauh lebih gampang di-maintain.
27. Attack scenario yang kita pakai
Jangan langsung bikin 20 jenis attack.
Kita mulai dari:
Scenario 1 — SSH brute force
failed login × banyak
Scenario 2 — SSH brute force + successful login
failed
↓
success
Scenario 3 — Post-auth activity
login
↓
sudo
↓
wget
↓
cron
Scenario 4 — Suspicious PowerShell
PowerShell
↓
encoded command
↓
network connection
Scenario 5 — Suspicious file
file creation
↓
hash
↓
threat intel
Scenario 6 — Privilege escalation
user activity
↓
privilege change
Jadi automation akhirnya nggak bergantung pada SSH doang.
28. Tahapan pembangunannya
PHASE 0 — Infrastructure
AWS VPS
↓
Ubuntu
↓
Docker
↓
n8n
↓
HTTPS
↓
Security hardening
Output:
n8n accessible dan aman.
PHASE 1 — Mock SOC Alert
Fake Wazuh JSON
↓
n8n
↓
normalize
↓
AI
↓
notification
Belum ada Wazuh real.
Tujuannya memastikan architecture n8n-nya jalan.
PHASE 2 — Wazuh Integration
Wazuh
↓
n8n webhook
Mulai dari:
SSH authentication alerts
PHASE 3 — Correlation
Tambahkan:
same IP
same host
same user
time window
related events
Ini menurut gue milestone paling penting.
PHASE 4 — Threat Intelligence
Tambahkan:
VirusTotal
AbuseIPDB
PHASE 5 — Timeline
Gabungkan:
alert
+
related events
+
TI
menjadi incident timeline.
PHASE 6 — AI Investigation
Masukkan evidence package ke:
Gemini
dan hasilkan:
summary
observations
inferences
recommendations
PHASE 7 — Rich Notification
Bangun output untuk:
Discord
Telegram
Gmail
dengan IOC dan context lengkap.
PHASE 8 — Case Storage
Tambahkan:
PostgreSQL / Supabase
untuk menyimpan incident.
PHASE 9 — Human Review
Tambahkan:
TP
FP
ESCALATED
dan analyst notes.
PHASE 10 — Response
Baru:
optional containment
dengan deterministic gates.
PHASE 11 — Expansion
Tambah:
PowerShell
Malware
Privilege Escalation
Persistence
Web Attacks
29. Full end-state flow
Ini versi yang gue anggap FINAL ARCHITECTURE:
                           ┌──────────────────┐
                           │    ENDPOINTS     │
                           │ Linux / Windows  │
                           └────────┬─────────┘
                                    │
                                    ▼
                           ┌──────────────────┐
                           │      WAZUH       │
                           │ Detection / SIEM │
                           └────────┬─────────┘
                                    │
                              SECURITY ALERT
                                    │
                                    ▼
                     ┌──────────────────────────┐
                     │    ALERT INTAKE (n8n)    │
                     │ Auth → Validate → Parse  │
                     └─────────────┬────────────┘
                                   │
                                   ▼
                     ┌──────────────────────────┐
                     │      DEDUPLICATION       │
                     └─────────────┬────────────┘
                                   │
                                   ▼
                     ┌──────────────────────────┐
                     │     IOC EXTRACTION       │
                     └─────────────┬────────────┘
                                   │
                                   ▼
               ┌───────────────────┼───────────────────┐
               │                   │                   │
               ▼                   ▼                   ▼
      ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
      │ WAZUH          │  │ THREAT INTEL   │  │ ASSET CONTEXT  │
      │ CORRELATION    │  │                │  │                │
      │                │  │ VT             │  │ Host           │
      │ Related events │  │ AbuseIPDB      │  │ OS             │
      │ ± time window  │  │ Reputation     │  │ User           │
      └───────┬────────┘  └───────┬────────┘  └───────┬────────┘
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  ▼
                       ┌────────────────────┐
                       │ EVIDENCE FILTERING │
                       │ + CORRELATION      │
                       └─────────┬──────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │  TIMELINE BUILDER  │
                       └─────────┬──────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │ EVIDENCE PACKAGE   │
                       │                    │
                       │ Alert              │
                       │ IOC                │
                       │ Events             │
                       │ Timeline           │
                       │ Threat Intel       │
                       │ Asset Context      │
                       └─────────┬──────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │       AI ANALYSIS        │
                    │                          │
                    │ Gemini / OpenRouter /    │
                    │ Ollama                   │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │ INVESTIGATION REPORT     │
                    │                          │
                    │ Summary                  │
                    │ Observations             │
                    │ Inference                │
                    │ MITRE                    │
                    │ Confidence               │
                    │ Recommendations          │
                    └────────────┬─────────────┘
                                 │
                  ┌──────────────┼──────────────┐
                  │              │              │
                  ▼              ▼              ▼
               Telegram       Discord         Gmail
                  │              │              │
                  └──────────────┼──────────────┘
                                 ▼
                         ┌────────────────┐
                         │ HUMAN ANALYST  │
                         └───────┬────────┘
                                 │
                      ┌──────────┼──────────┐
                      ▼          ▼          ▼
                     TP         FP      ESCALATE
                      │          │          │
                      └──────────┼──────────┘
                                 ▼
                         ┌────────────────┐
                         │ CASE STORAGE   │
                         │ PostgreSQL      │
                         └────────────────┘
                                 │
                                 ▼
                       OPTIONAL RESPONSE
                                 │
                          POLICY GATES
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
               AUTOMATED BLOCK             SKIP
30. Dan posisi AI-nya sebenarnya cuma ini
               ┌──────────────┐
               │     WAZUH    │
               └──────┬───────┘
                      ↓
            ┌──────────────────┐
            │ AUTOMATED DATA   │
            │ COLLECTION       │
            └────────┬─────────┘
                     ↓
            ┌──────────────────┐
            │   CORRELATION    │
            └────────┬─────────┘
                     ↓
            ┌──────────────────┐
            │    EVIDENCE      │
            └────────┬─────────┘
                     ↓
            ┌──────────────────┐
            │       AI         │
            └────────┬─────────┘
                     ↓
            ┌──────────────────┐
            │   ANALYST        │
            └──────────────────┘
Dan itu justru desain yang gue mau.
Karena kalau nanti lu interview dan ditanya:
“What role does AI play in your SOC automation project?”
Lu bisa menjawab secara teknis:
“The AI is used as an investigation and summarization layer over correlated security evidence. Deterministic logic handles event correlation, IOC enrichment, scoring, and response gates, while the analyst retains final decision authority.”
Itu kedengerannya jauh lebih matang daripada:
“I send Wazuh alerts to Gemini and Gemini tells me whether they're malicious.”
31. Definition of Done
Project ini gue anggap full version selesai kalau satu SSH incident bisa melakukan:
Wazuh detects attack
        ↓
n8n receives alert
        ↓
deduplicates
        ↓
extracts IOC
        ↓
queries related events
        ↓
queries threat intel
        ↓
collects asset context
        ↓
builds timeline
        ↓
calculates deterministic risk
        ↓
creates evidence package
        ↓
LLM generates analysis
        ↓
builds analyst report
        ↓
sends rich notification
        ↓
stores case
        ↓
analyst opens it
        ↓
analyst can verify raw evidence
        ↓
analyst decides TP / FP / escalation
Dan setelah itu baru kita bisa bilang:
“Gue punya automated SOC investigation assistant.”
Yang paling penting: urutan prioritasnya
Gue bakal jangan menyentuh dashboard, Ollama, auto-block, atau 5 jenis attack sekaligus dulu.
Prioritas:
1. n8n VPS
2. Secure n8n
3. Wazuh → n8n
4. Alert normalization
5. Correlation
6. Threat intelligence
7. Timeline
8. AI analysis
9. Rich notification
10. Case storage
11. Human review
12. Response automation
13. More attack scenarios
14. Optional dashboard
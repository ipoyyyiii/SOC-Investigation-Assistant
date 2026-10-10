# BOTS harness score (2026-10-09)

Dataset: BOTS v1 attack-only (Splunk/Sysmon export, real attack sequence: osk.exe -> iexplore/wmic/vssadmin/schtasks/powershell)
Sample: 10 Sysmon ProcessCreate events replayed through /webhook/soc-alert (source=splunk)

| Criterion | Score |
|---|---|
| Events stored as incidents | 10/10 |
| attack_type = process (router) | 10/10 |
| parent_image preserved | 10/10 |
| command preserved | 10/10 |
| hash (SHA256) preserved | 10/10 |
| Incidents rows created | 9/10 (1 correct dedup: identical CommandLine+ts pair) |
| TI cache: live file-hash lookups | 9/9 fresh virustotal_file rows during run |

Per-event:
- bots-harness-0001: OK INC-20261009-4102|process|C:\Windows\Microsoft.NET\Framework64\v2.0.50727\csc.exe|C:\Windows\Microsoft.NET\Framework64\v2.0.50727\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Users\BOBSMI~1.WAY\AppData\Local\Temp\RES958E.tmp" "c:\Users\bob.smith.WAYNECORPINC\AppData\Local\Temp\CSC958D.tmp"|0300CA237CF2D7D4A415612A68AB9BBDF3226FA6A055CED19E13DF862EC4FB98
- bots-harness-0002: OK INC-20261009-5442|process|C:\Windows\System32\sdiagnhost.exe|"C:\Windows\Microsoft.NET\Framework64\v2.0.50727\csc.exe" /noconfig /fullpaths @"C:\Users\bob.smith.WAYNECORPINC\AppData\Local\Temp\l62oeljq.cmdline"|2C623C8D4A531778292D1F360019CEA36200BEE11BE96662B7EC907B514FD3E6
- bots-harness-0003: OK INC-20261009-7623|process|C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe|"C:\Program Files (x86)\Internet Explorer\iexplore.exe" -nohome|E285FEECA968B3CA22017A64363EEA5E69CCD519696671DF523291B089597875
- bots-harness-0004: OK INC-20261009-8743|process|C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe|"C:\Windows\system32\wbem\wmic.exe" shadowcopy delete|DA3AD32583644BD20116F0479C178F7C7C0B730728F4C02A438C0D19378C83D9
- bots-harness-0005: OK INC-20261009-6301|process|C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe|"C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet|4DE7FA20E3224382D8C4A81017E5BDD4673AFBEF9C0F017E203D7B78977FBF8C
- bots-harness-0006: OK INC-20261009-4879|process|C:\Windows\System32\wbem\WmiPrvSE.exe|cmd /c "schtasks /query /XML &gt; %SystemRoot%\TEMP\nessus_VPG2T4UF.TMP &amp; ren %SystemRoot%\TEMP\nessus_VPG2T4UF.TMP nessus_VPG2T4UF.TXT"|DB06C3534964E3FC79D2763144BA53742D7FA250CA336F4A0FE724B75AAFF386
- bots-harness-0007: OK INC-20261009-4396|process|C:\Windows\System32\wbem\WmiPrvSE.exe|cmd /c "schtasks /query /XML &gt; %SystemRoot%\TEMP\nessus_W426FMMY.TMP &amp; ren %SystemRoot%\TEMP\nessus_W426FMMY.TMP nessus_W426FMMY.TXT"|0B9BC863E2807B6886760480083E51BA8A66118659F4FF274E7B73944D2219F5
- bots-harness-0008: OK INC-20261009-9724|process|C:\Windows\System32\wbem\WmiPrvSE.exe|cmd /c powershell "Get-AppxPackage -AllUsers | select name, version, architecture, publisher 
- bots-harness-0009: OK INC-20261009-7670|process|C:\Windows\System32\SearchIndexer.exe|"C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe21_ Global\UsGthrCtrlFltPipeMssGthrPipe21 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon"|4AC002E90A52CB0998DA78F2995294EE77B89FB2BE709B0E3C8E1627212BCCDC
- bots-harness-0010: OK INC-20261009-2614|process|C:\Windows\System32\SearchIndexer.exe|"C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe20_ Global\UsGthrCtrlFltPipeMssGthrPipe20 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon"|4AC002E90A52CB0998DA78F2995294EE77B89FB2BE709B0E3C8E1627212BCCDC

## Method
- Sample: 10 Sysmon EventCode=1 (ProcessCreate) events from BOTS v1 attack-only export (830k events scanned, filtered to attack-pattern CommandLine/ParentImage).
- Replay: POST /webhook/soc-alert (source=splunk), parallel batches, scoring read from soc DB (no LLM).
- Criteria are pipeline-fidelity (stored/routing/field-preservation/TI), NOT attack-vs-benign classification: BOTS attack-only has no benign events by construction.
- Reproduce: /tmp/bots_sample.py + /tmp/bots_harness.py (kept on n8n VPS).

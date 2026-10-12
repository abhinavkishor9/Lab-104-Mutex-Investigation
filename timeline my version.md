# Lab 104 — Mutex Investigation Timeline

| Time | Activity | Evidence or observation | Assessment |
|---|---|---|---|
| During lab setup | Evidence directory prepared | `C:\MutexInvestigationLab\Evidence` | Collection workspace created |
| During lab setup | Monitoring services checked | Sysmon and Wazuh service status command executed | Service status output saved to `sensor-status.txt` |
| During lab setup | Handle executable verified | `D:\important docs\Handle\handle64.exe` | `Test-Path` returned `True` |
| 2026-10-12 07:19:54 local time | PowerShell process started | Process metadata for PID `25528` | Process creation time recorded by `Get-CimInstance` |
| 2026-10-12 01:49:55.586 UTC | Sysmon Process Create event time | Event ID 1; process ID `25528` | Consistent with approximately `07:19:55` local time |
| 2026-10-12 07:28:03.242 | Wazuh dashboard timestamp | PowerShell image and PID `25528` | Dashboard timestamp differs from the event's process-creation time |
| 2026-10-12 07:28:59.4395031 +05:30 | Controlled mutex creation recorded | `Global\Lab104_TestMutex`; PID `25528` | Test script recorded the mutex name and process details |
| During mutex test | Handle inspection performed | `type: Mutant`; path `\BaseNamedObjects\Lab104_TestMutex` | Mutex handle observed under `pwsh.exe` PID `25528` |
| During investigation | Process metadata collected | PID `25528`; parent PID `9592` | Executable path and process creation time recorded |
| During investigation | Sysmon process events exported | `sysmon-process-events.csv` | Recent Event ID 1 records collected |
| During evidence collection | Initial hash command failed | File under `C:\Windows\System32` was in use | Command targeted an unexpected directory |
| During troubleshooting | Evidence path explicitly set | `$LabPath = "C:\MutexInvestigationLab\Evidence"` | Collection scope corrected |
| After path correction | SHA-256 manifest command rerun | `evidence-hashes.csv` | Command returned without an error; manifest contents require verification |


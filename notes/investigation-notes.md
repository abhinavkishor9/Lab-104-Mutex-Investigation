# Lab 104 — Mutex Investigation Notes

## 1. Investigation Summary

This investigation examined a controlled Windows named mutex created through PowerShell. Sysinternals Handle was used to inspect the mutex, and PowerShell was used to collect the associated process details. Available Sysmon and Wazuh evidence was reviewed to establish process context.

The investigation focused on validating the observed artifact and its process association without treating the mutex itself as an indicator of compromise.

## 2. Environment

| Attribute | Observed value |
|---|---|
| Operating system | Windows 11 Pro |
| PowerShell version | 7.6.6 |
| Sysinternals Handle | v5.0 |
| Endpoint | `DESKTOP-9MMM37V` |
| Wazuh Agent ID | `001` |
| Wazuh Agent IP | `192.168.203.1` |
| Evidence directory | `C:\MutexInvestigationLab\Evidence` |

## 3. Mutex Artifact

The test script created the following named mutex:

| Attribute | Observation |
|---|---|
| Mutex name | `Global\Lab104_TestMutex` |
| Process name | `pwsh` |
| Process ID | `25528` |
| Recorded creation time | `2026-10-12T07:28:59.4395031+05:30` |
| Investigation purpose | Controlled mutex inspection |

The mutex was created using the .NET `System.Threading.Mutex` class. The script kept the PowerShell process active for 180 seconds to allow the object to be inspected.

## 4. Handle Inspection

**Tool:** Sysinternals Handle v5.0

**Command:**

`& "D:\important docs\Handle\handle64.exe" -a Lab104_TestMutex`

**Observed output:**

`pwsh.exe pid: 25528 type: Mutant AD8: \BaseNamedObjects\Lab104_TestMutex`

### Interpretation

- `pwsh.exe` identifies the process holding the handle.
- PID `25528` matches the PID recorded by the mutex-creation script.
- `Mutant` is the Windows kernel-object type associated with mutexes.
- `\BaseNamedObjects\Lab104_TestMutex` is the object path reported by Handle.

This output confirms that Handle observed the named mutex handle associated with the controlled PowerShell process.

## 5. Process Correlation

PowerShell process metadata was collected using `Get-CimInstance Win32_Process`.

| Field | Observed value |
|---|---|
| Process ID | `25528` |
| Parent process ID | `9592` |
| Process name | `pwsh.exe` |
| Executable path | `C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe` |
| Command line | PowerShell executable path without additional arguments displayed |
| Process creation time | `2026-10-12 07:19:54` local time |

The PID matches the value recorded in the controlled mutex evidence and Handle output.

The process creation time predates the mutex-creation timestamp. This is expected because the test ran inside an already-started PowerShell process.

## 6. Sysmon and Wazuh Evidence

A Sysmon Process Create event was visible in Wazuh.

| Field | Observed value |
|---|---|
| Wazuh index | `wazuh-alerts-4.x-2026.10.12` |
| Agent name | `DESKTOP-9MMM37V` |
| Agent ID | `001` |
| Dashboard `@timestamp` | `2026-10-12 07:28:03.242` |
| Sysmon `creationUtcTime` | `2026-10-12 01:49:55.586 UTC` |
| Process ID | `25528` |
| Process image | `C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe` |
| Event type | Sysmon Process Create, Event ID 1 |

The Sysmon process creation time corresponds to approximately `2026-10-12 07:19:55` local time, consistent with the process metadata.

The dashboard timestamp and the event's process-creation timestamp represent different timing fields and should not be treated as interchangeable.

### Correlation assessment

**Confirmed:** The Sysmon event identifies PowerShell PID `25528`, which matches the process identified in the local evidence and Handle output.

**Not established:** The Sysmon event does not prove that the mutex was created at the event timestamp. Event ID 1 records process creation, not mutex creation.

No direct mutex-creation event was established by this evidence.

## 7. Evidence Collection

The following files were prepared in the evidence directory:

- `investigation-start.txt`
- `system-information.txt`
- `sensor-status.txt`
- `mutex-creation.txt`
- `handle-output.txt`
- `process-details.txt`
- `sysmon-process-events.csv`
- `evidence-hashes.csv`

The SHA-256 manifest command was rerun after explicitly setting `$LabPath` to the evidence directory. The later execution returned to the PowerShell prompt without an error.

The hash values themselves should be verified from `evidence-hashes.csv`. Successful command execution alone does not document the individual hash values.

## 8. Confirmed Findings

1. The controlled mutex was named `Global\Lab104_TestMutex`.
2. The mutex-creation script recorded PowerShell PID `25528`.
3. Handle observed a `Mutant` object at `\BaseNamedObjects\Lab104_TestMutex` associated with PID `25528`.
4. PowerShell process metadata identified the executable path and parent PID.
5. A Sysmon Process Create event in Wazuh recorded the same PID and PowerShell image.
6. The process creation time preceded the recorded mutex creation time.
7. The evidence collection and SHA-256 manifest commands were executed.

## 9. Unknowns and Limitations

- The exact kernel-level time at which the named mutex was created was not independently recorded by Sysmon.
- No direct mutex-creation event was established in Wazuh.
- The collected process metadata does not independently prove every action performed by the process.
- The actual SHA-256 values must be read from the generated manifest.
- The investigation did not establish malicious behavior or compromise.

## 10. Assessment

The evidence supports a successful controlled mutex investigation. Handle observed the test mutex under PowerShell PID `25528`, and the available process metadata and Sysmon event provide consistent process context.

The observed activity is consistent with the lab's intended test. No claim of malicious activity is supported by the mutex name or these observations alone.

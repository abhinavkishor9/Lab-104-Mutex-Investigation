# Lab-104-Mutex-Investigation
## Overview
A mutex (mutual exclusion object) is a synchronization mechanism that helps processes or threads coordinate access to shared resources. Windows represents mutexes as kernel objects, and Sysinternals Handle commonly displays their object type as Mutant.
Mutexes are useful in security investigations because:
- Legitimate applications may use mutexes to prevent multiple instances or coordinate execution.
- Malware may use named mutexes to coordinate its instances or check whether another instance is already running.
- SOC analysts can investigate the mutex name, owning process, executable path, command line, timestamps, and related endpoint activity.
Important: A suspicious-looking mutex name does not prove malware. The investigation must consider the surrounding process behavior and supporting evidence.

This lab investigates a controlled Windows named mutex and demonstrates how a SOC analyst can identify its associated process, examine available endpoint telemetry, and preserve investigation evidence.

A mutex (mutual exclusion object) is a synchronization mechanism used by processes or threads to coordinate access to shared resources. Windows represents mutexes as kernel objects, which Sysinternals Handle may display using the object type `Mutant`.

Named mutexes can appear in legitimate applications and potentially in malware. Their presence alone does not establish malicious activity. Process context, executable details, related events, and other supporting evidence are required to assess their significance.

## Lab Environment

| Component | Details |
|---|---|
| Operating system | Windows 11 Pro |
| PowerShell | PowerShell 7.6.6 |
| Process monitoring | Sysmon |
| Endpoint monitoring | Wazuh Agent 4.12.0 |
| Handle inspection | Sysinternals Handle v5.0 |
| Evidence directory | `C:\MutexInvestigationLab\Evidence` |
| Controlled mutex | `Global\Lab104_TestMutex` |
| Test process | `pwsh.exe` |
| Test process ID | `25528` |

## Lab Objectives

- Understand the purpose of Windows mutexes and their relevance to endpoint security investigations.
- Create a controlled named mutex using PowerShell and record its name, process ID, and creation timestamp.
- Use Sysinternals Handle to inspect the mutex and identify its reported object type, namespace path, and associated process.
- Collect process metadata, including the executable path, parent process ID, command line, and process creation time.
- Examine Sysmon Process Create events and correlate them with the process observed during the mutex investigation.
- Validate available process telemetry in Wazuh and identify limitations in detecting or recording mutex activity.
- Apply timestamp and process-ID correlation while distinguishing process creation from subsequent mutex creation.
- Preserve investigation outputs and generate SHA-256 hashes to support evidence integrity checks.
- Troubleshoot evidence collection issues, including incorrect directory scope and files that cannot be accessed.
- Document confirmed observations, unknowns, and telemetry gaps without treating a mutex name or its presence as proof of malicious activity.

## Lab Scenario

A SOC analyst is investigating Windows endpoint artifacts to understand how named mutexes can be examined during security investigations. Mutexes are commonly used by legitimate applications to coordinate execution, but they can also be used by malware to manage instances or coordinate activity. The analyst must determine what the available evidence establishes without assuming that the presence of a mutex indicates malicious behavior.

The investigation begins by creating a controlled mutex named `Global\Lab104_TestMutex` using PowerShell. While the PowerShell process remains active, Sysinternals Handle is used to inspect the object and identify the process holding its handle. The analyst records the mutex name, reported object type, process ID, and namespace path, then collects additional process details to establish context.

The investigation also examines the available Sysmon and Wazuh telemetry. A Sysmon Process Create event identifies the PowerShell process, but the process creation timestamp precedes the mutex creation timestamp recorded by the test script. The analyst must distinguish evidence of the process starting from evidence of the subsequent mutex operation.

The investigation focuses on the following activities:

- **Mutex inspection:** Examine the controlled named mutex using Sysinternals Handle and document the observed object details.
- **Process correlation:** Compare the process ID, executable path, parent process ID, and timestamps across the available evidence.
- **Telemetry validation:** Review Sysmon and Wazuh events to determine what process activity can be confirmed and identify visibility limitations.
- **Evidence preservation:** Save command outputs, generate SHA-256 hashes, and troubleshoot collection issues without expanding the investigation beyond the intended evidence directory.
- **Finding assessment:** Separate confirmed observations from assumptions and document any unresolved questions.

The lab is successful when the analyst can demonstrate the mutex-to-process association, explain the role and limitations of the available telemetry, and preserve the investigation evidence. The final assessment must remain evidence-based: a named mutex is an investigative artifact, not proof of compromise.## Investigation Workflow

1. Prepare the evidence directory and verify the monitoring services.
2. Confirm that Sysinternals Handle is accessible.
3. Create the controlled mutex `Global\Lab104_TestMutex`.
4. Inspect the named object with Handle while the test process is running.
5. Collect the process ID, executable path, parent PID, command line, and creation time.
6. Review Sysmon Process Create events and available Wazuh records.
7. Generate a SHA-256 manifest for the collected evidence.
8. Document findings, uncertainties, and collection limitations.

## Key Findings

### 1. Controlled mutex creation

PowerShell created the named mutex:

- Mutex name: `Global\Lab104_TestMutex`
- Process name: `pwsh`
- Process ID: `25528`
- Recorded mutex creation time: `2026-10-12 07:28:59.4395031 +05:30`

The timestamp above comes from the test script's recorded evidence.

### 2. Handle inspection

Sysinternals Handle v5.0 returned the following relevant output:

`pwsh.exe pid: 25528 type: Mutant AD8: \BaseNamedObjects\Lab104_TestMutex`

This directly supports the observation that the test PowerShell process held a handle to the named mutex at the time of inspection.

### 3. Process details

The process metadata collection identified:

- Process ID: `25528`
- Parent process ID: `9592`
- Process name: `pwsh.exe`
- Executable: `C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe`
- Process creation time: `2026-10-12 07:19:54` local time

### 4. Sysmon and Wazuh observations

A Sysmon Process Create event was visible in Wazuh with:

- Agent: `DESKTOP-9MMM37V`
- Agent ID: `001`
- Event timestamp in the dashboard: `2026-10-12 07:28:03.242`
- Sysmon process creation time: `2026-10-12 01:49:55.586 UTC`
- Process ID: `25528`
- Process image: PowerShell 7 executable

The process creation time corresponds to approximately `07:19:55` local time, which is consistent with the local process metadata.

**Correlation limitation:** The process started before the mutex creation recorded at `07:28:59` local time. The event supports the existence and identity of the PowerShell process, but it does not establish when the mutex was created.

## Evidence Files

The evidence directory was prepared to hold the following files:

| File | Purpose |
|---|---|
| `investigation-start.txt` | Records the investigation start time |
| `system-information.txt` | Records host and operating-system details |
| `sensor-status.txt` | Records Sysmon and Wazuh service status |
| `mutex-creation.txt` | Records the test mutex name, PID, process name, and timestamp |
| `handle-output.txt` | Preserves the Handle inspection output |
| `process-details.txt` | Stores the process metadata |
| `sysmon-process-events.csv` | Stores recent Sysmon Process Create events |
| `evidence-hashes.csv` | Stores SHA-256 hashes of collected evidence files |

The hash manifest command completed without displaying an error after the evidence directory was explicitly set. The actual hash values should be taken from the generated CSV rather than inferred from the command's successful completion.

## Investigation Limitations

- Sysmon Process Create events do not directly establish mutex creation.
- The presence of a named mutex is not evidence of malicious behavior by itself.
- A PID should be correlated with the image, creation time, and other available process details.
- Wazuh visibility depends on the events collected, decoded, indexed, and retained.
- A missing search result does not prove that an event or artifact was absent.
- The recorded evidence reflects the observations available during this lab run.


# Lab 104 — Mutex Investigation

## Overview

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

## Objectives

- Create a controlled named mutex using PowerShell.
- Inspect the mutex with Sysinternals Handle.
- Identify the process holding the mutex handle.
- Examine process metadata and available Sysmon events.
- Review Wazuh telemetry for supporting process evidence.
- Preserve investigation outputs and calculate SHA-256 hashes.
- Document confirmed observations, limitations, and troubleshooting steps.

## Investigation Scenario

A SOC analyst is examining a Windows endpoint to understand how named mutexes can be investigated during a security incident. The analyst creates a benign test mutex, keeps the owning PowerShell process active, and uses Sysinternals Handle to inspect the object.

The investigation then correlates the observed mutex with its process ID and examines the available Sysmon and Wazuh telemetry. The analyst distinguishes process-creation evidence from direct evidence of mutex activity and records any gaps in visibility.

## Investigation Workflow

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

## Conclusion

This lab demonstrates a repeatable method for investigating a controlled Windows named mutex through process-handle inspection and endpoint telemetry.

The confirmed finding is that Sysinternals Handle observed `Global\Lab104_TestMutex` as a `Mutant` object associated with PowerShell PID `25528`. The available process-creation evidence provides context for that process but does not directly record mutex creation.

The investigation follows an evidence-first approach: establish what was observed, correlate it with available telemetry, document uncertainty, and avoid conclusions that exceed the evidence.

## Skills Demonstrated

- Windows internals and named synchronization objects
- PowerShell evidence collection
- Sysinternals Handle
- Process and PID correlation
- Sysmon event investigation
- Wazuh endpoint telemetry analysis
- SHA-256 evidence integrity checks
- Investigation documentation and limitations

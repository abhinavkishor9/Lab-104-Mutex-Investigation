# Lab 104 — Troubleshooting Notes

## 1. Sysinternals Handle Path

### Issue

The investigation required Sysinternals Handle to inspect the named mutex.

### Resolution

The executable was available at:

`D:\important docs\Handle\handle64.exe`

The path was validated using:

`Test-Path $HandlePath`

The command returned `True`.

### Lesson

Do not assume that a utility is installed in a default directory. Verify the executable's actual location before running the investigation commands.

## 2. Mutex Visibility

### Observation

Handle returned:

`pwsh.exe pid: 25528 type: Mutant AD8: \BaseNamedObjects\Lab104_TestMutex`

### Interpretation

The output identified the named mutex and the PowerShell process holding its handle.

The `Mutant` type is the Windows kernel-object representation associated with a mutex.

### Lesson

Keep the controlled process running while inspecting the mutex. If the process exits or releases the handle before inspection, the result may differ.

## 3. Process Correlation

### Observation

The following sources identified the same process ID:

- Mutex-creation output: `25528`
- Handle output: `25528`
- PowerShell process metadata: `25528`
- Sysmon Process Create event in Wazuh: `25528`

The process image was the PowerShell 7 executable.

### Important timestamp distinction

The process creation time was approximately `07:19:54` local time. The mutex-creation script recorded `07:28:59` local time.

This difference is consistent with the mutex being created inside an already-running PowerShell process.

### Lesson

A process-creation event provides evidence about when the process started. It does not establish when a mutex was subsequently created. Correlate PID, image, process creation time, and the separately recorded mutex timestamp.

## 4. Wazuh Telemetry Limitations

### Observation

A Sysmon Event ID 1 record was visible in Wazuh for PowerShell PID `25528`.

### Interpretation

The event supports the identification of the process. It is not direct evidence of mutex creation.

A broad search for the mutex name may return no results if the collected telemetry does not contain that name.

### Lesson

- Use Event ID 1 for process-creation context.
- Inspect actual event fields before relying on a query.
- Use local Handle output as direct evidence of the observed mutex handle.
- Do not treat an absent mutex-name search result as proof that the object did not exist.
- Record telemetry limitations instead of inventing missing events.

## 5. SHA-256 Hashing Error

### Initial issue

The initial hashing command returned:

`The process cannot access the file 'C:\Windows\System32\5E37410B-D6F1-471D-AE27-563CEAC0D6B2' because it is being used by another process.`

The attempted command was:

`Get-ChildItem $LabPath -File | Where-Object { $_.Name -ne "evidence-hashes.csv" } | Get-FileHash -Algorithm SHA256`

The error showed that the command attempted to hash a file under `C:\Windows\System32`, rather than a file in the intended evidence directory.

### Likely cause

The evidence path variable was not set correctly in that execution context. When `$LabPath` is empty, PowerShell can enumerate the current directory, which in this session was `C:\Windows\System32`.

The error also reported that the encountered file was in use. However, the incorrect enumeration scope was the first issue to correct.

### Resolution

The evidence path was explicitly assigned:

`$LabPath = "C:\MutexInvestigationLab\Evidence"`

The hashing command was then rerun and returned to the prompt without displaying an error.

### Safer procedure

Before hashing, verify the variable and the directory:

`$LabPath`

`Test-Path -LiteralPath $LabPath -PathType Container`

Then inspect the files that will be processed:

`Get-ChildItem -LiteralPath $LabPath -File | Select-Object Name, FullName`

Only after confirming the paths should the hash manifest be generated.

### Lesson

Use `-LiteralPath` for explicit filesystem paths, validate the target directory, and inspect the candidate files before performing evidence collection.

A command returning without an error is not a substitute for reviewing the generated CSV and confirming that the expected files and hashes are present.


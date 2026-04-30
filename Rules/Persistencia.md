<h1>PERSISTENCIA</h1>

### Persistence

```
</> yamltitle: Scheduled Task Creation
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "schtasks /create"
  condition: selection
```

```
</> yaml
title: Registry Run Key Persistence
logsource: {product: windows}
detection:
  selection:
    TargetObject|contains: "CurrentVersion\\Run"
  condition: selection
```

```
</> yaml
title: New Service Installed
logsource: {product: windows}
detection:
  selection:
    EventID: 7045
  condition: selection
```

```
</> yaml
title: Suspicious Service Path
logsource: {product: windows}
detection:
  selection:
    ImagePath|contains: "AppData"
  condition: selection
```

```
</> yaml
title: WMI Persistence
logsource: {product: windows}
detection:
  selection:
    EventID: 5861
  condition: selection
```

```
</> yaml
title: Startup Folder Modification
logsource: {product: windows}
detection:
  selection:
    TargetFilename|contains: "Startup"
  condition: selection
```

```
</> yaml
title: DLL in Temp Execution
logsource: {product: windows}
detection:
  selection:
    Image|contains: ".dll"
    CommandLine|contains: "Temp"
  condition: selection
```

```
</> yaml
title: Autorun Registry Modification
logsource: {product: windows}
detection:
  selection:
    TargetObject|contains: "RunOnce"
  condition: selection
```

```
</> yaml
title: Service Modification
logsource: {product: windows}
detection:
  selection:
    EventID: 7040
  condition: selection
```

```
</> yaml
title: Suspicious Scheduled Task Path
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "AppData"
  condition: selection
```


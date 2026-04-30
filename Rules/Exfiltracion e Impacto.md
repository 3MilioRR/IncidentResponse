<H1>EXFILTRATION & IMPACT</H1> 

### Exfiltration & Impact

```
</> yaml
title: Archive Creation
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains:
      - ".zip"
      - ".rar"
      - ".7z"
  condition: selection
```

```
</> yaml
title: 7zip Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "7z"
  condition: selection
```

```
</> yaml
title: Large File Collection
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "copy"
  condition: selection
```

```
</> yaml
title: External Network Connection
logsource: {product: windows}
detection:
  selection:
    DestinationIp|notstartswith: "192.168."
  condition: selection
```

```
</> yaml
title: PowerShell Upload
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "Upload"
  condition: selection
```

```
</> yaml
title: Delete Shadow Copies
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "vssadmin delete shadows"
  condition: selection
```

```
</> yaml
title: Delete Backup Catalog
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "wbadmin delete"
  condition: selection
```

```
</> yaml
title: Service Stop
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "net stop"
  condition: selection
```

```
</> yaml
title: Mass File Rename
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "rename"
  condition: selection
```

```
</> yaml
title: Suspicious File Extension Change
logsource: {product: windows}
detection:
  selection:
    TargetFilename|contains: ".locked"
  condition: selection
```

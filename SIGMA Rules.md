<H1> SIGMA RULES </H1>
Las reglas SIGMA son como plantillas genéricas para detectar actividad sospechosa en logs.

:triangular_flag_on_post: Piensa en ellas como: “Si pasa esto en los logs → puede ser un ataque”

No están ligadas a una herramienta concreta. Luego se convierten a formatos específicos (Splunk, Elastic, Sentinel, etc.).

Ejemplo sencillo (fichero YAML)

```
title: Uso sospechoso de PowerShell
detection:
  selection:
    Image: powershell.exe
    CommandLine: "*DownloadString*"
  condition: selection
```

Traducción: Si alguien usa PowerShell para descargar cosas → sospechoso

A continuación tienes un set de ***50 reglas Sigma*** (simplificadas pero funcionales) listas para usar como base.

⚠️ Importante: Están optimizadas para claridad y uso práctico, no para cubrir todos los edge cases.

Deberás adaptar:
- logsource
- campos (Sysmon vs Security vs MDE)
Úsalas como plantilla operativa, no como copy/paste ciego.

## 50 reglas sigma

### PowerShell / Execution

```
</> yaml
title: Suspicious PowerShell Encoded Command
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "EncodedCommand"
  condition: selection
```

```
</> yaml
title: PowerShell DownloadString
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "DownloadString"
  condition: selection
```

```
</> yaml
title: PowerShell Invoke-WebRequest
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "Invoke-WebRequest"
  condition: selection
```

```
</> yaml
title: PowerShell from Office
logsource: {product: windows}
detection:
  selection:
    ParentImage|endswith:
      - winword.exe
      - excel.exe
    Image|endswith: powershell.exe
  condition: selection
```

```
</> yaml
title: PowerShell IEX Usage
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains: "IEX"
  condition: selection
```

```
</> yaml
title: PowerShell Hidden Window
logsource: {product: windows}
detection:
  selection:
    CommandLine|contains:
      - "-nop"
      - "-w hidden"
  condition: selection
```

```
</> yaml
title: PowerShell Base64 Long String
logsource: {product: windows}
detection:
  selection:
    CommandLine|re: "[A-Za-z0-9+/]{200,}"
  condition: selection
```

```
</> yaml
title: Suspicious Cmd Execution
logsource: {product: windows}
detection:
  selection:
    Image|endswith: cmd.exe
    CommandLine|contains: "/c"
  condition: selection
```

```
</> yaml
title: Rundll32 Remote Execution
logsource: {product: windows}
detection:
  selection:
    Image|endswith: rundll32.exe
    CommandLine|contains: "http"
  condition: selection
```

```
</> yaml
title: Regsvr32 Remote Script
logsource: {product: windows}
detection:
  selection:
    Image|endswith: regsvr32.exe
    CommandLine|contains: "http"
  condition: selection
```



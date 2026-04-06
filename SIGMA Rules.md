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


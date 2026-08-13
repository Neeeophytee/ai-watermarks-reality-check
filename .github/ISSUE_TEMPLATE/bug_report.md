---
name: Bug report
about: An analyzer produced a wrong or unsafe result
labels: bug
---

## What happened

<!-- The exact command and the JSON output. Redact any private values. -->

```
$ python3 skills/.../script.py ...
```

## What you expected

<!-- Which state should it have returned, and why? -->

## Severity check

- [ ] It returned a **conclusive** state (`ABSENT`, `NOT_DETECTED`, `VALID`,
      `TRUSTED`, exit `0`) that was not justified. **This is the most serious
      class of bug in this project — say so up front.**
- [ ] It crashed, hung, or wrote to an input file.
- [ ] It returned `UNKNOWN` where it could reasonably have concluded (coverage gap).

## Environment

- Tool and version:
- Python version:
- `c2patool -V` (if relevant):
- OS:

## Input

<!-- Attach the file, or a short script that generates it. A real fixture is
     far more useful than a description. -->

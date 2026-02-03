# dupecode

**Python Code Clone Detector** — Find duplicated code via AST analysis. Zero dependencies.

Detects exact clones (copy-paste) and parameterized clones (same structure, different names/values) across your entire Python project.

## Why?

| Tool | Deps | Python | AST-based | Cross-file | Grading |
|------|------|:---:|:---:|:---:|:---:|
| **dupecode** | **0** | ✅ | ✅ | ✅ | ✅ |
| Clone Digger | dead | ✅ | ✅ | ✅ | ❌ |
| pylint dup-code | pylint | ✅ | ❌ (text) | ✅ | ❌ |
| jscpd | Node.js | ❌ | ❌ (tokens) | ✅ | ❌ |
| PMD CPD | Java | ❌ | ✅ | ✅ | ❌ |

## Quick Start

```bash
# Scan a project
python dupecode.py src/

# With code snippets
python dupecode.py --verbose src/

# Custom thresholds
python dupecode.py --min-lines 8 --min-tokens 30 src/

# CI mode (fail if too much duplication)
python dupecode.py --check --threshold 90 src/

# JSON output
python dupecode.py --json src/
```

## Clone Types

### Exact Clones (Type 1)
Identical code blocks — pure copy-paste. Same AST structure, same names, same values.

### Parameterized Clones (Type 2)
Same structure but with different names or values. Like the same function written twice with different variable names.

## Example Output

```
─────────────────────────────────────────────────────────────────
  dupecode v0.1.0 — Python Code Clone Detector
─────────────────────────────────────────────────────────────────

🔴 Clone Group #1 (exact, 15 lines, 3 copies)
  📄 src/handlers/user.py:42-56
  📄 src/handlers/admin.py:38-52
  📄 src/handlers/api.py:61-75

🟡 Clone Group #2 (parameterized, 22 lines, 2 copies)
  📄 src/parsers/json_parser.py:10-31
  📄 src/parsers/xml_parser.py:10-31

─────────────────────────────────────────────────────────────────
  Score: 82/100 (Grade: B)
  Files: 24 | Lines: 3,200 | Duplicated: 293 (9.2%)
  Clone groups: 8 (3 exact, 5 parameterized)
─────────────────────────────────────────────────────────────────
```

## Options

| Flag | Description |
|------|-------------|
| `--min-lines N` | Minimum lines for a clone (default: 5) |
| `--min-tokens N` | Minimum AST nodes (default: 20) |
| `--check` | Exit 1 if score below threshold |
| `--threshold N` | Score threshold (default: 90) |
| `--json` | Output as JSON |
| `--top N` | Show top N clone groups (default: 10) |
| `--verbose` | Show code snippets |
| `--quiet` | Only show summary |

## Requirements

- Python 3.9+
- Zero dependencies

## License

MIT

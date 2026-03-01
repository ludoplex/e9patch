# LLM Context Discovery

This project supports multiple LLM coding assistants through universal context files.

## Context Files

| File | Purpose | Consumers |
|------|---------|-----------|
| `AGENTS.md` | Primary agent context | All LLM tools |
| `CONVENTIONS.md` | Code style guide | All LLM tools |
| `specs/*.feature` | BDD behavior specs | All LLM tools |
| `specs/*.schema` | Type definitions | Generators + LLMs |
| `specs/*.sm` | State machines | Generators + LLMs |

## Provider Symlinks (Active)

All symlink to `AGENTS.md` (single source of truth):

| File | Provider |
|------|----------|
| `.claude/CLAUDE.md` | Claude Code (Anthropic) |
| `.cursorrules` | Cursor |
| `.github/copilot-instructions.md` | GitHub Copilot |
| `AI.md` | Generic / Aider |
| `LLM.md` | Generic |
| `CONTEXT.md` | Generic |

```
AGENTS.md  ← canonical source
    ↑
    ├── .claude/CLAUDE.md
    ├── .cursorrules
    ├── .github/copilot-instructions.md
    ├── AI.md
    ├── LLM.md
    └── CONTEXT.md
```

## Discovery Order

LLM tools should look for context in this order:

1. `AGENTS.md` (universal, preferred)
2. `AI_CONTEXT.md` (this file, meta)
3. `CONVENTIONS.md` (style guide)
4. `README.md` (project overview)
5. Provider-specific files (`.claude/`, `.cursorrules`, etc.)

## Why Universal?

- **Portable**: Works across IDEs and LLM providers
- **Maintainable**: Single source of truth
- **Discoverable**: Standard filename
- **Human-readable**: Also serves as documentation

## Cosmic Convention

Following Cosmopolitan's philosophy: write once, run everywhere.
Same principle applied to LLM context: write once, understood everywhere.

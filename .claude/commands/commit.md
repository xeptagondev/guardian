---
description: Generate commit following project conventions
allowed-tools: Bash(git:*)
---

!git status
!git diff

Review all changes above. Selectively stage ONLY files relevant to the current task, then create a commit following /docs/commit.md guidelines:

## Format
```
<emoji> <type>: <short description>

<optional body for complex changes>
```

## Types
- ✨ feat: New feature
- 🐛 fix: Bug fix
- 🔧 improve: Enhancement to existing feature
- ♻️ refactor: Code restructure (no behavior change)
- 🎨 style: UI/styling changes
- ⚡ perf: Performance improvement
- 🧹 chore: Maintenance, deps, config
- 📝 docs: Documentation
- 🧪 test: Tests

## Rules
- **Never mention Claude Code** in commit messages
- Keep subject under 50 chars
- Use imperative mood ("Add" not "Added")
- No period at end
- Only commit files relevant to current task
- Add body only for complex changes
- **Always sign the commit** with `git commit -S` (GPG/SSH signed)

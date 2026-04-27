---
description: Update docs/structure.md with current codebase structure
allowed-tools: Bash(tree:*), Read, Edit, Glob
---

Update the /docs/structure.md file to reflect the current codebase structure.

## Process

1. **Run tree** to get current structure:
   ```bash
   tree -I 'node_modules|dist|.git|coverage|.nuxt|.output|playwright-report|test-results|*.log' --dirsfirst -L 4
   ```

2. **Read current structure.md** at /docs/structure.md

3. **Compare and identify differences**:
   - New files/folders that need to be added
   - Removed files/folders that need to be deleted
   - Moved files that need path updates

4. **Make granular edits** using the Edit tool:
   - DO NOT rewrite the entire document
   - Make small, targeted changes for each difference
   - Preserve existing descriptions and comments
   - Add descriptions for new files based on their content

5. **Update the "Last updated" date** at the top

## Rules
- Only update what has changed
- Keep existing descriptions intact
- Add brief descriptions for new files (inspect them if needed)
- Maintain the existing formatting style
- Update the date to today's date

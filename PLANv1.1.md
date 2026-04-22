# Command Wizard v1.1 — Import Robustness + Safe Persistence

**Summary**
Harden the help importer so complex CLIs (node, cloudflared) parse actions/params reliably, and fix save/history persistence so it never fails in Program Files. Add a small import review flow to make “edit before save” explicit, plus light UX labeling cleanup.

**Key Changes**
1. **Help importer parsing**
   1. Update `HelpTextParser` to keep “commands” mode active when encountering nested headers (e.g., `Access:` / `Tunnel:`) instead of exiting command parsing. Only exit when a new top-level section like `OPTIONS`, `GLOBAL OPTIONS`, or `FLAGS` starts.
   2. Support multi‑line option descriptions: if a line does not match the flag regex but is indented and follows a flag line, append to the previous description.
   3. Add a `ParseParametersFromUsage` step:
      - Extract usage lines (`Usage:` / `usage:`).
      - Identify positional tokens (e.g., `script.js`, `arguments`, `<command>`, `[arguments]`).
      - Create `SchemaParameter` entries with `Required = true` when token is not bracketed, else `false`.
   4. Handle aliases in action lines like `help, h` or `access, forward` by keeping the first token as the action `Name` and appending alias text into `Description` so we don’t lose the action.

2. **Import workflow (edit-before-save)**
   1. Extend `ImportHelpWindow` with a toggle: “Run help command” vs “Paste help text”.
   2. When “Paste help text” is selected, pass the raw text directly to the parser (no process invocation).
   3. After import, open Schema Editor and show a brief “Imported (unsaved)” banner + summary counts (actions/flags/parameters).
   4. Add a “Discard Imported Schema” action that removes the unsaved tool from the list without touching disk.

3. **Persistence & permissions**
   1. Move history and schema storage under user data:
      - Base folder: `Environment.SpecialFolder.LocalApplicationData\Aptlantis\CommandWizard`
      - Paths: `schemas\` and `history.json`
   2. Add `try/catch` around schema save and history append so failures surface as message boxes and do not exit the app.
   3. Keep app base directory as a fallback only when it is writable (optional check).

4. **UX polish**
   1. Rename “Generate” to “Save” in:
      - Button label
      - Menu text
      - Message box wording (“Command saved to history” stays, but label becomes “Save”).
   2. Keep the command shortcut `Ctrl+G` unless you want to switch it to `Ctrl+S` later.

5. **UI kit shortlist (non-code evaluation)**
   - WinUI Gallery (official patterns, components)
   - Windows App SDK Samples (real-world windowing + styling patterns)
   - WinUI Community Toolkit (utility controls, behaviors)
   - Third-party (if desired): Syncfusion WinUI, DevExpress WinUI

**Test Plan**
1. Add tests in `CommandWizard.Tests`:
   - Parse winget help: assert actions include `install`, `search`, `list`, etc., and options include `--verbose`, `--no-proxy`.
   - Parse node help: assert parameters include `script.js` and `arguments`, plus many options parsed.
   - Parse cloudflared help: assert actions include `access` and `tunnel` (from nested sections).
2. Use the file at `A:\AptWeb\zypper-operations\Archive-Hasher\HelpLists.txt` as test fixture input (copy into test data or embed as a resource).

**Assumptions**
- We will use the provided `HelpLists.txt` as the primary parser regression test input.
- Default storage should move to `%LocalAppData%` for safe writes; app-dir storage is optional fallback.
- “Edit before save” is satisfied by an explicit “Imported (unsaved)” state + discard option rather than a full pre-save diff UI.

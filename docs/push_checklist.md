# ScamAppScan Push Checklist

Use this checklist to publish the current work tree to the `scamAppScan_codex` branch on GitHub.

1. Verify that you are on the correct branch:
   ```bash
   git status -sb
   ```
   The output should show `## scamAppScan_codex`.
2. Confirm that the working tree is clean or contains only the changes you intend to ship:
   ```bash
   git status
   ```
3. Run the basic lint/compile checks to ensure nothing obvious is broken:
   ```bash
   python -m py_compile Web/app/analysis_service.py Web/app/blueprints/api/views.py Web/app/utils/apkAnalyzer.py
   ```
4. Stage and commit any outstanding changes:
   ```bash
   git add <paths>
   git commit -m "<your message>"
   ```
5. Push the branch upstream:
   ```bash
   git push origin scamAppScan_codex
   ```
6. If the branch already exists remotely and you need to update it, use a safe force push:
   ```bash
   git push --force-with-lease origin scamAppScan_codex
   ```
7. Share the resulting commit hash or GitHub link with your collaborators.

Documenting each step in the project notes will make future releases faster and easier to audit.

# Publishing ashadow07/karmadue-action (Adam approves; nothing has been created or pushed)

Files are ready in `/workspace/karmadue/integrations/github-action-repo/` (the repository root). Tests: `npm test` (20 pass, 1 live test skipped) and `npm run test:live` (21 pass).

```sh
cd /workspace/karmadue/integrations/github-action-repo
git init -b main && git add -A && git commit -m "KarmaDue guard v1.0.0"
gh repo create ashadow07/karmadue-action --public --source . --push \
  --description "Fail PRs that add malicious packages or MCP servers; warn on advisories and recent owner/license/tool-list changes. No token."
git tag -a v1.0.0 -m v1.0.0 && git tag -f v1 && git push origin v1.0.0 v1
```

Marketplace: open the repo → Releases → Draft a new release → tag v1.0.0 → tick "Publish this Action to the GitHub Marketplace" (requires accepting the Marketplace agreement once; the action name "KarmaDue package and MCP guard" must be unique on the Marketplace). Category: Security.

After publishing: move `v1` on each compatible release (`git tag -f v1 && git push -f origin v1`), and remove "(source ready, not yet published)" from llms.txt.

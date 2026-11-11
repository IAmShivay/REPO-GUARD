# REPO-GUARD

Hourly GitHub Action that watches every IAmShivay repo and opens an issue (GitHub emails you) when:

- a branch is force-pushed or deleted
- an account other than IAmShivay or Dependabot pushes
- a lock ruleset (`lock-all-branches`, `main-only-via-pr`, `lock-all-tags`) is turned off, deleted, or given a bypass
- a repo goes missing or changes visibility
- a push lands PolinRider malware patterns on the default branch

It uses only the workflow's built-in token, so it stores no secrets.
Add a new repo to `REPOS` in `guard.py` when you create one.

# DevSkim detection test — expected vs. found

Test file: `security-test/DevSkimTestCases.cs`
Run date: _fill in_
Workflow run: _link to Actions run_

| # | Vulnerability planted | Line | DevSkim rule ID expected (approx.) | Found? | Severity reported | Notes |
|---|---|---|---|---|---|---|
| 1 | Hardcoded credentials (password, API key) | 25-26 | `DS173237` / `DS117838`-family (hardcoded secret) | | | |
| 2 | Weak hash (MD5) for password | 30-34 | `DS126858` (weak hash) | | | |
| 3 | Insecure randomness (`System.Random` for token) | 38-41 | `DS148264` (insufficient randomness) | | | |
| 4 | SQL injection (string concat into `SqlCommand`) | 45-50 | `DS181812` / SQLi pattern | | | |
| 5 | Command injection (`Process.Start` with user input) | 54-57 | `DS104456`-family (process injection) | | | |
| 6 | Path traversal (`File.ReadAllText` + concat) | 61-63 | may or may not be flagged — path traversal needs dataflow, DevSkim is pattern-only | | | |
| 7 | Insecure deserialization (`BinaryFormatter`) | 67-71 | `DS440000` (BinaryFormatter obsolete/dangerous) | | | |
| 8 | XXE (`XmlDocument` + `XmlUrlResolver`) | 75-79 | XXE-pattern rule | | | |
| 9 | Disabled TLS certificate validation | 83-87 | cert-validation-bypass rule | | | |
| 10 | Forced obsolete TLS (SSL3) | 91-94 | obsolete-protocol rule | | | |

## How to fill this in

1. Push this branch: `git push -u origin security/devskim-test-vulns`
2. Open the PR (or just check the push-triggered run, since `decskim.yml` fires on both `push` and `pull_request`).
3. Go to the Actions tab → the DevSkim run → check the job log for what it scanned.
4. Go to repo **Security → Code scanning alerts** — this is where `upload-sarif` publishes DevSkim's findings, filtered by branch.
5. For each row above: mark Found = yes/no, note the actual rule ID DevSkim reports (it won't necessarily match my guesses above — I don't have DevSkim's exact rule ID list memorized, treat those as placeholders to fill with real output), and the severity it assigned.
6. Anything in the "Found" column that's blank/no is a **gap** — useful evidence for the Semgrep/Roslyn/SecurityCodeScan comparison.

## Cleanup

Once the comparison is documented, delete `security-test/` entirely before merging anything back toward main —
this code must never land in a real branch beyond this test one.

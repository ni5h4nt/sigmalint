# Reporting a vulnerability

sigmalint is used inside CI pipelines by red and blue teams. If you find a defect that could be exploited — for example, a crafted Sigma rule that crashes the linter or causes a hang — please report it privately rather than opening a public issue.

## How to report

Use GitHub's private security advisory workflow:

1. Open <https://github.com/ni5h4nt/sigmalint/security/advisories/new>
2. Describe the issue with a minimal reproducer (a small Sigma YAML file is usually enough).

If you cannot use GitHub advisories, email `nishant.tyagi@gmail.com` with `sigmalint security` in the subject.

## What to expect

- Acknowledgement within 7 days.
- A coordinated fix and disclosure timeline, typically 30–90 days depending on severity.
- Credit in the release notes unless you prefer to remain anonymous.

## Out of scope

- False positives or false negatives in lint rules — those belong in regular issues.
- Vulnerabilities in dependencies — please report those to the upstream project (we will update pins).

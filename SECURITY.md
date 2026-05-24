# Reporting a vulnerability

sigmalint is used inside CI pipelines by red and blue teams. If you find a defect that could be exploited — for example, a crafted Sigma rule that crashes the linter, causes a hang, or makes the score drop arbitrarily — please report it privately rather than opening a public issue.

## How to report

**Email is the primary channel today.** Send to `nishant.tyagi@gmail.com` with `sigmalint security` in the subject. Include a minimal reproducer (a small Sigma YAML file is usually enough) and the sigmalint version (`sigmalint --version`).

Once the project is public (currently pending the v0.1.0 release), GitHub's private security advisory workflow will also be available at:

- <https://github.com/ni5h4nt/sigmalint/security/advisories/new>

While the repository is private, that URL is unavailable and email is the only path.

## What to expect

- Acknowledgement within 7 days.
- A coordinated fix and disclosure timeline, typically 30–90 days depending on severity.
- Credit in the release notes unless you prefer to remain anonymous.

## Out of scope

- False positives or false negatives in lint rules — those belong in regular issues.
- Vulnerabilities in dependencies — please report those to the upstream project; we will update the pin.

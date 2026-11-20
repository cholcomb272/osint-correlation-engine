# Independent clean-install and evidence review

An independent review must be performed by someone who did not implement the
change under review. The supplied automation proves reproducibility on a fresh
Compose project; it does not turn the implementer into an independent reviewer.

## Reviewer prerequisites

- A clean Linux host or disposable VM with Docker Engine and Compose v2
- Git, curl, and Python 3
- No copy of the maintainer's `.env`, database volume, or private deployment data
- Network access to GitHub and the documented public data sources

Run the current public tag or commit:

```bash
git clone https://github.com/cholcomb272/osint-correlation-engine.git
cd osint-correlation-engine
REVIEW_REF=v0.2.0-alpha.1 scripts/clean-install-review.sh
```

If Docker access on the review host requires sudo, set
`OSINT_DOCKER_SUDO=1` for that command.

The script clones the requested ref again into a temporary directory, creates
four independent one-time secrets, uses a unique Compose project and host port,
waits for readiness, exercises public endpoints, and runs the versioned
correlation benchmark. It then deletes only that temporary Compose project and
volume. Evidence is saved under the invoking checkout's ignored `artifacts/`
directory; generated secrets are not copied into the bundle.

## Human review checklist

1. Confirm a clean clone builds without local files or cached application data.
2. Confirm the dashboard loads without credentials and admin operations reject
   an absent or invalid bearer token.
3. Open several topology edges. Verify inferred edges are visually and verbally
   distinct from direct observations and confirmed dependencies.
4. Check that scheduled maintenance, future events, policy announcements, and
   security advisories do not appear as active operational correlations.
5. Verify two feeds using the same observation modality are not described as
   independent technical corroboration.
6. Inspect the coverage panel. Confirm it reports actual monitored prefixes,
   ASNs, modalities, intervals, missing incident scope, and limitations.
7. Re-run `python -m app.cli benchmark`; report every failing scenario rather
   than editing expected values to match a regression.
8. Review the generated topology JSON for unsupported causal language,
   sensational attribution, or evidence-source confusion.
9. Verify `.env`, generated logs, backups, private IPs, and internal hostnames
   are absent from tracked files and container build contexts.
10. Record the exact commit, host architecture, Docker versions, commands,
    deviations, failures, and screenshots in the report template.

## Review outcome

Use [the independent review report template](INDEPENDENT_REVIEW_REPORT.md). A
maintainer may fix findings, but only the external reviewer should sign the
independence declaration or state that the review is complete.

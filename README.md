# AuthTrail

A local-only Python command-line tool for summarizing common OpenSSH authentication events from an authorized log file. It counts failed and successful events and flags sources with repeated failures for human review. It does not connect to systems, block addresses, or label activity as malicious.

## Requirements

Python 3.9+; standard library only.

## Use

```bash
python -m authtrail.cli sample-auth.log --threshold 5
```

The input should contain common OpenSSH messages such as `Failed password for ... from ...` and `Accepted publickey for ... from ...`. Threshold counts apply to the entire supplied file, not a time window. Treat output as a triage aid, not an incident conclusion.

## Tests

```bash
python -m unittest discover -s tests -v
```

## AI assistance

This initial starter implementation was created with AI assistance. Review, test, and extend it before representing the work as your own.

## Scope and privacy

- Reads one local file; makes no network connections and performs no automatic response.
- Log data may contain personal or operational information. Sanitize samples and avoid committing production logs.
- Use only logs you are authorized to access.

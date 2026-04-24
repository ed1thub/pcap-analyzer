# Contributing

Thanks for your interest in contributing to PCAP Analyzer.

## Getting Started

1. Fork the repository.
2. Create a feature branch from `main`.
3. Run the app locally with `./run.sh`.
4. Make your changes with clear commits.
5. Open a pull request.

## Local Validation

1. Ensure backend modules compile:
   - `cd backend && ./venv/bin/python -m py_compile analyzer.py main.py`
2. Start the app and verify dashboard behavior:
   - `./run.sh`
3. If you change docs, verify links and screenshots render.

## Pull Request Guidelines

- Keep PRs focused and small.
- Describe what changed and why.
- Include screenshots for UI changes.
- Update README and docs when behavior changes.
- Add sample data updates only when necessary.

## Coding Notes

- Preserve existing API response fields unless a change is intentional and documented.
- Prefer backward-compatible changes for frontend/backend contracts.
- Avoid committing generated runtime artifacts (logs, uploads, cache files).

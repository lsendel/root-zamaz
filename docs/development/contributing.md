# Contributing Guidelines

Thank you for taking the time to contribute! This project welcomes pull requests from the community. The following guidelines help keep the process smooth.

## Getting Started

1. Fork the repository and clone your fork.
2. Create a feature branch using a descriptive name: `git checkout -b feat/my-change`.
3. Run `make dev-setup` to install dependencies and hooks.

## Development Workflow

- Follow the [Code Style Guide](code-style.md) for Go and TypeScript conventions.
- Write or update tests for any code you change. Run `make test` to ensure all tests pass.
- Use `make fmt` and `make lint` before committing.
- Keep commits focused and use [Conventional Commits](https://www.conventionalcommits.org/).

## Pull Requests

1. Ensure your branch is up to date with `main`.
2. Open a draft PR early if you'd like feedback.
3. Fill out the PR template, describing the change and linking related issues.
4. Verify CI checks pass. Run `make quality-check` locally to catch issues early.
5. Request review from maintainers once ready.

## Code Reviews

- Reviews focus on correctness, readability, and alignment with project goals.
- Address all comments or questions before merging.
- Squash or rebase if necessary to keep history clean.

## Reporting Issues

If you encounter a bug or have a feature request, please open an issue with detailed steps to reproduce or a clear description of the desired behavior.

## Community

Join the discussion in GitHub issues to ask questions or share ideas. We appreciate all contributions, whether code, documentation, or feedback.


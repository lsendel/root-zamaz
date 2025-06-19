# Code Style Guide

This document outlines the coding standards used throughout the project for both Go and TypeScript code.

## Go Guidelines

- **Formatting**: All Go code must be formatted using `goimports`. Run `make fmt` before committing.
- **Linting**: We use `golangci-lint` with the configuration in `.golangci.yml`. Run `make lint` to check for issues.
- **Error Handling**: Prefer wrapped errors using `fmt.Errorf("context: %w", err)`.
- **Testing**: Table-driven tests are encouraged. Aim for 80% coverage or higher.
- **Packages**: Keep packages focused. Avoid cyclic dependencies and use internal packages when code should not be consumed externally.

## TypeScript Guidelines

- **Formatting**: The repository uses Prettier. Run `npm run format` in the `frontend` directory.
- **Linting**: ESLint rules are enforced via `npm run lint`.
- **Components**: Use functional React components and hooks. Keep files under 300 lines when possible.
- **Types**: Prefer explicit types and interfaces. Avoid `any` except in tests or temporary code.

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/). Example:

```
feat(auth): add JWT middleware
```

Type scopes should match package or feature areas. Use the imperative mood and keep the summary under 72 characters.

## Pull Requests

- Keep PRs focused and small when possible.
- Reference relevant issues in the description.
- Ensure `make quality-check` and all tests pass before requesting review.


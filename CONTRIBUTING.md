# Contributing to Root Herald

Thanks for your interest in contributing.

## Getting set up

Each repo's `README.md` has its own setup instructions. Generally:

```bash
git clone https://github.com/RootHerald/<repo>.git
cd <repo>
# follow the language-specific build steps in README
```

## Reporting issues

- Open a GitHub issue with a minimal reproduction (code, version, OS, error output).
- For **security** issues, do **not** open a public issue — see [SECURITY.md](./SECURITY.md).

## Pull requests

- Open a PR against `main`.
- Include a clear description of the change and why.
- All checks (build, tests, lint) must pass.
- Maintainers review and merge; squash-merge is the default.

## Commit messages

Conventional Commits are encouraged but not required. The most important thing is that the PR description explains the change.

## Code style

Match the existing style in each file. Each repo's CI runs language-idiomatic linters; if it passes lint, that's enough.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE) the same as this repository.

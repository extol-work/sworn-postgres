# Contributing to sworn-postgres

Pre-alpha. Scaffold-only during Week 1 of implementation (early August 2026). Real contribution paths open once the first PR lands with directory structure and a chosen language.

## What we're building

A reference implementation of [SWORN v0.1](https://github.com/extol-work/sworn). Scope in [SCOPE.md](./SCOPE.md), timeline in [ROADMAP.md](./ROADMAP.md).

## What we're looking for once contribution opens

- **Spec ambiguity reports:** if you tried to implement a section of SWORN and the reference implementation disagrees with your reading, file an issue here AND in [extol-work/sworn](https://github.com/extol-work/sworn/issues) with the `ambiguity` label. Cross-linked issues get resolved fastest.
- **Conformance test contributions:** adding new tests to `conformance/` that would catch a class of implementation bug we haven't thought of.
- **Additional language bindings:** once we ship, second and third implementations in different languages are the highest-signal way to stress the spec. If you're building one, we want to know.

## What we're NOT looking for

- Feature additions beyond [SCOPE.md](./SCOPE.md). "Reference" means minimal-conforming; features live in derivative implementations.
- Blockchain integrations, HD wallets, multi-tenancy, auth systems. Those belong in Extol's production implementation, not the reference.
- Framework migrations, dependency swaps, or "let's rewrite in X" PRs. Language choice happens once in Week 1 and doesn't change.

## Reporting bugs

Standard GitHub issue with the bug reproduction. Include:

- Version (git commit hash of the sworn-postgres you're running)
- Version of SWORN spec you're implementing against
- Reproduction steps (docker-compose logs help)
- Expected vs. actual behavior

## Code of conduct

Same as [extol-work/sworn/CONTRIBUTING.md](https://github.com/extol-work/sworn/blob/main/CONTRIBUTING.md#code-of-conduct). Disagreement welcome, disrespect not.

## License

Contributions are Apache 2.0. By opening a PR you agree to license your contribution under Apache 2.0.

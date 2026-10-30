# Contributing

Contributions are welcome! Here's how you can help.

## Development Setup

1. Fork and clone the repository
2. Install dependencies: `npm install`
3. Make your changes
4. Run type checking: `npm run typecheck`
5. Run linting: `npm run lint`
6. Test the build: `npm run build:all`
7. Submit a pull request

## Code Style

- Use TypeScript strict mode
- Follow existing code patterns
- Add JSDoc comments for public APIs
- Use meaningful variable names

## Commit Messages

Use conventional commits format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Tests

## Pull Requests

1. Create a feature branch from `main`
2. Make focused, atomic commits
3. Update documentation if needed
4. Ensure all checks pass
5. Request review

## Scripts

```bash
npm run build            # Build for Chrome
npm run build:firefox    # Build for Firefox
npm run build:all        # Build for both
npm run zip              # Build Chrome + create ZIP
npm run zip:firefox      # Build Firefox + create ZIP
npm run zip:all          # Build both + create both ZIPs
npm run clean            # Remove dist directories
npm run test             # Run tests
npm run test:e2e         # Load the built extension in Chromium and drive the popup
npm run lint             # Run ESLint
npm run typecheck        # TypeScript check
npm run version:bump     # Sync version across all manifests (run before tagging)
npm run capture          # Re-generate screenshots and demo video
```

## Releasing

```bash
npm run version:bump 0.9.0     # sync version across manifests + lockfile
# update CHANGELOG.md with the new version's notes
npm run lint
npm run typecheck
npm test
npm run test:e2e
npm run build:all
PASSKEY_VAULT_RELEASE=1 npm run zip:all
PASSKEY_VAULT_RELEASE=1 npm run validate:packages
git commit -am "Release Fenko Vault 0.9.0"
git tag v0.9.0
git push origin main
git push origin v0.9.0
```

The CI pipeline builds both extensions, publishes to the Chrome Web Store, and creates a GitHub release. Release notes come from the matching `## [x.y.z]` section in `CHANGELOG.md`.

`PASSKEY_VAULT_RELEASE=1` makes a build a store package, as in the release workflow: its version is the plain `x.y.z`, and its manifest has no `key`. Every other build is a development build. Its version names its commit, such as `0.12.0+2d873fb`, with `.dirty` when tracked files have uncommitted changes; Chrome shows it on `chrome://extensions` and in the options page. Its manifest carries a development key, so every development build gets the extension ID `opnaemnnjkoolijgdldhjfinpjmhkagi` and keeps its vault when a newer build is loaded from another folder. `npm run validate:packages` accepts either kind, and only a store package when the variable is set. `npm run capture` needs a release build in `dist/`, so that the screenshots show the plain version.

Store listing copy and upload assets live in `docs/cws/`.

## Security Issues

For security vulnerabilities, please open a private issue or contact the maintainer directly rather than posting publicly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

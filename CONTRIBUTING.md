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
npm run zip:all
npm run validate:packages
git commit -am "Release Fenko Vault 0.9.0"
git tag v0.9.0
git push origin main
git push origin v0.9.0
```

The CI pipeline builds both extensions, publishes to the Chrome Web Store, and creates a GitHub release. Release notes come from the matching `## [x.y.z]` section in `CHANGELOG.md`.

Store listing copy and upload assets live in `docs/cws/`.

## Security Issues

For security vulnerabilities, please open a private issue or contact the maintainer directly rather than posting publicly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

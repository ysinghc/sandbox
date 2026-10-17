# Contributing

Thanks for your interest in Sandbox Engine. This is a small, systems-level
project; please keep changes focused and well explained.

## Ground rules

- **Match the codebase.** Follow the existing C11/C++17 style, naming, and file
  layout. Keep functions and comments in the same voice as their neighbours.
- **Document deviations.** If the implementation must differ from
  [`SYSTEM DESIGN.md`](SYSTEM%20DESIGN.md), record it in the appropriate `§15`
  subsection and in [`docs/IMPLEMENTATION_LOG.md`](docs/IMPLEMENTATION_LOG.md).
- **Keep the design honest.** When behavior changes, update the affected design
  section and the docs in `README.md` / `docs/` in the same change.

## Getting set up

See [`docs/BUILDING.md`](docs/BUILDING.md) for dependencies and build options,
and [`docs/TESTING.md`](docs/TESTING.md) for how to run the suite (most
end-to-end tests need root + KVM + assets).

Minimum before opening a PR:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build --output-on-failure          # as root on a prepared host

# Sanitizer pass
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSANDBOX_SANITIZE=address,undefined
cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure
```

## Pull requests

1. Branch from `master`.
2. Keep commits atomic and give each a clear, imperative subject.
3. Make sure CI passes (build, ASan/UBSan tests, fuzz smoke). The privileged
   tests run on a lab host — state in the PR how you validated them.
4. Update docs and [`CHANGELOG.md`](CHANGELOG.md) when behavior changes.

## Reporting bugs and requesting features

Open an issue with: what you expected, what happened, the exact commands, and
`uname -a`, the engine version (`sandboxd --version`), and relevant log lines
(structured JSON on stderr / `journalctl -u sandboxd`). For security-sensitive
issues, avoid pasting credentials or tokens.

## License

By contributing you agree that your contributions are licensed under the
**GNU General Public License v2** (`GPL-2.0-only`). See [`LICENSE`](LICENSE).

<!-- Rendered in the docs book. The source of truth is CONTRIBUTING.md in the repository root. -->
{{#include ../CONTRIBUTING.md}}

## Development commands

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release --target x86_64-unknown-linux-musl    # needs musl-tools
```

New package managers implement the `Manager` trait in `src/managers/mod.rs`
(`capture`, `installed`, `prepare`, `plan`, `key_of`) and add a purl mapping
in `src/sbom.rs`.

## Working on these docs

The pages live in `docs/` and are built with [mdBook](https://rust-lang.github.io/mdBook/):

```sh
cargo install --locked mdbook
mdbook serve book --open        # live preview
mdbook build book               # output in target/book
```

The table of contents is `docs/SUMMARY.md`. The brand styles are in
`book/theme/matsya.css`. Links between pages use relative `.md` paths so they
work both on GitHub and on the website.

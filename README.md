This document is built using Rust's
[mdbook](https://github.com/rust-lang/mdBook) tool and the [katex
preprocessor](https://github.com/lzanini/mdbook-katex) for rendering LaTeX.

```
# Install the binaryi
cargo install mdbook
# Install LaTeX preprocessor
cargo install mdbook-katex
# Build HTML (need the cargo bin directory in your $PATH)
mdbook build
```

When editing, you can run a server that listens for changes to the source and
re-renders it in real time:

```
mkbook serve
```

This document is built using Rust's
[mdbook](https://github.com/rust-lang/mdBook) tool.

```
cargo install mdbook # Install the binary
mdbook build         # Build HTML (need the cargo bin directory in your $PATH)
```

When editing, you can run a server that listens for changes to the source and
re-renders it in real time:

```
mkbook serve
```

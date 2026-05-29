# third_party/pixma — placeholder

This repo interoperates with the `leecher1337/pixma` firmware-decrypt lineage but does
**not** vendor its source. See `../../INTEROP.md`.

When the firmware dispatch-table cross-check workflow lands (T2/T3), wire the working
fork in here as a git submodule:

```sh
git submodule add https://github.com/jesssullivan/pixma third_party/pixma
```

Built binaries and any Canon firmware blobs are gitignored — no redistribution.

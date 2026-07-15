# Implant ISOB3 — GitHub Action

Composite action that implants BLAKE3 (**ISOB3**) integrity metadata into an
ISO9660 image and verifies it, using the prebuilt `blake3iso` binary from this
repository's public releases. No build step, no token required.

## Usage

```yaml
jobs:
  build-iso:
    runs-on: ubuntu-latest   # Linux x86_64 runner required
    steps:
      - uses: actions/checkout@v4

      # ...produce an ISO somewhere in the workspace, e.g. build/mydisc.iso...

      - name: Implant ISOB3
        id: isob3
        uses: AmentumCMS/ISOB3TOOLS/.github/actions/implant-isob3@main
        with:
          iso_path: build/mydisc.iso

      - name: Show digest
        run: echo "Implanted digest: ${{ steps.isob3.outputs.digest }}"
```

Pin `@main` to a tag or commit SHA once you cut a version (e.g. `@v1`).

## Inputs

| Input      | Required | Default    | Description                                                        |
|------------|----------|------------|--------------------------------------------------------------------|
| `iso_path` | yes      | —          | Path to the ISO to implant, relative to the workspace.             |
| `force`    | no       | `false`    | Overwrite existing application-use metadata (passes `--force`).    |
| `version`  | no       | `latest`   | ISOB3TOOLS release tag to pull `blake3iso` from, or `latest`.      |

## Outputs

| Output   | Description                                          |
|----------|------------------------------------------------------|
| `digest` | The BLAKE3-256 digest implanted into the ISO (hex).  |

## Notes

- **Linux x86_64 only.** The action downloads the `linux-x86_64-gnu` release
  asset and fails fast on other runners.
- `version: latest` resolves the newest release **including prereleases**
  (ISOB3TOOLS publishes its `build-*` releases as prereleases). Pin a specific
  release tag (e.g. `version: build-69`) for reproducibility.

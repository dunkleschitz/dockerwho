# Changelog — dockerwho

## v1.0.0 (2026-10-23)

- Initial release. `dockerwho IMAGE` resolves an image reference to its
  fully-qualified form (registry/repository/tag/digest with defaults
  surfaced) and reports which credential source docker will consult:
  `credHelpers` → `credsStore` → `auths[canonical key]`.
- Docker Hub canonical key `https://index.docker.io/v1/` modeled;
  non-canonical key forms surface as D02.
- Hygiene rules D01–D06 (no-credential error, key-form mismatch,
  cloud-only global helper vs docker.io, base64 blob storage,
  world-readable config, implicit-defaults info, empty-entry info).
- `--list` mode: every registry with configured credentials.
- Safety is structural: stored credentials never decoded, helpers never
  invoked, no registry ever contacted; 25 hermetic tests incl. a
  never-decodes and a never-invokes test.

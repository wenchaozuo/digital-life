# D22-D2 Cubism Core provenance record

Verification date: 2026-08-29

The production Core identity was verified from the official Live2D
distribution package:

- Product: Cubism SDK for Web
- Release: Cubism 5 SDK for Web R5 (`5-r.5`)
- Official package: `CubismSdkForWeb-5-r.5.zip`
- Official release date: 2026-04-02
- Package-relative Core path: `Core/live2dcubismcore.min.js`
- Core size: 228,042 bytes
- Core SHA-256: `8741f739779b5d5210872bd3d7d99f0f1e56e6c87409e7d26d6bb4b80aa1ef47`
- Package size: 20,708,681 bytes
- Package SHA-256: `67064a7fb1812cf502f5c4a03bfe12cc638c75a621bb4acf06bb28763df06ba0`

The local package was obtained from the official Live2D Cubism SDK
distribution. `cubism-info.yml` identifies the package version as `5-r.5`;
the package changelog identifies the `5-r.5` release as 2026-04-02; and the
Core README identifies `live2dcubismcore.min.js` as the production file.

The Core hash was computed from the extracted local bytes with both Windows
`certutil -hashfile ... SHA256` and Python `hashlib.sha256`; both produced the
exact lowercase value recorded above. The archive hash was independently
checked with the same two mechanisms.

The SDK archive and proprietary Core bytes are external inputs and are not
committed, copied into the repository, or bundled into the frontend. Public or
commercial release remains subject to the applicable Live2D SDK and
Publication License requirements.

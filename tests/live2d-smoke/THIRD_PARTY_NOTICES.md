# D21 browser smoke third-party notice

This directory is a test-only browser smoke harness. It does not add Live2D
models or Cubism Core to the digital-life product, package assets, or release.

## PixiJS and the test adapter

- `pixi.js` 8.20.0 is distributed under the MIT License:
  <https://github.com/pixijs/pixijs/blob/v8.20.0/LICENSE>
- `@jannchie/pixi-live2d-display` 1.4.0 is distributed under the MIT License:
  <https://github.com/Jannchie/pixi-live2d-display/blob/v1.4.0/LICENSE>

## Live2D sample models

The smoke selector loads Haru, Mark, and Rice from the official
`Live2D/CubismWebSamples` repository at pinned commit
`b1de66b0b1f1cb881d95fb6158622aeb6a2827bd` using official raw URLs. The model
files, textures, motions, physics, and sounds are not redistributed or
committed by digital-life.

These official sample data are used only for this local feasibility smoke.
They are subject to the Live2D Free Material License Agreement and the
individual sample model terms. They are not MIT-licensed or otherwise
open-source assets. Terms:

- <https://www.live2d.com/eula/live2d-free-material-license-agreement_en.html>
- <https://www.live2d.com/learn/sample/model-terms/>
- <https://raw.githubusercontent.com/Live2D/CubismWebSamples/b1de66b0b1f1cb881d95fb6158622aeb6a2827bd/LICENSE.md>

Required sample attribution notice:

> 本作品のキャラクターには株式会社Live2Dの著作物であるサンプルデータが株式会社Live2Dの定める規約に従って用いられています。本作品は制作者の完全な自己の裁量で制作されています。

## Cubism Core

Cubism Core is proprietary Live2D software and is not open-source. The smoke
page references the official hosted
`live2dcubismcore.min.js` only at runtime:

<https://cubism.live2d.com/sdk-web/cubismcore/live2dcubismcore.min.js>

Core is not committed, copied into `src/` or `public/`, or published as a
digital-life asset.

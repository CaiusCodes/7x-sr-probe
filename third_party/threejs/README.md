# three.js r128 (MIT)

`three.min.js` is the unmodified `build/three.min.js` from the npm package `three@0.128.0`.

- npm dist.shasum (tarball sha1): 884dacca6a330e45600a09ec5439283f50b76aa6
- npm dist.integrity: sha512-i0ap/E+OaSfzw7bD1TtYnPo3VEplkl70WX5fZqZnfZsE3k3aSFudqrrC9ldFZfYFkn1zwDmBcdGfiIm/hnbyZA==
- sha256 of three.min.js: 9274bbcec8d96168626c732b5d31c775aa8cfb7eaa0599bec0c175908a2c1ce2

It is inlined into `app/src/main/assets/vision/index.html` by `tools/build-vision-page.sh` and only draws the
Zeekr Vision scene inside the app's WebView. It makes no vehicle calls and, with network loads blocked, cannot fetch anything.

# android/ — svrnty TWA wrapper

Trusted Web Activity shell for `https://svrnty.is`, generated with
[Bubblewrap](https://github.com/GoogleChromeLabs/bubblewrap) (`@bubblewrap/cli@1.25.0`).
This directory is the whole wrapper — the app itself lives on the web.

## How updates work

The APK loads the deployed PWA. **Web changes ship by redeploying the site — no
APK rebuild, no store review.** Rebuild this wrapper only when wrapper metadata
changes: app name, icons, package id, `minSdkVersion`, orientation, or the host
domain. When you do rebuild, bump `appVersionCode` / `appVersionName` in
`twa-manifest.json` — Play requires a strictly increasing `versionCode` per upload.

## Build locally

Prereqs: JDK 17 (`JAVA_HOME` or `/usr/lib/jvm/java-17-*`), Android SDK with
`platforms;android-36`, `build-tools;36.1.0`, `platform-tools`
(`ANDROID_HOME` set — on this repo's dev VM it's `~/Android/Sdk`).

```sh
cd android
echo "sdk.dir=$ANDROID_HOME" > local.properties
./gradlew app:assembleRelease app:bundleRelease
# unsigned APK:  app/build/outputs/apk/release/app-release-unsigned.apk
# unsigned AAB:  app/build/outputs/bundle/release/app-release.aab
```

Sign with the release keystore (see below):

```sh
# use the build-tools version you installed (CI installs 36.1.0):
$ANDROID_HOME/build-tools/36.1.0/apksigner sign \
  --ks svrnty-twa.keystore --ks-key-alias svrnty \
  --ks-pass env:KS_PASS --key-pass env:KS_PASS \
  --out svrnty-1.apk app/build/outputs/apk/release/app-release-unsigned.apk
```

`bubblewrap build` does the same end-to-end but is interactive (prompts for
SDK/JDK paths and the keystore passwords) and falls over on gradle's verbose
output — the gradlew + apksigner path above is what CI uses.

## The signing key is the app identity

`svrnty-twa.keystore` is **not in this repo** (see `.gitignore`). Whoever holds
it can push app updates — losing it means the Play listing can never be updated
again. Keep offline copies; treat it like the forever-key.

- **Play App Signing (recommended):** when you opt in at first upload, Google
  re-signs with its own app cert. You must then add the *Play-managed* cert's
  SHA-256 fingerprint to `public/.well-known/assetlinks.json` — Play Console
  shows it under *Setup → App integrity*. The upload-key fingerprint stays in
  the file too; assetlinks accepts a list.
- **CI builds** read the keystore from repo secrets: `ANDROID_KEYSTORE_B64`
  (base64 of the file), `ANDROID_KEYSTORE_PASSWORD`,
  `ANDROID_KEY_ALIAS_PASSWORD`. See `.github/workflows/android.yml`.

## Digital Asset Links

`public/.well-known/assetlinks.json` binds `is.svrnty.app` to this domain.
It is what makes the app open full-screen instead of a Chrome tab. The file
ships with the site's deploy — if the domain or signing cert changes, update it.

## Deliberate choices

- `packageId: is.svrnty.app` — matches assetlinks.
- `minSdkVersion 24` — floor required by `androidbrowserhelper`.
- No geolocation permission — svrnty is I-4 reachability-not-location; the
  wrapper must not request what the product refuses to render.
- `display: standalone` — app chrome/status bar preserved.
- `enableNotifications: false` — the web app requests no Notification/push
  APIs, so the POST_NOTIFICATIONS permission + delegation service were stripped
  rather than shipped as dead surface.
- Icons generated from `public/icon-512.png` / `icon-512-maskable.png`
  (committed under `public/`).

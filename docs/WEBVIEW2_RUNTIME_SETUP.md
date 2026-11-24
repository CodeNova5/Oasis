# WebView2 Runtime Setup and Deployment

The Data Saver preview page is hosted in an embedded Microsoft Edge WebView2
control. This note covers what a build or installation must provide, and how the
page assets are produced.

## Prerequisites

### WebView2 Runtime (end-user machine)

The Microsoft Edge WebView2 Evergreen Runtime must be installed. It ships with
current Windows 10/11 releases and with Microsoft Edge, so most machines already
have it.

- Evergreen Bootstrapper (small, downloads the runtime):
  https://go.microsoft.com/fwlink/p/?LinkId=2124703
- Evergreen Standalone Installer (offline install):
  https://go.microsoft.com/fwlink/p/?LinkId=2124701

If the runtime is missing, the Data Saver preview page shows a readable failure
message instead of the page; the rest of the application keeps working. The
native Data Saver screen remains the fallback.

The SDK header used at build time lives at
`third_party/webview2/include/WebView2.h` and is the 1.0.4370.26 SDK, which
matches the evergreen runtime.

### WebView2Loader.dll (application folder)

`WebView2Loader.dll` must sit next to `Oasis.exe` (for a release layout,
`bin/WebView2Loader.dll`). The host loads it at runtime with `QLibrary`, so
nothing links against it at build time.

The loader DLL architecture must match `Oasis.exe`:

| Build | Loader required |
| --- | --- |
| 64-bit (Qt `mingw_64` kit) | `WebView2Loader.dll` built for x64 |
| 32-bit (Qt `mingw` kit) | `WebView2Loader.dll` built for x86 |

A mismatched loader fails to load; the preview then reports that
`WebView2Loader.dll` could not be loaded. Take the loader from the NuGet package
`Microsoft.Web.WebView2` (`runtimes/win-x64/native/WebView2Loader.dll`).

`bin/WebView2Loader.dll` is intentionally not committed (the repository ignores
`*.dll`), so packaging and CI must copy it into the output folder alongside
`Oasis.exe`.

## Building the web assets

The page is built from `web/datasaver` with Node:

```bash
cd web/datasaver
npm install --no-audit --no-fund
npm run build
```

`npm run build` (implemented in `web/datasaver/build.mjs`) writes the complete
asset set:

- `web/datasaver/dist/app.js` — bundled, minified Preact/HTM application
- `web/datasaver/dist/app.css` — minified stylesheet
- `web/datasaver/dist/index.html` — page shell with assets referenced relatively

It also refreshes `bin/web/datasaver/dist`.

`web/datasaver/dist` and `bin/web/datasaver/dist` are generated output and are
not committed. Run `npm run build` before a release build (or in the release
job) so the assets exist.

## How the assets reach the build output

`Oasis.pro` adds a post-link rule that creates `$$DESTDIR/web/datasaver/dist`
and copies every file from `web/datasaver/dist` into it after linking. A clean
build therefore produces:

```
<build dir>/bin/Oasis.exe
<build dir>/bin/WebView2Loader.dll   (packaging step, not qmake)
<build dir>/bin/web/datasaver/dist/index.html
<build dir>/bin/web/datasaver/dist/app.js
<build dir>/bin/web/datasaver/dist/app.css
```

The page is always loaded from the executable directory
(`applicationDirPath()/web/datasaver/dist/index.html`), never from the source
tree, and it needs no network access or Node at runtime.

Do not commit the generated `bin/web/datasaver/dist` folder; it is covered by
`.gitignore` and reproduced on every link.

Every path in that rule is wrapped in qmake's `$$shell_quote()`. Project paths
that contain spaces (for example `.../Documents/Next Js/...`) otherwise split
into several arguments and the copy fails with:

```
cp: cannot stat 'Js/Tecrust/.../app.css': No such file or directory
cp: -r not specified; omitting directory '/C/Users/.../Next'
mingw32-make[1]: *** [Makefile.Release:546: bin/Oasis.exe] Error 1
```

That error appears *after* a successful link, so `bin/Oasis.exe` is already
valid; only the asset copy failed. Escaped `\"` quotes in `QMAKE_POST_LINK` are
silently stripped before they reach the Makefile, which is why `$$shell_quote()`
is used instead. Note that make will not re-run the post-link rule on its own
because the executable target is up to date — delete `bin/Oasis.exe` (or do a
clean build) after touching that rule.

## Troubleshooting

| Symptom in the Data Saver preview | Cause |
| --- | --- |
| `WebView2Loader.dll could not be loaded.` | Loader missing next to the exe, or wrong architecture |
| `WebView2 runtime is unavailable (0x...)` | Evergreen Runtime not installed |
| `Data Saver preview assets were not found.` | `bin/web/datasaver/dist` missing; run `npm run build` and relink |
| `WebView2 environment factory is unavailable.` | Loader DLL does not export the expected entry points (old/incorrect DLL) |

A build is only complete once `<build dir>/bin/web/datasaver/dist/` contains
`index.html`, `app.js` and `app.css`. If the folder is missing or empty, the
post-link copy did not run — see the note on paths with spaces above.

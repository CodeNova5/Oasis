# WebView2 + Preact Layout Handoff

## Goal

Prepare the first presentation-only stage of the Ultimate NetGuard AIO UI migration:

- Host a modular Preact + HTM Data Saver layout inside the existing Qt shell.
- Keep the page offline-capable and packaged with the application.
- Use static mock data and local UI state for now.
- Preserve the existing native Data Saver implementation and backend behavior.
- Add the real Data Saver bridge, tickets, telemetry, enforcement integration, and mode migration later.

The product modes shown by the layout are `Off` and `Enforce`. There is no Monitor mode in this stage.

## Completed

### Frontend layout

- Added the Preact/HTM source under `web/datasaver`.
- Added a reusable page shell with:
  - Header and breadcrumb
  - Off/Enforce segmented control
  - Status banner
  - Metric cards
  - Detection table
  - Preview footer state
- Added static display data in `src/mockData.js`.
- Added responsive local CSS with the existing dark Qt visual direction.
- The Off/Enforce control changes only local Preact state.
- No frontend code calls Qt, WebView2 messages, settings, NetworkWidget, WinDivert, QoS, or firewall services.

Relevant files:

- `web/datasaver/src/main.js`
- `web/datasaver/src/App.js`
- `web/datasaver/src/mockData.js`
- `web/datasaver/src/styles.css`
- `web/datasaver/index.html`
- `web/datasaver/dist/index.html`
- `web/datasaver/dist/app.js`
- `web/datasaver/dist/app.css`
- `web/datasaver/package.json`
- `web/datasaver/package-lock.json`
- `web/datasaver/build.mjs` — generates `app.js`, `app.css` and `index.html` in `dist/`

### WebView2 preparation

- Added the SDK header at `third_party/webview2/include/WebView2.h`.
- Confirmed `bin/WebView2Loader.dll` exists beside `bin/Oasis.exe`.
- Added `DataSaverWebPage`, a QWidget boundary that:
  - Dynamically loads `WebView2Loader.dll` with `QLibrary`.
  - Resolves `CreateCoreWebView2EnvironmentWithOptions`.
  - Creates the WebView2 environment and controller asynchronously.
  - Resizes the WebView2 controller with the QWidget.
  - Navigates to the packaged static page.
  - Shows a readable fallback message when the loader, runtime, or assets are unavailable.

Relevant files:

- `src/ui/webview2/datasaverwebpage.h`
- `src/ui/webview2/datasaverwebpage.cpp`
- `src/core/mainwindow_p.h`
- `src/core/mainwindow.cpp`

### Project/build integration

- Added the WebView2 include directory to `Oasis.pro`.
- Added the WebView2 host source and header to `Oasis.pro`.
- Added a `Data Saver` preview destination to the existing stacked Qt shell.
- Kept the original hidden native Data Saver tab alive as the backend/service owner.
- Added the generated web assets to `resources.qrc`.
- Added qmake post-link asset copying to `bin/web/datasaver/dist`.
- Manually verified the runtime asset set exists in `bin/web/datasaver/dist`:
  - `index.html`
  - `app.js`
  - `app.css`

## Validation completed

- `npm install --no-audit --no-fund` completed.
- `npm run build` completed and generated the JavaScript and CSS bundle.
- `rcc --list resources.qrc` showed all three Data Saver assets.
- qmake accepted the WebView2 project changes.
- The new WebView2 source compiled under the installed Qt 6.11.1 MinGW kit.
- `WebView2Loader.dll` and the WebView2 header were found in the expected locations.
- `Oasis.exe` launched and remained running.

The full forced rebuild was intentionally stopped while recompiling the large existing network/backend portion. It had not produced a new WebView2-related error; a clean complete build is still a remaining check. A later clean-build attempt reached ~35 of ~110 translation units with no errors before it was stopped and handed off.

## Important current behavior

- The preview host currently loads `web/datasaver/dist/index.html` from the executable directory.
- It does not use `QWebChannel`.
- It does not use WebView2 `postMessage`.
- It does not read or write Data Saver settings.
- It does not connect to `NetworkWidget`.
- It does not implement Data Saver enforcement.
- The native Data Saver screen and implementation remain unchanged.

## Remaining work, step by step

### Stage 1 completion

Done:

- `npm run build` now generates the complete asset set (`app.js`, `app.css`,
  `index.html`) via `web/datasaver/build.mjs`, and refreshes
  `bin/web/datasaver/dist`. Previously only `app.js` was generated, so a clean
  build would have shipped a page without HTML or CSS.
- Generated assets are no longer committed. `web/datasaver/dist/` and
  `bin/web/datasaver/dist/` were untracked and added to `.gitignore`; both are
  reproduced by `npm run build` and by the qmake post-link rule.
- Build/deployment notes added in `docs/WEBVIEW2_RUNTIME_SETUP.md`: Evergreen
  Runtime prerequisite, x64 loader requirement, asset build step, output
  layout, and a fallback-message troubleshooting table.
- WebView2 fallback messages are actionable: they name the missing file or
  expected path, the runtime install requirement, and point at the setup doc.
  The WebView2 content surface is hidden while a failure is shown, because the
  native child window would otherwise paint over the fallback text.
- `src/ui/webview2/datasaverwebpage.cpp` compiles cleanly under the Qt 6.11.1
  MinGW kit.

Still needs a machine with the full build and a display:

1. Finish a clean release build with the temporary qmake makefile or the normal project build.
2. Confirm the post-link rule reliably creates `bin/web/datasaver/dist` on a clean output directory without manual copying.
3. Launch the freshly built executable and navigate to the new Data Saver preview destination.
4. Verify the page renders from the packaged folder, not the source tree.
5. Test the preview at the minimum window size and at 125%, 150%, and 200% Windows scaling.
6. Confirm the WebView2 fallback message is useful when `WebView2Loader.dll` or the page assets are missing.
7. Verify the existing native Data Saver controls, persistence, notifications, and enforcement behavior are unchanged.

Clean build commands:

```bash
cd web/datasaver && npm install --no-audit --no-fund && npm run build && cd ../..
rm -rf build/stage1 && mkdir -p build/stage1 && cd build/stage1
/c/Qt/6.11.1/mingw_64/bin/qmake.exe ../../Oasis.pro CONFIG+=release
PATH="/c/Qt/Tools/mingw1310_64/bin:$PATH" mingw32-make -j8
```

Temporary artifacts (`Makefile.webview2*`, `.obj`, `.moc`, `.rcc`, `.ui`,
`build/`, `release/`, `debug/`) are already covered by `.gitignore`; the scratch
`build/stage1` shadow build directory used for verification can be deleted at
any time.

### Stage 2: real Data Saver integration

1. Implement and test the backend contract with exactly `Off` and `Enforce`.
2. Migrate legacy stored mode values conservatively; the old Monitor value must not silently enable enforcement.
3. Add a dedicated WebView2 message bridge using `postMessage` and `WebMessageReceived`.
4. Define a versioned JSON-compatible snapshot and command contract.
5. Connect the bridge to existing Data Saver state, detection signals, enforcement results, and automatic-control restoration.
6. Replace mock values with backend snapshots.
7. Add explicit pending, success, failure, and unavailable-runtime states.
8. Test invalid commands, repeated commands, reloads, teardown, stale callbacks, and backend failures.
9. Compare the web page against the native Data Saver behavior before removing the native fallback.

### Later UI migration

1. Migrate other bounded pages one at a time.
2. Keep Qt shell navigation authoritative until cross-page web contracts are defined.
3. Move navigation into Preact only after the bridge and page lifecycle rules are stable.
4. Retire native widgets only after feature parity, release deployment, and fallback removal are verified.

## Known repository state

At the time this document was written, `git status` also showed modifications to the Data Saver PRD and ticket documents. Those changes were not part of this WebView2 layout implementation and should be preserved and reviewed separately.
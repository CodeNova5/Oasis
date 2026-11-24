// Bundles the Data Saver page into dist/ so the qmake post-link rule can copy
// a complete asset set into bin/web/datasaver/dist.
//
// Produces:
//   dist/app.js    bundled + minified Preact/HTM application
//   dist/app.css   minified stylesheet
//   dist/index.html  page shell with the dist/ prefix stripped from asset URLs

import { build } from "esbuild";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "dist");

await mkdir(dist, { recursive: true });

await build({
    entryPoints: [join(root, "src/main.js")],
    bundle: true,
    minify: true,
    loader: { ".js": "jsx" },
    outfile: join(dist, "app.js"),
    logLevel: "warning",
});

await build({
    entryPoints: [join(root, "src/styles.css")],
    bundle: true,
    minify: true,
    outfile: join(dist, "app.css"),
    logLevel: "warning",
});

// The source page references dist/ so it can be opened directly in a browser.
// Inside dist/ the assets sit next to the page, so the prefix is removed.
const page = await readFile(join(root, "index.html"), "utf8");
await writeFile(join(dist, "index.html"), page.replaceAll('"dist/', '"'), "utf8");

// Keep the packaged copy in bin/ in sync when building from a checked-out tree.
// The qmake post-link rule repeats this copy for full builds.
await mkdir(join(root, "../../bin/web/datasaver/dist"), { recursive: true });
for (const asset of ["app.js", "app.css", "index.html"]) {
    await copyFile(join(dist, asset), join(root, "../../bin/web/datasaver/dist", asset));
}

console.log("Data Saver assets written to dist/ and bin/web/datasaver/dist/");

// Bundles the Oasis frontend into dist/ so the qmake post-link rule can copy
// one complete asset set into bin/web/ui/dist.
//
// Each page under src/ is its own Preact/HTM entry point:
//   src/main.js           → dist/app.js,        dist/app.css,        dist/index.html
//   src/datasaver/main.js → dist/datasaver.js,  dist/datasaver.css,  dist/datasaver.html

import { build } from "esbuild";
import { copyFile, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "dist");

// `entry` is relative to src/, `name` is the bundle basename.
const pages = [
    { entry: "main.js", css: "styles.css", name: "app", shell: "index.html" },
    {
        entry: "datasaver/main.js",
        css: "datasaver/styles.css",
        name: "datasaver",
        shell: "datasaver.html",
    },
];

await mkdir(dist, { recursive: true });

for (const page of pages) {
    const entryPoint = join(root, "src", page.entry);
    const cssOut = join(dist, `${page.name}.css`);

    await build({
        entryPoints: [entryPoint],
        bundle: true,
        minify: true,
        // No JSX loader on purpose: components use HTM template literals, so a
        // stray JSX tag fails the build instead of emitting React.createElement
        // calls (React is not a dependency).
        outfile: join(dist, `${page.name}.js`),
        logLevel: "warning",
    });

    // The stylesheet is also imported from the entry so esbuild emits it; this
    // pass guarantees a standalone, minified file even if the import is removed.
    await build({
        entryPoints: [join(root, "src", page.css)],
        bundle: true,
        minify: true,
        outfile: cssOut,
        logLevel: "warning",
    });

    // The source page references dist/ so it can be opened directly in a
    // browser. Inside dist/ the assets sit next to the page, so the prefix is
    // removed.
    const shell = await readFile(join(root, page.shell), "utf8");
    await writeFile(join(dist, page.shell), shell.replaceAll('"dist/', '"'), "utf8");
}

// Keep the packaged copy in bin/ in sync when building from a checked-out tree.
// The qmake post-link rule repeats this copy for full builds.
await mkdir(join(root, "../../bin/web/ui/dist"), { recursive: true });
for (const asset of await readdir(dist)) {
    await copyFile(join(dist, asset), join(root, "../../bin/web/ui/dist", asset));
}

console.log("Oasis UI assets written to dist/ and bin/web/ui/dist/");

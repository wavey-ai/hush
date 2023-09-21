import liveServer from "live-server";
import chokidar from "chokidar";
import esbuild from "esbuild";
import cssModulesPlugin from "esbuild-css-modules-plugin";
import sass from "esbuild-sass-plugin";

import postcss from "postcss";
import autoprefixer from "autoprefixer";
import postcssPresetEnv from "postcss-preset-env";
import fs from "fs-extra";

import stylePlugin from 'esbuild-style-plugin';
import tailwindcss from 'tailwindcss';
const isWatch = process.argv.includes("--watch");

/**
 * Live Server Params
 * @link https://www.npmjs.com/package/live-server#usage-from-node
 */
const serverParams = {
  port: 8181, // Set the server port. Defaults to 8080.
  root: "build", // Set root directory that's being served. Defaults to cwd.
  open: true // When false, it won't load your browser by default.
  // host: "0.0.0.0", // Set the address to bind to. Defaults to 0.0.0.0 or process.env.IP.
  // ignore: 'scss,my/templates', // comma-separated string for paths to ignore
  // file: "index.html", // When set, serve this file (server root relative) for every 404 (useful for single-page applications)
  // wait: 1000, // Waits for all changes, before reloading. Defaults to 0 sec.
  // mount: [['/components', './node_modules']], // Mount a directory to a route.
  // logLevel: 2, // 0 = errors only, 1 = some, 2 = lots
  // middleware: [function(req, res, next) { next(); }] // Takes an array of Connect-compatible middleware that are injected into the server middleware stack
};

/**
 * ESBuild Params
 * @link https://esbuild.github.io/api/#build-api
 */
const buildParams = {
  color: true,
  entryPoints: ["src/index.jsx"],
  loader: { ".js": "jsx", ".json": "json", ".png": "file", ".jpeg": "file", ".jpg": "file", ".svg": "file" },
  outdir: "dist",
  minify: !isWatch,
  format: "cjs",
  bundle: true,
  sourcemap: isWatch,
  logLevel: "error",
  incremental: isWatch,
  plugins: [
    stylePlugin({
      postcss: {
        plugins: [tailwindcss, autoprefixer],
      },
    }),
  ],
};

// Clean build folder
try {
  fs.removeSync("dist");
} catch (err) {
  console.error(err);
}
// Copy public folder into build folder
try {
  fs.copySync("public", "dist");
} catch (err) {
  console.error(err);
}

if (isWatch) {
  (async () => {
    // Build
    const result = await esbuild.build(buildParams).catch(() => process.exit(1));

    // Start live server
    liveServer.start(serverParams);
    /**
     * Watch development server changes
     * ignored: ignore watch `.*` files
     */
    return chokidar
      .watch("src/**/*", { ignored: /(^|[/\\])\../, ignoreInitial: true })
      .on("all", async (event, path) => {
        if (event === "change") {
          console.log(`⚡ [esbuild] Rebuilding ${path}`);
          console.time("⚡ [esbuild] Done");
          if (result.rebuild) await result.rebuild();
          console.timeEnd("⚡ [esbuild] Done");
        }
      });
  })();
} else {
  // Run build
  console.log(`⚡ [esbuild] Building..`);
  esbuild.build(buildParams).catch(() => process.exit(1));
}

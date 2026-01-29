const webpack = require('webpack');
const { GenerateSW } = require('workbox-webpack-plugin');

module.exports = function override(config, env) {
  const fallback = config.resolve.fallback || {};
  Object.assign(fallback, {
    "path": require.resolve("path-browserify"),
    "buffer": require.resolve("buffer/"),
    "process": require.resolve("process/browser"),
    "fs": false,
    "child_process": false,
    "crypto": false
  });
  config.resolve.fallback = fallback;

  config.plugins = (config.plugins || []).concat([
    new webpack.ProvidePlugin({
      process: 'process/browser',
      Buffer: ['buffer', 'Buffer']
    })
  ]);

  // Add Workbox service worker plugin for production builds
  if (env === 'production') {
    config.plugins.push(
      new GenerateSW({
        clientsClaim: true,
        skipWaiting: true,
        maximumFileSizeToCacheInBytes: 50 * 1024 * 1024, // 50MB for large WASM files
        exclude: [/\.map$/, /asset-manifest\.json$/, /LICENSE/],
        runtimeCaching: [
          {
            // Cache WASM files
            urlPattern: /\.wasm$/,
            handler: 'CacheFirst',
            options: {
              cacheName: 'wasm-cache',
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 30 * 24 * 60 * 60, // 30 days
              },
            },
          },
          {
            // Cache .data files (Wiregasm)
            urlPattern: /\.data$/,
            handler: 'CacheFirst',
            options: {
              cacheName: 'data-cache',
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 30 * 24 * 60 * 60,
              },
            },
          },
          {
            // Cache Pyodide files
            urlPattern: /\/pyodide\//,
            handler: 'CacheFirst',
            options: {
              cacheName: 'pyodide-cache',
              expiration: {
                maxEntries: 50,
                maxAgeSeconds: 30 * 24 * 60 * 60,
              },
            },
          },
          {
            // Cache Python bundles
            urlPattern: /\/python\//,
            handler: 'CacheFirst',
            options: {
              cacheName: 'python-cache',
              expiration: {
                maxEntries: 50,
                maxAgeSeconds: 30 * 24 * 60 * 60,
              },
            },
          },
        ],
      })
    );
  }

  return config;
}

const path = require('path')

module.exports = [
  {
    in: './api/*.js',
    out: './build/functions',
    presets: [
      'node',
      'serverless'
    ],
    env: {
      SANITY_PROJECT_ID: JSON.stringify("elg2h51q"),
      SANITY_DATASET: JSON.stringify("root"),
      SANITY_TOKEN: process.env.SANITY_TOKEN
    },
    alias: {
      '@': path.resolve('./api')
    }
  },
  {
    in: './site/index.js',
    out: './build/site',
    presets: [
      'postcss'
    ],
    env: {
      SANITY_PROJECT_ID: JSON.stringify("elg2h51q"),
      SANITY_DATASET: JSON.stringify("root")
    },
    alias: {
      '@': path.resolve('./site')
    },
    reload: true
  },
]

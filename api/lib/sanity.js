const sanityClient = require('@sanity/client')

console.log('token', SANITY_TOKEN)

module.exports = sanityClient({
  projectId: SANITY_PROJECT_ID,
  dataset: SANITY_DATASET,
  token: SANITY_TOKEN,
  useCdn: false
})

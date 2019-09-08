const sanityClient = require('@sanity/client')

module.exports = sanityClient({
  projectId: SANITY_PROJECT_ID,
  dataset: SANITY_DATASET,
  useCdn: false
})

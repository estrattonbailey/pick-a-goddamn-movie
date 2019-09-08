const createError = require('http-errors')

const wrapper = require('@/lib/wrapper.js')
const crypto = require('@/lib/crypto.js')
const sanity = require('@/lib/sanity.js')

exports.handler = wrapper(async ev => {
  const { id } = ev.body

  const { _id } = await sanity
    .patch(id)
    .set({
      dateWatched: new Date()
    })
    .commit()

  return {
    body: {
      id: _id
    }
  }
}, {
  auth: true
})

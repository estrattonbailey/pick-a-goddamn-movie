const createError = require('http-errors')

const wrapper = require('@/lib/wrapper.js')
const crypto = require('@/lib/crypto.js')
const sanity = require('@/lib/sanity.js')

exports.handler = wrapper(async ev => {
  const userId = ev.user.id
  const {
    title,
    director,
    runtime,
    trailer
  } = ev.body

  const numberOfPicks = await sanity.fetch(
    `count(*[_type == 'movie' && user._ref == '07685db0-5a59-4389-8f7b-efdf99ce54c7'])`
  )

  if (numberOfPicks > 2) {
    throw createError(400, `You already picked three movies, silly.`)
  }

  const { _id } = await sanity.create({
    _type: 'movie',
    title,
    director,
    trailer,
    runtime: parseInt(runtime),
    user: { _ref: userId },
  })

  return {
    body: {
      id: _id
    }
  }
}, {
  auth: true
})

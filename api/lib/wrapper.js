const createError = require('http-errors')

const { sstack, handler } = require('sstack')
const { parse, stringify } = require('@sstack/json')
const helmet = require('@sstack/helmet')
const cookies = require('@sstack/cookies')
const errors = require('@sstack/errors')

const crypto = require('@/lib/crypto.js')
const users = require('@/lib/users.js')
const getAuthTokenFromHeaders = require('@/lib/getAuthTokenFromHeaders.js')

function guard () {
  return handler => {
    const ev = handler.event

    const cookie = ev.cookies.pickagoddamnmovie
    const header = getAuthTokenFromHeaders(ev.headers)
    const token = cookie || header
    try {
      const username = crypto.decrypt(token).username

      if (!users[username]) {
        throw createError(401, `Merry Christmas, ya filthy animal.`)
      }

      ev.user = users[username]
    } catch (e) {
      throw createError(401, `Hey dumbass, you're probably not logged in.`)
    }
  }
}

module.exports = (fn, options = {}) => {
  let { auth } = options

  return sstack([
    /**
     * Parse incoming request bodies to JSON
     */
    parse(),
    handler => {
      console.log(JSON.stringify(handler.event.body, null, '  '))
    },
    /**
     * Attach cookies to ev.cookies = {}
     */
    cookies(),
    /**
     * Block requests based on token validation
     * and user roles from Auth0
     */
    auth && guard(),
    /**
     * Our route handler
     */
    handler(
      fn
    ),
    /**
     * Attach a default body if none exists
     */
    handler => {
      const res = handler.response
      res.body = res.body || ''
    },
    /**
     * Stringify (almost) last
     */
    stringify(),
    helmet()
  ].filter(Boolean), [
    handler => {
      /**
       * Handling Sanity errors
       */
      if (handler.error.response) {
        handler.response = handler.error.response
      }
    },
    errors(),
    /**
     * Again, stringify last
     */
    stringify()
  ])
}

const createError = require('http-errors')

const wrapper = require('@/lib/wrapper.js')
const crypto = require('@/lib/crypto.js')
const users = require('@/lib/users.js')

exports.handler = wrapper(ev => {
  const { username, password } = ev.body

  if (users[username]) {
    console.log(users[username].password, password)
    if (users[username].password === password) {
      return {
        body: {
          token: crypto.encrypt({ username })
        }
      }
    }
  }

  throw createError(401, `Done fucked that up, didn't ya?`)
})

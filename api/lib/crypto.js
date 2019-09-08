const crypto = new (require("simple-crypto-js").default)('pickagoddamnmovie')

function decrypt (token) {
  return JSON.parse(crypto.decrypt(token))
}

function encrypt (payload) {
  return crypto.encrypt(JSON.stringify(payload))
}

module.exports = {
  decrypt,
  encrypt
}

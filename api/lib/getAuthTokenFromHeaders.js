module.exports = function getAuthTokenFromHeaders (headers) {
  try {
    const header = headers.authorization || headers.Authorization
    return header.split('Bearer ')[1].trim()
  } catch (e) {}
}

'use strict'
try {
  module.exports = require('./bindings')
} catch (err) {
  if (process.env.DEBUG) {
    console.error('Scrypt bindings are not compiled. Pure JS implementation will be used.')
  }

  module.exports = require('./js')
}

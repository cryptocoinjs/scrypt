'use strict'
var buffer = require('safe-buffer')
var Buffer = buffer.Buffer
var toString = Object.prototype.toString

function isValidNumber (value) {
  return (typeof value === 'number' || toString(value) === '[object Number]') && value > 0 && value % 1 === 0
}

module.exports = function (scrypt) {
  return function (password, salt, N, r, p, length) {
    if (!Buffer.isBuffer(password)) throw new TypeError('"password" must be a Buffer instance')
    if (!Buffer.isBuffer(salt)) throw new TypeError('"salt" must be a Buffer instance')
    if (!isValidNumber(N)) throw new TypeError('"N" should be positive finite integer')
    if (!isValidNumber(r)) throw new TypeError('"r" should be positive finite integer')
    if (!isValidNumber(p)) throw new TypeError('"p" should be positive finite integer')
    if (!isValidNumber(length)) throw new TypeError('"length" should be positive finite integer')

    if (((N & (N - 1)) !== 0) || (N < 2)) {
      throw new RangeError('"N" must be a power of 2 greater than 1')
    }

    if (N > buffer.kMaxLength / 128 / r) {
      throw new RangeError('"N" is too large')
    }

    if (r > buffer.kMaxLength / 128 / p || r > buffer.kMaxLength / 256) {
      throw new RangeError('"r" is too large')
    }

    if (r * p >= (1 << 30)) {
      throw new RangeError('"r" * "p" must be less than 2^30')
    }

    if (length > buffer.kMaxLength) {
      throw new RangeError('"length" argument must not be larger than ' + buffer.kMaxLength)
    }

    return scrypt(password, salt, N, r, p, length)
  }
}

'use script'
var test = require('tape')

function main (name, scrypt) {
  test(name, (t) => {
    t.test('params', (t) => {
      t.end()
    })

    t.test('vectors', (t) => {
      var vectors = require('./vectors').slice(0, 3) // because 4rd is too expensive
      for (var i = 0; i < vectors.length; ++i) {
        var vector = vectors[i]
        var output = scrypt(
          Buffer.from(vector.password),
          Buffer.from(vector.salt),
          vector.N,
          vector.r,
          vector.p,
          vector.output.length / 2)

        t.equal(output.toString('hex'), vector.output)
      }

      t.end()
    })

    t.end()
  })
}

if (!process.browser) main('bindings', require('../bindings'))
main('purejs', require('../js'))

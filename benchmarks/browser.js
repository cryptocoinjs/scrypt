const scrypt = require('../js')

const now = () => new Date().getTime()

setTimeout(() => {
  const node = document.getElementById('scrypt')
  node.innerHTML = 'Start...'

  const ts1 = now()
  console.log(scrypt(Buffer.from('password'), Buffer.from('salt'), 16384, 8, 1, 32).toString('hex'))
  const delta1 = now() - ts1

  node.innerHTML += `<br /> current: ${delta1}ms`
}, 1000)

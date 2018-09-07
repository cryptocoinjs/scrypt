# scrypt

Version | Mac/Linux | Windows
------- | --------- | -------
[![NPM Package](https://img.shields.io/npm/v/scrypt.svg?style=flat-square)](https://www.npmjs.org/package/scrypt) | [![Build Status](https://img.shields.io/travis/cryptocoinjs/scrypt.svg?branch=master&style=flat-square)](https://travis-ci.org/cryptocoinjs/scrypt) | [![AppVeyor](https://img.shields.io/appveyor/ci/fanatid/scrypt.svg?branch=master&style=flat-square)](https://ci.appveyor.com/project/fanatid/scrypt)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

This module provides native bindings to [Colin Percival's scrypt][1].

In browser Pure JS implementation (based on [scryptsy](https://github.com/cryptocoinjs/scryptsy)) will be used.

Current scrypt version: 1.2.1

This library is experimental, so use at your own risk.

## Installation

`npm install scrypt`

##### Windows

Before install scrypt you should install [windows-build-tools][2].

## API

Only one function — scrypt.

`scrypt(Buffer password, Buffer salt, Number N, Number r, Number p, Number length)`

- `password` - key which will be hashed
- `salt` - salt
- `N` - number of iterations
- `r` - memory factor
- `p` - parallelization factor
- `length` - output buffer length

## USAGE

```js
const scrypt = require('scrypt')
console.log(scrypt(Buffer.from('password'), Buffer.from('salt'), 262144, 1, 8, 32))
// <Buffer ec c9 3f 60 b9 75 00 ef d2 3a b7 f5 a7 96 7d 6d 89 2b 5d d3 07 69 49 15 bd 69 03 28 e7 11 08 de>
```

## LICENSE

This library is free and open-source software released under the MIT license.

[1]: https://www.tarsnap.com/scrypt.html
[2]: https://github.com/felixrieseberg/windows-build-tools

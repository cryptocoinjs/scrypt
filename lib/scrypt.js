'use strict'
var crypto = require('crypto')

/**
 * Compute scrypt(password, salt, N, r, p, buflen) and return buffer with length bytes.
 * The parameters r, p must satisfy r * p < 2^30.
 * The parameter N must be a power of 2.
 */
module.exports = function (password, salt, N, r, p, length) {
  var XY = Buffer.alloc(256 * r)
  var V = Buffer.alloc(128 * r * N)

  /* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
  var B = crypto.pbkdf2Sync(password, salt, 1, p * 128 * r, 'sha256')

  /* 2: for i = 0 to p - 1 do */
  for (var i = 0; i < p; ++i) {
    /* 3: B_i <-- MF(B_i, N) */
    smix(B, i * 128 * r, r, N, V, XY)
  }

  /* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
  return crypto.pbkdf2Sync(password, B, 1, length, 'sha256')
}

/**
 * smix(B, Bi, r, N, V, XY):
 * Compute B = SMix_r(B, N). The input B must be 128r bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length. The value N must be a power of 2.
 */
function smix (B, Bi, r, N, V, XY) {
  var Xi = 0
  var Yi = 128 * r

  /* 1: X <-- B */
  blockcopy(B, Bi, XY, Xi, 128 * r)

  /* 2: for i = 0 to N - 1 do */
  for (var i = 0; i < N; i++) {
    /* 3: V_i <-- X */
    blockcopy(XY, Xi, V, i * 128 * r, 128 * r)

    /* 4: X <-- H(X) */
    blockmixSalsa8(XY, Xi, Yi, r)
  }

  /* 6: for i = 0 to N - 1 do */
  for (i = 0; i < N; i++) {
    /* 7: j <-- Integerify(X) mod N */
    var offset = Xi + (2 * r - 1) * 64
    var j = XY.readUInt32LE(offset) & (N - 1)

    /* 8: X <-- H(X \xor V_j) */
    blockxor(XY, Xi, V, j * 128 * r, 128 * r)
    blockmixSalsa8(XY, Xi, Yi, r)
  }

  /* 10: B' <-- X */
  blockcopy(XY, Xi, B, Bi, 128 * r)
}

/**
 * blockmixSalsa8(BY, Bi, Yi, r):
 * Compute B = BlockMix_{salsa20/8, r}(B). The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
function blockmixSalsa8 (BY, Bi, Yi, r) {
  var X = Buffer.allocUnsafe(64)

  /* 1: X <-- B_{2r - 1} */
  blockcopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64)

  /* 2: for i = 0 to 2r - 1 do */
  for (var i = 0; i < 2 * r; ++i) {
    /* 3: X <-- H(X \xor B_i) */
    blockxor(X, 0, BY, Bi + i * 64, 64)
    salsa20(X)

    /* 4: Y_i <-- X */
    blockcopy(X, 0, BY, Yi + i * 64, 64)
  }

  /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
  for (i = 0; i < r; ++i) blockcopy(BY, Yi + (i * 2) * 64, BY, Bi + i * 64, 64)
  for (i = 0; i < r; ++i) blockcopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64)
}

/**
 * salsa20(B):
 * Apply the salsa20/8 core to the provided block.
 */
function salsa20 (B) {
  var x = new Array(16)

  for (var i = 0, s = 0; i < 16; ++i, s += 4) {
    x[i] = B[s + 3] << 24 | B[s + 2] << 16 | B[s + 1] << 8 | B[s]
  }

  for (i = 8; i > 0; i -= 2) {
    /* Operate on columns. */
    x[4] ^= rotl(x[0] + x[12], 7)
    x[8] ^= rotl(x[4] + x[0], 9)
    x[12] ^= rotl(x[8] + x[4], 13)
    x[0] ^= rotl(x[12] + x[8], 18)
    x[9] ^= rotl(x[5] + x[1], 7)
    x[13] ^= rotl(x[9] + x[5], 9)
    x[1] ^= rotl(x[13] + x[9], 13)
    x[5] ^= rotl(x[1] + x[13], 18)
    x[14] ^= rotl(x[10] + x[6], 7)
    x[2] ^= rotl(x[14] + x[10], 9)
    x[6] ^= rotl(x[2] + x[14], 13)
    x[10] ^= rotl(x[6] + x[2], 18)
    x[3] ^= rotl(x[15] + x[11], 7)
    x[7] ^= rotl(x[3] + x[15], 9)
    x[11] ^= rotl(x[7] + x[3], 13)
    x[15] ^= rotl(x[11] + x[7], 18)
    /* Operate on rows. */
    x[1] ^= rotl(x[0] + x[3], 7)
    x[2] ^= rotl(x[1] + x[0], 9)
    x[3] ^= rotl(x[2] + x[1], 13)
    x[0] ^= rotl(x[3] + x[2], 18)
    x[6] ^= rotl(x[5] + x[4], 7)
    x[7] ^= rotl(x[6] + x[5], 9)
    x[4] ^= rotl(x[7] + x[6], 13)
    x[5] ^= rotl(x[4] + x[7], 18)
    x[11] ^= rotl(x[10] + x[9], 7)
    x[8] ^= rotl(x[11] + x[10], 9)
    x[9] ^= rotl(x[8] + x[11], 13)
    x[10] ^= rotl(x[9] + x[8], 18)
    x[12] ^= rotl(x[15] + x[14], 7)
    x[13] ^= rotl(x[12] + x[15], 9)
    x[14] ^= rotl(x[13] + x[12], 13)
    x[15] ^= rotl(x[14] + x[13], 18)
  }

  for (i = 0, s = 0; i < 16; ++i, s += 4) {
    var carry = B[s] + (x[i] & 0xff)
    B[s] = carry & 0xff

    carry = (carry >> 8) + B[s + 1] + (x[i] >> 8 & 0xff)
    B[s + 1] = carry & 0xff

    carry = (carry >> 8) + B[s + 2] + (x[i] >> 16 & 0xff)
    B[s + 2] = carry & 0xff

    carry = (carry >> 8) + B[s + 3] + (x[i] >> 24 & 0xff)
    B[s + 3] = carry & 0xff
  }
}

function blockxor (S, Si, D, Di, length) {
  for (var i = 0; i < length; ++i) S[Si + i] ^= D[Di + i]
}

function blockcopy (S, Si, D, Di, length) {
  S.copy(D, Di, Si, Si + length)
}

function rotl (a, b) {
  return (a << b) | (a >>> (32 - b))
}

{
  "targets": [{
    "target_name": "scrypt",
    "sources": [
      "./src/addon.cc",
      "./src/scrypt/lib/crypto/crypto_scrypt.c",
      "./src/scrypt/lib/crypto/crypto_scrypt_smix.c",
      "./src/scrypt/lib/crypto/crypto_scrypt_smix_sse2.c",
      "./src/scrypt/libcperciva/util/insecure_memzero.c",
      "./src/scrypt/libcperciva/util/warnp.c"
    ],
    "include_dirs": [
      "/usr/local/include",
      "<!(node -e \"require('nan')\")",
      "./src",
      "./src/scrypt",
      "./src/scrypt/lib/crypto",
      "./src/scrypt/libcperciva/alg",
      "./src/scrypt/libcperciva/cpusupport",
      "./src/scrypt/libcperciva/util"
    ],
    "defines": [
      "CONFIG_H_FILE=\"config-mock.h\""
    ],
    "cflags": [
      "-Wall",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wextra"
    ],
    "cflags_c": [
      "-std=c99"
    ],
    "cflags_cc+": [
      "-std=c++0x"
    ],
    "conditions": [
      [
        "OS=='mac'", {
          "libraries": [
            "-L/usr/local/lib"
          ],
          "xcode_settings": {
            "MACOSX_DEPLOYMENT_TARGET": "10.7",
            "OTHER_CPLUSPLUSFLAGS": [
              "-stdlib=libc++"
            ]
          }
        }
      ],
      [
        "OS=='win'", {
          "include_dirs": [
            "./src/win"
          ],
          "sources": [
            "./src/win/sha256.c"
          ]
        }, {
          "sources": [
            "./src/scrypt/libcperciva/alg/sha256.c"
          ]
        }
      ]
    ]
  }]
}

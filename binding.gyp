{
    'targets': [{
        'target_name': 'sodium-native',

        'defines': [
            'SODIUM_STATIC',
            'HAVE_LIBM=1'
        ],

        'include_dirs': [
            '<(module_root_dir)/vendor/libsodium/src/libsodium/include',
            '<(module_root_dir)/vendor/libsodium/src/libsodium/include/sodium',
            '<!(node -e "require(\'nan\')")'
        ],

        'actions': [{
            'action_name': 'generate_version_header',
            'variables': {
                'configure.ac': 'vendor/libsodium/configure.ac'
            },

            'inputs': [
                'vendor/libsodium/src/libsodium/include/sodium/version.h.in'
            ],

            'outputs': [
                '<(module_root_dir)/vendor/libsodium/src/libsodium/include/sodium/version.h'
            ],

            'action': [
                'python', './gyptools/generate_version_header.py',
                '-c', '<@(configure.ac)', '-o', '<@(_outputs)', '<@(_inputs)'
            ]
        }],

        'sources': [
            'vendor/libsodium/src/libsodium/sodium/core.c',
            'vendor/libsodium/src/libsodium/sodium/runtime.c',
            'vendor/libsodium/src/libsodium/sodium/utils.c',
            'vendor/libsodium/src/libsodium/sodium/version.c',

            'vendor/libsodium/src/libsodium/randombytes/randombytes.c',
            'vendor/libsodium/src/libsodium/randombytes/salsa20/randombytes_salsa20_random.c',
            'vendor/libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c',

            'vendor/libsodium/src/libsodium/crypto_verify/16/ref/verify_16.c',
            'vendor/libsodium/src/libsodium/crypto_verify/16/verify_16_api.c',
            'vendor/libsodium/src/libsodium/crypto_verify/32/ref/verify_32.c',
            'vendor/libsodium/src/libsodium/crypto_verify/32/verify_32_api.c',
            'vendor/libsodium/src/libsodium/crypto_verify/64/ref/verify_64.c',
            'vendor/libsodium/src/libsodium/crypto_verify/64/verify_64_api.c',

            'vendor/libsodium/src/libsodium/crypto_core/curve25519/ref10/curve25519_ref10.c',

            'vendor/libsodium/src/libsodium/crypto_core/salsa20/ref/core_salsa20.c',
            'vendor/libsodium/src/libsodium/crypto_core/salsa20/core_salsa20_api.c',

            # this is all stuff that we don't actually use, but that sodium calls
            # in sodium_init()
            # {
            'vendor/libsodium/src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c',
            'vendor/libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c',
            'vendor/libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c',
            'vendor/libsodium/src/libsodium/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c',

            'vendor/libsodium/src/libsodium/crypto_pwhash/argon2/argon2.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/argon2/argon2-core.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ssse3.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/argon2/blake2b-long.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/argon2/pwhash_argon2i.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/crypto_pwhash.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c',
            'vendor/libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c',

            'vendor/libsodium/src/libsodium/crypto_generichash/blake2/generichash_blake2_api.c',
            'vendor/libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-avx2.c',
            'vendor/libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-ref.c',
            'vendor/libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-sse41.c',
            'vendor/libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-compress-ssse3.c',
            'vendor/libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-ref.c',
            'vendor/libsodium/src/libsodium/crypto_generichash/blake2/ref/generichash_blake2b.c',
            'vendor/libsodium/src/libsodium/crypto_generichash/crypto_generichash.c',

            'vendor/libsodium/src/libsodium/crypto_stream/salsa20/ref/stream_salsa20_ref.c',
            'vendor/libsodium/src/libsodium/crypto_stream/salsa20/ref/xor_salsa20_ref.c',
            'vendor/libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20_api.c',
            # }

            'vendor/libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c',
            'vendor/libsodium/src/libsodium/crypto_scalarmult/curve25519/donna_c64/curve25519_donna_c64.c',
            'vendor/libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c',
            'vendor/libsodium/src/libsodium/crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c',
            'vendor/libsodium/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_invert.c',
            'vendor/libsodium/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c',
            'vendor/libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c',

            'vendor/libsodium/src/libsodium/crypto_hash/sha256/cp/hash_sha256.c',
            'vendor/libsodium/src/libsodium/crypto_hash/sha256/hash_sha256_api.c',
            'vendor/libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512.c',
            'vendor/libsodium/src/libsodium/crypto_hash/sha512/hash_sha512_api.c',

            'vendor/libsodium/src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256_api.c',
            'vendor/libsodium/src/libsodium/crypto_auth/hmacsha256/cp/hmac_hmacsha256.c',
            'vendor/libsodium/src/libsodium/crypto_auth/hmacsha256/cp/verify_hmacsha256.c',

            'vendor/libsodium/src/libsodium/crypto_sign/crypto_sign.c',
            'vendor/libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c',
            'vendor/libsodium/src/libsodium/crypto_sign/ed25519/ref10/obsolete.c',
            'vendor/libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c',
            'vendor/libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c',
            'vendor/libsodium/src/libsodium/crypto_sign/ed25519/sign_ed25519_api.c',

            'vendor/libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c',
            'vendor/libsodium/src/libsodium/crypto_stream/chacha20/ref/stream_chacha20_ref.c',
            'vendor/libsodium/src/libsodium/crypto_stream/chacha20/vec/stream_chacha20_vec.c',

            'src/util.cc',
            'src/crypto.cc',
            'src/wrapper.cc'
        ]
    }]
}

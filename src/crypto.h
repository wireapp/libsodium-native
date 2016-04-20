#include <node.h>
#include <nan.h>

NAN_METHOD(scalarmult);

NAN_METHOD(hash_sha256);

NAN_GETTER(get_auth_hmacsha256_KEYBYTES);
NAN_METHOD(auth_hmacsha256);
NAN_METHOD(auth_hmacsha256_verify);

NAN_METHOD(sign_keypair);
NAN_METHOD(sign_detached);
NAN_METHOD(sign_verify_detached);

NAN_METHOD(sign_ed25519_pk_to_curve25519);
NAN_METHOD(sign_ed25519_sk_to_curve25519);

NAN_METHOD(stream_chacha20_xor);

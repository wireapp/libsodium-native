#include <sodium.h>

#include <node.h>
#include <nan.h>

#include "crypto.h"

NAN_MODULE_INIT(init)
{
	if (sodium_init() == -1) {
		Nan::ThrowError("Couldn't initialise libsodium");
		return;
	}

	Nan::SetMethod(target, "crypto_hash_sha256", hash_sha256);

	Nan::SetMethod(target, "crypto_scalarmult", scalarmult);

	Nan::SetMethod(target, "crypto_auth_hmacsha256", auth_hmacsha256);
	Nan::SetMethod(target, "crypto_auth_hmacsha256_verify", auth_hmacsha256_verify);

	Nan::SetMethod(target, "crypto_sign_keypair", sign_keypair);
	Nan::SetMethod(target, "crypto_sign_detached", sign_detached);
	Nan::SetMethod(target, "crypto_sign_verify_detached", sign_verify_detached);

	Nan::SetMethod(target, "crypto_sign_ed25519_pk_to_curve25519", sign_ed25519_pk_to_curve25519);
	Nan::SetMethod(target, "crypto_sign_ed25519_sk_to_curve25519", sign_ed25519_sk_to_curve25519);

	Nan::SetMethod(target, "crypto_stream_chacha20_xor", stream_chacha20_xor);

	Nan::SetAccessor(target,
		Nan::New("crypto_auth_hmacsha256_KEYBYTES").ToLocalChecked(),
		get_auth_hmacsha256_KEYBYTES);
}

NODE_MODULE(sodium_native, init)

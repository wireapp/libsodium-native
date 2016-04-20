#include <stdint.h>

#include <sodium.h>

#include <node.h>
#include <nan.h>

#include "crypto.h"
#include "util.h"

/*******************************************************
 * crypto (misc)
 *******************************************************/

NAN_METHOD(scalarmult)
{
	struct lsn_buf_data n, p, q;

	v8::Local<v8::ArrayBuffer> ret = v8::ArrayBuffer::New(
			v8::Isolate::GetCurrent(), crypto_scalarmult_BYTES);

	if (info.Length() < 2) {
		Nan::ThrowTypeError("Expecting two Uint8Arrays");
		return;
	}

	n = lsn_buf_data_from_value(info[0]);
	p = lsn_buf_data_from_value(info[1]);
	if (!n.data || !p.data)
		return;

	if (n.nbytes != crypto_scalarmult_SCALARBYTES
			|| p.nbytes != crypto_scalarmult_BYTES) {
		Nan::ThrowError("Incorrect parameter bytelengths");
		return;
	}

	q = lsn_buf_data_from_value(ret);
	if (crypto_scalarmult(q.data, n.data, p.data)) {
		Nan::ThrowError("Error in scalarmult");
		return;
	}

	info.GetReturnValue().Set(v8::Uint8Array::New(ret, 0, crypto_scalarmult_BYTES));
}

/*******************************************************
 * crypto_hash
 *******************************************************/

NAN_METHOD(hash_sha256)
{
	struct lsn_buf_data in, out;

	v8::Local<v8::ArrayBuffer> ret = v8::ArrayBuffer::New(
			v8::Isolate::GetCurrent(), crypto_hash_sha256_BYTES);

	if (info.Length() < 1) {
		Nan::ThrowTypeError("Expecting one Uint8Array");
		return;
	}

	in = lsn_buf_data_from_value(info[0], 1);
	if (!in.data)
		return;

	out = lsn_buf_data_from_value(ret);
	crypto_hash_sha256(out.data, in.data, in.nbytes);

	lsn_buf_data_free(&in);

	info.GetReturnValue().Set(v8::Uint8Array::New(ret, 0, crypto_hash_sha256_BYTES));
}

/*******************************************************
 * crypto_auth_hmacsha256
 *******************************************************/

NAN_GETTER(get_auth_hmacsha256_KEYBYTES)
{
	info.GetReturnValue().Set(crypto_auth_hmacsha256_KEYBYTES);
}

NAN_METHOD(auth_hmacsha256)
{
	struct lsn_buf_data in, key, out;

	v8::Local<v8::ArrayBuffer> ret = v8::ArrayBuffer::New(
			v8::Isolate::GetCurrent(), crypto_auth_hmacsha256_BYTES);

	if (info.Length() < 2) {
		Nan::ThrowTypeError("Expecting two Uint8Arrays");
		return;
	}

	in  = lsn_buf_data_from_value(info[0], 1);
	key = lsn_buf_data_from_value(info[1]);
	if (!in.data || !key.data)
		return;

	if (key.nbytes != crypto_auth_hmacsha256_KEYBYTES) {
		Nan::ThrowError("Incorrect key bytelength");
		return;
	}

	out = lsn_buf_data_from_value(ret);
	crypto_auth_hmacsha256(out.data, in.data, in.nbytes, key.data);

	lsn_buf_data_free(&in);

	info.GetReturnValue().Set(v8::Uint8Array::New(ret, 0, crypto_auth_hmacsha256_BYTES));
}

NAN_METHOD(auth_hmacsha256_verify)
{
	struct lsn_buf_data hmac, in, key;

	if (info.Length() < 3) {
		Nan::ThrowTypeError("Expecting three Uint8Arrays");
		return;
	}

	hmac = lsn_buf_data_from_value(info[0]);
	in   = lsn_buf_data_from_value(info[1], 1);
	key  = lsn_buf_data_from_value(info[2]);
	if (!hmac.data || !in.data || !key.data)
		return;

	if (hmac.nbytes != crypto_auth_hmacsha256_BYTES) {
		Nan::ThrowError("Incorrect HMAC bytelength");
		return;
	}

	if (key.nbytes != crypto_auth_hmacsha256_KEYBYTES) {
		Nan::ThrowError("Incorrect key bytelength");
		return;
	}

	info.GetReturnValue().Set(
			crypto_auth_hmacsha256_verify(hmac.data, in.data, in.nbytes, key.data) == 0);

	lsn_buf_data_free(&in);
}

/*******************************************************
 * crypto_sign
 *******************************************************/

NAN_METHOD(sign_keypair)
{
	v8::Isolate *isolate = v8::Isolate::GetCurrent();

	v8::Local<v8::ArrayBuffer> publicKey = v8::ArrayBuffer::New(
			v8::Isolate::GetCurrent(), crypto_sign_PUBLICKEYBYTES);
	v8::Local<v8::ArrayBuffer> secretKey = v8::ArrayBuffer::New(
			v8::Isolate::GetCurrent(), crypto_sign_SECRETKEYBYTES);

	v8::Local<v8::Object> ret = v8::Object::New(isolate);

	struct lsn_buf_data pk, sk;

	pk = lsn_buf_data_from_value(publicKey);
	sk = lsn_buf_data_from_value(secretKey);

	crypto_sign_keypair(pk.data, sk.data);

	Nan::Set(ret, Nan::New("publicKey").ToLocalChecked(),
			v8::Uint8Array::New(publicKey, 0, crypto_sign_PUBLICKEYBYTES));
	Nan::Set(ret, Nan::New("privateKey").ToLocalChecked(),
			v8::Uint8Array::New(secretKey, 0, crypto_sign_SECRETKEYBYTES));

	info.GetReturnValue().Set(ret);
}

NAN_METHOD(sign_detached)
{
	struct lsn_buf_data m, sk, sig;
	unsigned long long sig_len;

	v8::Local<v8::ArrayBuffer> ret = v8::ArrayBuffer::New(
			v8::Isolate::GetCurrent(), crypto_sign_BYTES);

	if (info.Length() < 2) {
		Nan::ThrowTypeError("Expecting two Uint8Arrays");
		return;
	}

	m  = lsn_buf_data_from_value(info[0], 1);
	sk = lsn_buf_data_from_value(info[1]);
	if (!m.data || !sk.data)
		return;

	if (sk.nbytes != crypto_sign_SECRETKEYBYTES) {
		Nan::ThrowError("Incorrect key bytelength");
		return;
	}

	sig = lsn_buf_data_from_value(ret);
	crypto_sign_detached(sig.data, &sig_len, m.data, m.nbytes, sk.data);

	lsn_buf_data_free(&m);

	info.GetReturnValue().Set(v8::Uint8Array::New(ret, 0, sig_len));
}

NAN_METHOD(sign_verify_detached)
{
	struct lsn_buf_data m, sk, sig;

	if (info.Length() < 3) {
		Nan::ThrowTypeError("Expecting three Uint8Arrays");
		return;
	}

	sig = lsn_buf_data_from_value(info[0]);
	m   = lsn_buf_data_from_value(info[1], 1);
	sk  = lsn_buf_data_from_value(info[2]);
	if (!sig.data || !m.data || !sk.data)
		return;

	if (sk.nbytes != crypto_sign_PUBLICKEYBYTES) {
		Nan::ThrowError("Incorrect key bytelength");
		return;
	}

	info.GetReturnValue().Set(
		crypto_sign_verify_detached(sig.data, m.data, m.nbytes, sk.data) == 0);

	lsn_buf_data_free(&m);
}

/*******************************************************
 * crypto_sign_ed25519
 *******************************************************/

NAN_METHOD(sign_ed25519_pk_to_curve25519)
{
	struct lsn_buf_data ed, curve;

	v8::Local<v8::ArrayBuffer> ret = v8::ArrayBuffer::New(
			v8::Isolate::GetCurrent(), crypto_scalarmult_curve25519_BYTES);

	if (info.Length() < 1) {
		Nan::ThrowTypeError("Expecting one Uint8Array");
		return;
	}

	ed = lsn_buf_data_from_value(info[0]);
	if (!ed.data)
		return;

	curve = lsn_buf_data_from_value(ret);
	if (crypto_sign_ed25519_pk_to_curve25519(curve.data, ed.data)) {
		Nan::ThrowError("crypto_sign_ed25519_pk_to_curve25519 failed");
		return;
	}

	info.GetReturnValue().Set(v8::Uint8Array::New(ret, 0, crypto_scalarmult_curve25519_BYTES));
}

NAN_METHOD(sign_ed25519_sk_to_curve25519)
{
	struct lsn_buf_data ed, curve;

	v8::Local<v8::ArrayBuffer> ret = v8::ArrayBuffer::New(
			v8::Isolate::GetCurrent(), crypto_scalarmult_curve25519_SCALARBYTES);

	if (info.Length() < 1) {
		Nan::ThrowTypeError("Expecting one Uint8Array");
		return;
	}

	ed = lsn_buf_data_from_value(info[0]);
	if (!ed.data)
		return;

	curve = lsn_buf_data_from_value(ret);
	crypto_sign_ed25519_sk_to_curve25519(curve.data, ed.data);

	info.GetReturnValue().Set(v8::Uint8Array::New(ret, 0, crypto_scalarmult_curve25519_SCALARBYTES));
}

/*******************************************************
 * crypto_stream_chacha20
 *******************************************************/

NAN_METHOD(stream_chacha20_xor)
{
	v8::Local<v8::ArrayBuffer> ret;
	struct lsn_buf_data in, nonce, key, out;

	if (info.Length() < 1) {
		Nan::ThrowTypeError("Expecting one Uint8Array");
		return;
	}

	in    = lsn_buf_data_from_value(info[0], 1);
	nonce = lsn_buf_data_from_value(info[1]);
	key   = lsn_buf_data_from_value(info[2]);
	if (!in.data || !nonce.data || !key.data)
		return;

	if (nonce.nbytes != crypto_stream_chacha20_NONCEBYTES) {
		Nan::ThrowError("Incorrect nonce bytelength");
		return;
	}

	if (key.nbytes != crypto_stream_chacha20_KEYBYTES) {
		Nan::ThrowError("Incorrect key bytelength");
		return;
	}

	ret = v8::ArrayBuffer::New(v8::Isolate::GetCurrent(), in.nbytes);
	out = lsn_buf_data_from_value(ret);

	crypto_stream_chacha20_xor(out.data, in.data, in.nbytes, nonce.data, key.data);

	lsn_buf_data_free(&in);

	info.GetReturnValue().Set(v8::Uint8Array::New(ret, 0, in.nbytes));
}

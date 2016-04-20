#include <stdint.h>

#include <node.h>
#include <nan.h>

#include "util.h"

struct lsn_buf_data
lsn_buf_data_from_string(v8::Local<v8::Value> value)
{
	v8::Local<v8::ArrayBuffer> buf;
	v8::ArrayBuffer::Contents contents;
	uint8_t *data;
	ssize_t nbytes;

	nbytes = Nan::DecodeBytes(value, Nan::UTF8);
	if (nbytes < 0) {
		Nan::ThrowTypeError("Error in DecodeBytes");
		return {NULL, 0, 0};
	}

	data = (uint8_t *) malloc(nbytes);
	Nan::DecodeWrite((char *) data, nbytes, value, Nan::UTF8);

	return {
		data,
		(size_t) nbytes,
		1
	};
}

struct lsn_buf_data
lsn_buf_data_from_value(v8::Local<v8::Value> value, int strings_ok)
{
	v8::Local<v8::ArrayBuffer> buf;
	v8::ArrayBuffer::Contents contents;

	if (value->IsArrayBuffer())
		buf = v8::Local<v8::ArrayBuffer>::Cast(value);
	else if (value->IsUint8Array())
		buf = v8::Local<v8::Uint8Array>::Cast(value)->Buffer();
	else if (strings_ok && value->IsString()) {
		return lsn_buf_data_from_string(value);
	} else {
		Nan::ThrowTypeError("Can't convert value to ArrayBuffer");
		return {NULL, 0, 0};
	}

	contents = buf->GetContents();

	return {
		(uint8_t *) contents.Data(),
		contents.ByteLength(),
		0
	};
}

void
lsn_buf_data_free(struct lsn_buf_data *b)
{
	if (b->need_dealloc)
		free(b->data);
}

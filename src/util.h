#include <stdint.h>

#include <node.h>
#include <nan.h>

struct lsn_buf_data {
	uint8_t *data;
	size_t nbytes;
	int need_dealloc;
};


struct lsn_buf_data lsn_buf_data_from_string(v8::Local<v8::Value>);

struct lsn_buf_data lsn_buf_data_from_value(v8::Local<v8::Value>,
		int strings_ok = 0);

void lsn_buf_data_free(struct lsn_buf_data *);

// stream interface for in-memory files

// TODO(5/30): use different cursor for read and write, also define the mode of operation to mimic the actual file operation and avoid confusions
// (5/31): after testing standard FILE operation functions, I find out there is no need for 2 cursors, so I decided to leave it as it is

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stream.h"

static inline size_t golden_growth_ceil(size_t n)
{
	// from: https://github.com/Snaipe/fmem/blob/master/src/alloc.c
    /* This effectively is a return ceil(n * φ).
       φ is approximatively 207 / (2^7), so we shift our result by
       6, then perform our ceil by adding the remainder of the last division
       by 2 of the result to itself. */

    n = (n * 207) >> 6;
    n = (n >> 1) + (n & 1);
    return n;
}

static int expand_buf(stream *stream)
{
	if(stream->max_size && stream->buf_size >= stream->max_size) return 0;
	size_t newsize = golden_growth_ceil(stream->buf_size);
	if(stream->max_size > 0 && newsize > stream->max_size) {
		newsize = stream->max_size;
	}
	char *new_buf = realloc(stream->buf, newsize);
	if(!new_buf) return 0;
	stream->buf = new_buf;
	// initialize new memory
	memset(stream->buf+stream->buf_size, 0, newsize-stream->buf_size);
	stream->buf_size = newsize;
	return 1;
}

stream *stream_create(size_t min, size_t max_size)
{
	if(min <= 0) return NULL;
	char *mem = malloc(min);
	memset(mem, 0, min);
	if(!mem) return NULL;
	stream *rtn = malloc(sizeof(stream));
	if(!rtn) {
		free(mem);
		return NULL;
	}
	rtn->buf = mem;
	rtn->buf_size = min;
	rtn->cursor_pos = 0;
	rtn->error = 0;
	rtn->datalen = 0;
	if(max_size > 0) {
		rtn->max_size = max_size;
	} else {
		rtn->max_size = 0; //no limit
	}
	return rtn;
}

stream *stream_create_from(void *ptr, size_t size, size_t max_size)
{
	if(size <= 0) {
		return stream_create(10, max_size);
	}
	stream *rtn = stream_create(size, max_size);
	if(!rtn) return NULL;
	if(!memcpy(rtn->buf, ptr, size)) {
		stream_close(rtn);
		return NULL;
	}
	return rtn;
}

void stream_clear(stream *stream)
{
	if(stream) {
		if(stream->buf) {
			memset(stream->buf, 0, stream->buf_size);
		}
		stream->datalen = 0L;
		stream->cursor_pos = 0L;
		stream->error = 0L;
	}
}

int stream_close(stream *stream)
{
	if(stream) {
		// for security reason
		stream_clear(stream);
		free(stream->buf);
		free(stream);
		// always return 0
	}
	return 1;
}

int stream_error(stream *stream)
{
	return stream->error;
}

void stream_clearerr(stream *stream)
{
	if(stream) {
		stream->error = 0;
	}
}

size_t stream_read(void *ptr, size_t size, size_t nmemb, stream *stream)
{
	if(!stream || !ptr) return 0;
	if(size*nmemb > stream->datalen-stream->cursor_pos) {
		// cannot read everything
		if(stream->datalen-stream->cursor_pos > size) {
			// can read part of it
			int nread = stream->datalen-stream->cursor_pos / size;
			if(!memcpy(ptr, stream->buf+stream->cursor_pos, size*nread)) {
				stream->error = 1;
				return 0;
			}
			stream->cursor_pos += size*nread;
			return nread;
		}
		// if not, read nothing and return 0
		return 0;
	}
	// read everything (as normal cases)
	if(!memcpy(ptr, stream->buf+stream->cursor_pos, size*nmemb)) {
		stream->error = 1;
		return 0;
	}
	stream->cursor_pos += size*nmemb;
	return nmemb;
}
	
size_t stream_write(const void *ptr, size_t size, size_t nmemb, stream *stream)
// all or nothing function
{
	if(!stream || !ptr || size*nmemb <= 0) return 0;
	// attempt to enlarge the stream if buffer is not enough
	while(size*nmemb > stream->buf_size-stream->cursor_pos) {
		if(!expand_buf(stream)) {
			stream->error = 1;
			return 0; //Cannot write stream because not enough memory on system or limited by max_size
		}
	}
	if(!memcpy(stream->buf+stream->cursor_pos, ptr, size*nmemb)) {
		return 0;
	}
	stream->cursor_pos += size*nmemb;
	stream->datalen = (stream->datalen > stream->cursor_pos ? stream->datalen : stream->cursor_pos);
	return nmemb;
}

int stream_getpos(stream *stream, long *pos)
{
	if(!stream || !pos) return 0;
	*pos = stream->cursor_pos;
	return 1;
}

int stream_setpos(stream *stream, const long pos)
/// note: it is allowed to set the pos beyond datalen as long as there is enough memory
/// but it is not recommended to do so since it will leave a chunk of uninitialized memory 
///in the middle of the stream buffer
{
	if(!stream) return 0;
	if(stream->max_size && pos > stream->max_size) return 0;
	while(pos > stream->buf_size) {
		// expand buf to meet the requirement
		if(!expand_buf(stream)) {
			stream->error = 1;
			return 0; //Cannot write stream because not enough memory
		}
	}
	stream->cursor_pos = pos;
	return 1;
}

int stream_read_from_file(stream *stream, FILE *file, size_t size)
{
	// attempt to enlarge the stream if buffer is not enough
	while(size > stream->buf_size-stream->cursor_pos) {
		if(!expand_buf(stream)) {
			stream->error = 1;
			return 0; //Cannot write stream because not enough memory
		}
	}
	// all or nothing operation
	if(!fread(stream->buf+stream->cursor_pos, size, 1, file)) {
		stream->error = 2; //EOF
		return 0;
	}
	stream->cursor_pos += size;
	stream->datalen = (stream->datalen > stream->cursor_pos ? stream->datalen : stream->cursor_pos);
	return size;
}

int stream_copy_all(stream *stream, void *data)
{
	if(!stream || !data) return 0;
	if(!memcpy(data, stream->buf, stream->datalen)) {
		return 0;//memory copy error
	}
	return 1;
}

void stream_dump(stream *stream)
{
	if(stream) {
		printf("STREAM DUMP: buf_size: %ld, cursor_pos: %ld, datalen: %ld, max_size: %ld, error: %ld\n", \
		stream->buf_size, stream->cursor_pos, stream->datalen, stream->max_size, stream->error);
		int i;
		for(i = 0; i < stream->buf_size; i++) {
			printf("%02x ", (unsigned char)stream->buf[i]);
		}
		printf("\n");
	}
}

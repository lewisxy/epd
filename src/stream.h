#ifndef _stream_h
#define _stream_h

// All returnable functions (except stream_error which return the error code) 
// return a positive number on SUCCESS, return 0 on FAILURE

typedef struct {
	char *buf;
	size_t buf_size;
	size_t max_size;
	long cursor_pos;
	long datalen;
	long error;
} stream;


// return a stream object with initial size min and maximum size max_size, return NULL if failed
// min must > 0 and max_size can be any number, if max_size <= 0, there is no memory limit on this stream
stream *stream_create(size_t min, size_t max_size);

// clear the data on current stream, reset the cursor_pos, datalen, and error
// the memory will NOT be freed!!!
void stream_clear(stream *stream);

// close a stream object and free all its memory
int stream_close(stream *stream);

// return the error code of current stream, 1 indicates memory problem, 2 indicates other problems
int stream_error(stream *stream);

// set the error to 0 of a stream
void stream_clearerr(stream *stream);

// read something from a stream to location indicated by ptr of size bytes each and nmemb number
// it is NOT a all-or-nothing operation!!!
// Its behavior is similar to the POSIX function fread()
size_t stream_read(void *ptr, size_t size, size_t nmemb, stream *stream);

// write something from the location indicated by ptr of size each bytes and nmemb number to a stream
// it is a all-or-nothing operation!!!
// it will automatically expand the memory usage if the total size need to write(size*nmemb) is more than
// current available buffer space in stream
// if there is not enough space, it will return 0 and the operation will failed
// other behaviors are similar to POSIX fwrite(), but may be changed in the future
size_t stream_write(const void *ptr, size_t size, size_t nmemb, stream *stream);

// return the cursor position of a stream
int stream_getpos(stream *stream, long *pos);

// set the cursor position of a stream
// if the value set is greater than current buffer size, the memory will be automatically allocated to
// satisfy the demand, if the pos value is too large for memory allocation or limited by max_size of 
// buffer, this operation will failed
int stream_setpos(stream *stream, const long pos);

// read something from a file using POSIX fread operation, 
// if fread failed, it will mark a error = 2 on the current stream
int stream_read_from_file(stream *stream, FILE *file, size_t size);

// make a copy of all the data in a stream to the location pointed by data
// if memcpy() failed, it will return 0; however, due to the unreliability of memcpy() on some platform,
// you should prepare enough memory for *data to prevent the failure which could otherwise cause some nasty undefined behaviors
int stream_copy_all(stream *stream, void *data);

// dump all info and data of a stream, for debugging purpose only
void stream_dump(stream *stream);

#endif
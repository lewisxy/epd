#include <stdio.h>
#include <stdlib.h>

#include "../key.h"
#include "../stream.h"
#include "../util.h"

void test_load_key(stream *st)
{
	printf("attempting to load key from file ... \n");
	char pub[32], sec[32];
	if(!key_load_pub(st, pub)) {
		printf("failed to load public key");
		exit(EXIT_FAILURE);
	}
	printf("pub loaded from file: ");
	dump_bin(pub, sizeof(pub));
	printf("\n");
	
	if(!key_load_sec(st, sec)) {
		printf("failed to load secret key");
		exit(EXIT_FAILURE);
	}
	printf("sec loaded from file: ");
	dump_bin(sec, sizeof(sec));
	printf("\n");
}

void test()
{
	stream *st = NULL;
	if(!key_create(&st)) {
		printf("key creation failed");
		exit(EXIT_FAILURE);
	}
	stream_dump(st);
	//====================
	test_load_key(st);
	stream_dump(st);
	//====================
	if(!key_change_pw(st)) {
		printf("failed to change password");
		exit(EXIT_FAILURE);
	}
	stream_dump(st);
	test_load_key(st);
	
}

int main()
{
	test();
	return 0;
}
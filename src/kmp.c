#include <stdio.h>
#include <stdlib.h>

// https://www.geeksforgeeks.org/searching-for-patterns-set-2-kmp-algorithm/

void compute_lps(char *pat, long *rtn, size_t size)
{
	long j = 0, i = 1;
	rtn[0] = 0;
	while(i < size) {
		if(pat[i] == pat[j]) {
			j++;
			rtn[i] = j;
			i++;
		} else {
			if(j > 0) {
				j = rtn[j-1];
			} else {
				rtn[i] = 0;
				i++;
			}
		}
	}
}

long KMP_match_first(char *pat, size_t sp, char *txt, size_t st)
{
	// the below code include VLA, a C99 feature that is not implemented in MSVC compiler
	//long lps[sp];
	// for the sake of compatibility, using malloc() will make this program compatible with C89 standard
	long *lps = malloc(sp*sizeof(long));
	if(!sp) abort();
	long i = 0, j = 0;
	compute_lps(pat, lps, sp);
	while(i < st) {
		if(pat[j] == txt[i]) {
			if(j == sp-1) {
				free(lps);
				return i-j;
			} else {
				i++;
				j++;
			}
		} else if(j > 0) {
			j = lps[j-1];
		} else {
			i++;
		}
	}
	free(lps);
	return -1;
}

// *rtn will be a free-able array of starting index that matched
// return value will be the number of times matched
long KMP_match_all(char *pat, size_t sp, char *txt, size_t st, long **rtn)
{
	// the below code include VLA(variable length array), a C99 feature that is not implemented in MSVC compiler
	//long lps[sp];
	// for the sake of compatibility, using malloc() will make this program compatible with C89 standard
	long *lps = malloc(sp*sizeof(long));
	long *tmp = malloc(sizeof(long));
	if(!sp || !tmp) abort();
	long i = 0, j = 0, count = 0;
	compute_lps(pat, lps, sp);
	while(i < st) {
		if(pat[j] == txt[i]) {
			i++;
			j++;
		} 
		if(j == sp) {
			count++;
			long *tmp2 = realloc(tmp, sizeof(long)*count);
			if(!tmp2) abort();
			tmp = tmp2;
			// be careful when handling polongers!!!
			tmp[count-1] = i-j;
			j = lps[j-1];
		}
		if(i < st && pat[j] != txt[i]) {
			if(j > 0) {
				j = lps[j-1];
			} else {
				i++;
			}
		}
	}
	// this is the correct way to do it!!!
	*rtn = tmp;
	free(lps);
	return count;
}

#if defined(KMP_TEST)

int main()
{
	//char txt[] = "abacaabadcabacabaabb";
	//char pat[] = "abacab";
	
	char txt[] = "00012347502859123689478096712368949312369850939212896041233333";
	char pat[] = "123";
	
	long res = KMP_match_first(pat, sizeof(pat)-1, txt, sizeof(txt)-1);
	if(res != -1) {
		printf("Matched at %ld\n", res);
	} else {
		printf("No match\n");
	}
	
	long *idx = NULL;
	res = KMP_match_all(pat, sizeof(pat)-1, txt, sizeof(txt)-1, &idx);
	if(res) {
		printf("%ld matched in total, at: ", res);
		long i;
		for(i = 0; i < res; i++) {
			printf("%ld ", idx[i]);
		}
		printf("\n");
	} else {
		printf("No match\n");
	}
	free(idx);
	return 0;
}

#endif
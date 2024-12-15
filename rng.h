#ifndef _RNG_H 
#define _RNG_H 1

#ifdef __cplusplus
extern "C" {
#endif
	int RAND_bytes(unsigned char* buf, int num); // from openssl 


#ifdef __cplusplus
}
#endif
#endif
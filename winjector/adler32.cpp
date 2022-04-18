#include "adler32.h"

DWORD adler32(const char* buf, size_t buf_length)
{
	DWORD s1 = 1;
	DWORD s2 = 0;

	while (buf_length--)
	{
		s1 = (s1 + *(buf++)) % 65521;
		s2 = (s2 + s1) % 65521;
	}
	return (s2 << 16) + s1;
}
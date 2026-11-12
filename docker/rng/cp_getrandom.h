/*
 * Entropy source for the CryptoPro RNG plugin that is built from the vendor
 * sample in <cprocsp>/src/rdk/rndm0.
 *
 * The sample's rndm0_rndm() fills the buffer with a constant (0xaa), which is
 * fine as a compile-time template but useless for real keys. This header is
 * force-included into the plugin sources (-include) and provides
 * cp_fill_random(), a drop-in replacement backed by the kernel CSPRNG.
 *
 * Kept as a separate static function so it can be force-included into several
 * translation units without link conflicts.
 */
#ifndef CP_GETRANDOM_H
#define CP_GETRANDOM_H

/* The vendor headers (reader/support.h and friends) rely on uint16_t,
 * wchar_t and va_list being available without including <stdint.h>,
 * <stdwchar.h> or <stdarg.h> themselves. Debian pulls those in transitively,
 * AlmaLinux does not, so they are included here as well. */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

/* Fills buf with len bytes of cryptographically strong randomness.
 * Returns 0 on success, -1 if no entropy source is available. */
static int cp_fill_random(void *buf, size_t len)
{
	unsigned char *p = (unsigned char *)buf;
	int fd;

#if defined(__linux__)
	while (len > 0) {
		ssize_t n = getrandom(p, len, 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			break; /* fall back to /dev/urandom below */
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	if (len == 0) {
		return 0;
	}
#endif

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	while (len > 0) {
		ssize_t n = read(fd, p, len);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) {
				continue;
			}
			close(fd);
			return -1;
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	close(fd);
	return 0;
}

#endif /* CP_GETRANDOM_H */

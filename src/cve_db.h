#ifndef CVE_DB_H
#define CVE_DB_H
#include <stddef.h>
int lookup_cve_info(const char *cve, char *vector, size_t vecsz,
                    char *desc, size_t descsz);
#endif

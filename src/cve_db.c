#include "cve_db.h"
#include <string.h>

typedef struct {
    const char *cve;
    const char *vector;
    const char *desc;
} CVERecord;

static CVERecord db[] = {
    {"CVE-2021-23017", "NETWORK", "A security issue in nginx resolver was identified, which might allow an attacker able to forge UDP packets from the DNS server to cause memory corruption."},
    {"CVE-2021-3618",  "NETWORK", "ALPACA is an application layer protocol content confusion attack that can redirect traffic between subdomains."},
    {"CVE-2019-20372", "NETWORK", "NGINX before 1.17.7 with certain error_page configs allows HTTP request smuggling."}
};

int lookup_cve_info(const char *cve, char *vector, size_t vecsz,
                    char *desc, size_t descsz) {
    for (size_t i = 0; i < sizeof(db)/sizeof(db[0]); i++) {
        if (strcmp(db[i].cve, cve) == 0) {
            strncpy(vector, db[i].vector, vecsz - 1);
            vector[vecsz - 1] = '\0';
            strncpy(desc, db[i].desc, descsz - 1);
            desc[descsz - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

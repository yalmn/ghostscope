#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include "../lib/cJSON/cJSON.h"
#include "ip_filter.h"

#define MAX_LINE_LEN 256

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void filter_valid_ips(const char *api_key, const char *input_file, const char *output_file) {
    FILE *infile = fopen(input_file, "r");
    FILE *outfile = fopen(output_file, "w");

    if (!infile || !outfile) {
        fprintf(stderr, "[!] Fehler beim Öffnen von Dateien.\n");
        return;
    }

    char line[MAX_LINE_LEN];

    while (fgets(line, sizeof(line), infile)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) continue;

        char url[512];
        snprintf(url, sizeof(url),
                 "https://api.shodan.io/shodan/host/search?key=%s&query=net:%s",
                 api_key, line);

        CURL *curl = curl_easy_init();
        struct MemoryStruct chunk = { .memory = malloc(1), .size = 0 };

        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "shodan-cli-tool");

            CURLcode res = curl_easy_perform(curl);
            if (res == CURLE_OK) {
                cJSON *root = cJSON_Parse(chunk.memory);
                if (root) {
                    cJSON *matches = cJSON_GetObjectItem(root, "matches");
                    if (cJSON_IsArray(matches)) {
                        cJSON *match;
                        int found = 0;

                        cJSON_ArrayForEach(match, matches) {
                            cJSON *ip = cJSON_GetObjectItem(match, "ip_str");
                            if (cJSON_IsString(ip)) {
                                fprintf(outfile, "%s\n", ip->valuestring);
                                printf("[+] Gefundene IP: %s\n", ip->valuestring);
                                found++;
                            }
                        }

                        if (found == 0) {
                            printf("[-] Keine IPs gefunden für Range: %s\n", line);
                        }
                    }
                    cJSON_Delete(root);
                } else {
                    fprintf(stderr, "[!] Fehler beim Parsen der Antwort für: %s\n", line);
                }
            } else {
                fprintf(stderr, "[!] Anfrage fehlgeschlagen für: %s\n", line);
            }

            curl_easy_cleanup(curl);
            free(chunk.memory);
        }

        sleep(1); // API-Rate-Limit einhalten
    }

    fclose(infile);
    fclose(outfile);
}

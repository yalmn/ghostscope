#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "../lib/cJSON/cJSON.h"
#include "shodan_api.h"

#define MAX_IP_LEN 64

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

void print_basic_info(cJSON *root) {
    const char *fields[] = {"ip_str", "asn", "city", "country_code", "org", "os", "isp", "last_update"};
    for (int i = 0; i < sizeof(fields)/sizeof(fields[0]); ++i) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(root, fields[i]);
        if (cJSON_IsString(item)) {
            printf("%s: %s\n", fields[i], item->valuestring);
        }
    }

    // Ports
    cJSON *ports = cJSON_GetObjectItemCaseSensitive(root, "ports");
    if (cJSON_IsArray(ports)) {
        printf("Ports: ");
        cJSON *port;
        cJSON_ArrayForEach(port, ports) {
            if (cJSON_IsNumber(port)) {
                printf("%d ", port->valueint);
            }
        }
        printf("\n");
    }

    // Vulns
    cJSON *vulns = cJSON_GetObjectItemCaseSensitive(root, "vulns");
    if (cJSON_IsObject(vulns)) {
        printf("Vulnerabilities:\n");
        cJSON *vuln = NULL;
        cJSON_ArrayForEach(vuln, vulns) {
            printf(" - %s\n", vuln->string);
        }
    }
    printf("\n---------------------------\n");
}

void process_shodan_data(const char *api_key, const char *ip_list_file, const char *output_file) {
    FILE *file = fopen(ip_list_file, "r");
    if (!file) {
        fprintf(stderr, "[!] Konnte %s nicht öffnen\n", ip_list_file);
        return;
    }

    char ip[MAX_IP_LEN];
    while (fgets(ip, sizeof(ip), file)) {
        ip[strcspn(ip, "\r\n")] = '\0';
        if (strlen(ip) == 0) continue;

        char url[512];
        snprintf(url, sizeof(url),
                 "https://api.shodan.io/shodan/host/%s?key=%s", ip, api_key);

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
                    print_basic_info(root);
                    // Hier später: HTML-Ausgabe vorbereiten
                    cJSON_Delete(root);
                } else {
                    fprintf(stderr, "[!] Fehler beim Parsen der JSON-Antwort für %s\n", ip);
                }
            } else {
                fprintf(stderr, "[!] Anfrage fehlgeschlagen für IP %s\n", ip);
            }

            curl_easy_cleanup(curl);
            free(chunk.memory);
        }
    }

    fclose(file);
}

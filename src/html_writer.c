#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include "../lib/cJSON/cJSON.h"
#include "html_writer.h"

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

void write_html_header(FILE *out) {
    fprintf(out, "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                 "<title>Shodan Report</title>"
                 "<style>body{font-family:monospace;background:#f9f9f9;padding:20px;} .ip-block{border:1px solid #ccc;padding:10px;margin-bottom:15px;background:white;}</style>"
                 "</head><body><h1>Shodan IP Report</h1>\n");
}

void write_html_footer(FILE *out) {
    fprintf(out, "</body></html>");
}

void write_json_to_html(FILE *out, cJSON *json) {
    const char *fields[] = {"ip_str", "asn", "city", "country_code", "org", "os", "isp", "last_update"};

    fprintf(out, "<div class='ip-block'>\n");

    for (int i = 0; i < sizeof(fields)/sizeof(fields[0]); ++i) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(json, fields[i]);
        if (cJSON_IsString(item)) {
            fprintf(out, "<strong>%s:</strong> %s<br>\n", fields[i], item->valuestring);
        }
    }

    cJSON *ports = cJSON_GetObjectItemCaseSensitive(json, "ports");
    if (cJSON_IsArray(ports)) {
        fprintf(out, "<strong>Ports:</strong> ");
        cJSON *port;
        cJSON_ArrayForEach(port, ports) {
            if (cJSON_IsNumber(port)) {
                fprintf(out, "%d ", port->valueint);
            }
        }
        fprintf(out, "<br>\n");
    }

    cJSON *vulns = cJSON_GetObjectItemCaseSensitive(json, "vulns");
    if (cJSON_IsArray(vulns)) {
        fprintf(out, "<strong>Vulnerabilities:</strong><ul>");
        cJSON *vuln = NULL;
        cJSON_ArrayForEach(vuln, vulns) {
            if (cJSON_IsString(vuln)) {
                fprintf(out, "<li>%s</li>", vuln->valuestring);
            }
        }
        fprintf(out, "</ul>\n");
    }

    fprintf(out, "</div>\n");
}

void generate_html_report(const char *api_key, const char *ip_list_file, const char *output_html_file) {
    FILE *infile = fopen(ip_list_file, "r");
    FILE *outfile = fopen(output_html_file, "w");

    if (!infile || !outfile) {
        fprintf(stderr, "[!] Fehler beim Öffnen von Dateien.\n");
        return;
    }

    write_html_header(outfile);

    char ip[MAX_IP_LEN];
    while (fgets(ip, sizeof(ip), infile)) {
        ip[strcspn(ip, "\r\n")] = '\0';
        if (strlen(ip) == 0) continue;

        char url[512];
        snprintf(url, sizeof(url), "https://api.shodan.io/shodan/host/%s?key=%s", ip, api_key);

        CURL *curl = curl_easy_init();
        struct MemoryStruct chunk = { .memory = malloc(1), .size = 0 };

        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "shodan-html-generator");

            CURLcode res = curl_easy_perform(curl);
            if (res == CURLE_OK) {
                cJSON *root = cJSON_Parse(chunk.memory);
                if (root) {
                    write_json_to_html(outfile, root);
                    cJSON_Delete(root);
                } else {
                    fprintf(stderr, "[!] Fehler beim Parsen der Antwort von %s\n", ip);
                }
            }

            curl_easy_cleanup(curl);
            free(chunk.memory);
        }

        sleep(1); // API Rate Limit einhalten
    }

    write_html_footer(outfile);

    fclose(infile);
    fclose(outfile);
}

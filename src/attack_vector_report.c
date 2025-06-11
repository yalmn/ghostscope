#include "attack_vector_report.h"
#include "../lib/cJSON/cJSON.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_IP_LEN 64

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if (!ptr)
    return 0;

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

static int fetch_attack_vector(const char *cve, char *buffer, size_t bufsz) {
  char year[8] = "";
  char id_part[16] = "";

  if (sscanf(cve, "CVE-%7[^-]-%15s", year, id_part) != 2)
    return 0;

  int id_num = atoi(id_part);
  char prefix[16];
  snprintf(prefix, sizeof(prefix), "%dxxx", id_num / 1000);

  char url[512];
  snprintf(url, sizeof(url),
           "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/%s/%s/CVE-%s.json",
           year, prefix, cve);

  CURL *curl = curl_easy_init();
  struct MemoryStruct chunk = {.memory = malloc(1), .size = 0};
  int ret = 0;

  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ghostscope-cve-fetch");

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
      cJSON *root = cJSON_Parse(chunk.memory);
      if (root) {
        cJSON *containers = cJSON_GetObjectItemCaseSensitive(root, "containers");
        if (cJSON_IsObject(containers)) {
          cJSON *cna = cJSON_GetObjectItemCaseSensitive(containers, "cna");
          if (cJSON_IsObject(cna)) {
            cJSON *metrics = cJSON_GetObjectItemCaseSensitive(cna, "metrics");
            if (cJSON_IsArray(metrics)) {
              cJSON *metric;
              cJSON_ArrayForEach(metric, metrics) {
                cJSON *cvss = cJSON_GetObjectItemCaseSensitive(metric, "cvssV3_1");
                if (!cJSON_IsObject(cvss))
                  cvss = cJSON_GetObjectItemCaseSensitive(metric, "cvssV3");
                if (cJSON_IsObject(cvss)) {
                  cJSON *attackVector = cJSON_GetObjectItemCaseSensitive(cvss, "attackVector");
                  if (cJSON_IsString(attackVector)) {
                    strncpy(buffer, attackVector->valuestring, bufsz - 1);
                    buffer[bufsz - 1] = '\0';
                    ret = 1;
                    break;
                  }
                }
              }
            }
          }
        }
        cJSON_Delete(root);
      }
    }

    curl_easy_cleanup(curl);
    free(chunk.memory);
  }

  return ret;
}

static int ip_already_seen(char seen_ips[][MAX_IP_LEN], int seen_count, const char *ip) {
  for (int i = 0; i < seen_count; i++) {
    if (strcmp(seen_ips[i], ip) == 0)
      return 1;
  }
  return 0;
}

static void write_header(FILE *out) {
  fprintf(out,
          "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<title>CVE Attack Vectors</title>"
          "<style>body{font-family:monospace;background:#f9f9f9;padding:20px;}"
          ".ip-block{border:1px solid #ccc;padding:10px;margin-bottom:15px;background:white;}"
          "</style></head><body><h1>CVE Attack Vectors</h1>\n");
}

static void write_footer(FILE *out) {
  fprintf(out, "</body></html>");
}

void generate_attack_vector_report(const char *api_key, const char *ip_list_file,
                                   const char *output_html_file) {
  FILE *infile = fopen(ip_list_file, "r");
  FILE *outfile = fopen(output_html_file, "w");

  if (!infile || !outfile) {
    fprintf(stderr, "[!] Fehler beim Öffnen von Dateien.\n");
    return;
  }

  write_header(outfile);

  char ip[MAX_IP_LEN];
  char seen_ips[10000][MAX_IP_LEN];
  int seen_count = 0;

  while (fgets(ip, sizeof(ip), infile)) {
    ip[strcspn(ip, "\r\n")] = '\0';
    if (strlen(ip) == 0)
      continue;
    if (ip_already_seen(seen_ips, seen_count, ip))
      continue;

    strncpy(seen_ips[seen_count], ip, MAX_IP_LEN);
    seen_count++;

    fprintf(outfile, "<div class='ip-block'><strong>IP:</strong> %s<ul>\n", ip);

    char url[512];
    snprintf(url, sizeof(url), "https://api.shodan.io/shodan/host/%s?key=%s", ip,
             api_key);

    CURL *curl = curl_easy_init();
    struct MemoryStruct chunk = {.memory = malloc(1), .size = 0};

    if (curl) {
      curl_easy_setopt(curl, CURLOPT_URL, url);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, "ghostscope-html-generator");

      CURLcode res = curl_easy_perform(curl);
      if (res == CURLE_OK) {
        cJSON *root = cJSON_Parse(chunk.memory);
        if (root) {
          cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
          if (cJSON_IsArray(data)) {
            char seen_cves[512][64];
            int seen_cve_count = 0;
            cJSON *entry;
            cJSON_ArrayForEach(entry, data) {
              cJSON *vulns = cJSON_GetObjectItemCaseSensitive(entry, "vulns");
              if (cJSON_IsObject(vulns)) {
                cJSON *vuln = vulns->child;
                while (vuln) {
                  if (vuln->string && cJSON_IsObject(vuln)) {
                    int already = 0;
                    for (int i = 0; i < seen_cve_count; i++) {
                      if (strcmp(seen_cves[i], vuln->string) == 0) {
                        already = 1;
                        break;
                      }
                    }
                    if (already) {
                      vuln = vuln->next;
                      continue;
                    }
                    strncpy(seen_cves[seen_cve_count++], vuln->string, 63);

                    char vector[64] = "Unknown";
                    if (fetch_attack_vector(vuln->string, vector, sizeof(vector))) {
                      fprintf(outfile, "<li><strong>%s:</strong> %s</li>\n", vuln->string, vector);
                    } else {
                      fprintf(outfile, "<li><strong>%s:</strong> %s</li>\n", vuln->string, vector);
                    }
                  }
                  vuln = vuln->next;
                }
              }
            }
          }
          cJSON_Delete(root);
        }
      }

      curl_easy_cleanup(curl);
      free(chunk.memory);
    }

    fprintf(outfile, "</ul></div>\n");
    sleep(1);
  }

  write_footer(outfile);

  fclose(infile);
  fclose(outfile);
}


#include "html_writer.h"
#include "../lib/cJSON/cJSON.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_IP_LEN 64
#define MAX_SEEN_IPS 10000

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

int ip_already_seen(char seen_ips[][MAX_IP_LEN], int seen_count,
                    const char *ip) {
  for (int i = 0; i < seen_count; i++) {
    if (strcmp(seen_ips[i], ip) == 0) {
      return 1;
    }
  }
  return 0;
}

void write_html_header(FILE *out) {
  fprintf(out,
          "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<title>Shodan Report</title>"
          "<style>body{font-family:monospace;background:#f9f9f9;padding:20px;} \
                 .ip-block{border:1px solid #ccc;padding:10px;margin-bottom:15px;background:white;} \
                 .low{color:green;} .medium{color:orange;} .high{color:red;} \
                 .legend{margin-bottom:20px; padding:10px; background:#eee; border:1px solid #ccc;}"
          "</style></head><body><h1>Shodan IP Report</h1>\n");

  // Legende einfügen
  fprintf(out, "<div class='legend'><strong>Legende CVSS Score:</strong><br>"
               "<span class='low'>CVSS &lt; 4.0</span> = Low<br>"
               "<span class='medium'>CVSS 4.0 - 6.9</span> = Medium<br>"
               "<span class='high'>CVSS ≥ 7.0</span> = High</div>\n");
}

void write_html_footer(FILE *out) { fprintf(out, "</body></html>"); }

void write_json_to_html(FILE *out, cJSON *json) {
  const char *fields[] = {"ip_str", "asn", "city", "country_code",
                          "org",    "os",  "isp",  "last_update"};

  fprintf(out, "<div class='ip-block'>\n");

  for (int i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, fields[i]);
    if (cJSON_IsString(item)) {
      fprintf(out, "<strong>%s:</strong> %s<br>\n", fields[i],
              item->valuestring);
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

  cJSON *data = cJSON_GetObjectItemCaseSensitive(json, "data");
  if (cJSON_IsArray(data)) {
    cJSON *entry;
    cJSON_ArrayForEach(entry, data) {
      cJSON *vulns = cJSON_GetObjectItemCaseSensitive(entry, "vulns");
      if (cJSON_IsObject(vulns)) {
        fprintf(out, "<strong>Vulnerabilities:</strong><ul>\n");
        cJSON *vuln = vulns->child;
        while (vuln) {
          if (vuln->string && cJSON_IsObject(vuln)) {
            fprintf(out, "<li><strong>%s</strong><ul>", vuln->string);

            cJSON *cvss = cJSON_GetObjectItemCaseSensitive(vuln, "cvss");
            cJSON *cvss_v2 = cJSON_GetObjectItemCaseSensitive(vuln, "cvss_v2");
            cJSON *cvss_version =
                cJSON_GetObjectItemCaseSensitive(vuln, "cvss_version");
            cJSON *epss = cJSON_GetObjectItemCaseSensitive(vuln, "epss");
            cJSON *ranking_epss =
                cJSON_GetObjectItemCaseSensitive(vuln, "ranking_epss");
            cJSON *summary = cJSON_GetObjectItemCaseSensitive(vuln, "summary");

            if (cJSON_IsNumber(cvss)) {
              const char *class = "low";
              if (cvss->valuedouble >= 7.0)
                class = "high";
              else if (cvss->valuedouble >= 4.0)
                class = "medium";
              fprintf(out, "<li class='%s'>CVSS: %.1f</li>\n", class,
                      cvss->valuedouble);
            }
            if (cJSON_IsNumber(cvss_v2))
              fprintf(out, "<li>CVSS v2: %.1f</li>\n", cvss_v2->valuedouble);
            if (cJSON_IsNumber(cvss_version))
              fprintf(out, "<li>CVSS Version: %.0f</li>\n",
                      cvss_version->valuedouble);
            if (cJSON_IsNumber(epss))
              fprintf(out, "<li>EPSS: %.5f</li>\n", epss->valuedouble);
            if (cJSON_IsNumber(ranking_epss))
              fprintf(out, "<li>EPSS Ranking: %.5f</li>\n",
                      ranking_epss->valuedouble);
            if (cJSON_IsString(summary))
              fprintf(out, "<li>Summary: %s</li>\n", summary->valuestring);

            fprintf(out, "</ul></li>\n");
          }
          vuln = vuln->next;
        }
        fprintf(out, "</ul>\n");
      }
    }
  }

  fprintf(out, "</div>\n");
}

void generate_html_report(const char *api_key, const char *ip_list_file,
                          const char *output_html_file) {
  FILE *infile = fopen(ip_list_file, "r");
  FILE *outfile = fopen(output_html_file, "w");

  if (!infile || !outfile) {
    fprintf(stderr, "[!] Fehler beim Öffnen von Dateien.\n");
    return;
  }

  write_html_header(outfile);

  char ip[MAX_IP_LEN];
  char seen_ips[MAX_SEEN_IPS][MAX_IP_LEN];
  int seen_count = 0;

  while (fgets(ip, sizeof(ip), infile)) {
    ip[strcspn(ip, "\r\n")] = '\0';
    if (strlen(ip) == 0)
      continue;
    if (ip_already_seen(seen_ips, seen_count, ip))
      continue;

    strncpy(seen_ips[seen_count], ip, MAX_IP_LEN);
    seen_count++;

    char url[512];
    snprintf(url, sizeof(url), "https://api.shodan.io/shodan/host/%s?key=%s",
             ip, api_key);

    CURL *curl = curl_easy_init();
    struct MemoryStruct chunk = {.memory = malloc(1), .size = 0};

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

#include "html_writer.h"
#include "ip_filter.h"
#include "utils.h"
#include "attack_vector_report.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void show_usage(const char *progname) {
  printf("Verwendung:\n");
  printf("  %s --filter     Nur IP-Ranges filtern\n", progname);
  printf("  %s --report     Nur HTML-Report generieren\n", progname);
  printf("  %s --attack     CVE Attack-Vektoren generieren\n", progname);
  printf("  %s --all        Alles ausführen (Filter + Report + Attack)\n", progname);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    show_usage(argv[0]);
    return 1;
  }

  char *apikey = read_apikey("apikey.txt");
  if (!apikey) {
    fprintf(stderr, "[!] API-Key konnte nicht geladen werden!\n");
    return 1;
  }

  if (strcmp(argv[1], "--filter") == 0) {
    printf("[*] Starte IP-Filterung...\n");
    filter_valid_ips(apikey, "iprange.txt", "filtered.txt");
  } else if (strcmp(argv[1], "--report") == 0) {
    printf("[*] Generiere HTML-Report...\n");
    generate_html_report(apikey, "filtered.txt", "result.html");
  } else if (strcmp(argv[1], "--attack") == 0) {
    printf("[*] Generiere Attack-Vector-Report...\n");
    generate_attack_vector_report(apikey, "filtered.txt",
                                  "cve-attack-vector.html");
  } else if (strcmp(argv[1], "--all") == 0) {
    printf("[*] IP-Filterung & Report...\n");
    filter_valid_ips(apikey, "iprange.txt", "filtered.txt");
    sleep(1);
    generate_html_report(apikey, "filtered.txt", "result.html");
    sleep(1);
    generate_attack_vector_report(apikey, "filtered.txt",
                                  "cve-attack-vector.html");
  } else {
    show_usage(argv[0]);
    free(apikey);
    return 1;
  }

  free(apikey);
  return 0;
}

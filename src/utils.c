#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *read_apikey(const char *filepath) {
  FILE *file = fopen(filepath, "r");
  if (!file) {
    perror("Fehler beim Öffnen der API-Key-Datei");
    return NULL;
  }

  char buffer[256];
  if (fgets(buffer, sizeof(buffer), file) == NULL) {
    fclose(file);
    fprintf(stderr, "Fehler beim Lesen des API-Keys\n");
    return NULL;
  }
  fclose(file);

  buffer[strcspn(buffer, "\r\n")] = '\0';

  char *key = malloc(strlen(buffer) + 1);
  if (!key)
    return NULL;
  strcpy(key, buffer);
  return key;
}

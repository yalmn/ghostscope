#include "eol_check.h"
#include <string.h>

// Strukturierte Liste mit bekannten EOL-Produkten
typedef struct {
  const char *pattern;
  const char *reason;
} EOLSignature;

static const EOLSignature eol_list[] = {
    {"windows_xp", "Microsoft Windows XP (EOL seit 2014)"},
    {"windows_7", "Microsoft Windows 7 (EOL seit 2020)"},
    {"windows_server:2003", "Windows Server 2003 (EOL seit 2015)"},
    {"windows_server:2008", "Windows Server 2008 (EOL seit 2020)"},
    {"windows_8", "Windows 8 (EOL seit 2023)"},
    {"linux_kernel:2.6", "Linux Kernel 2.6 (veraltet)"},
    {"debian:7", "Debian 7 Wheezy (EOL seit 2018)"},
    {"debian:8", "Debian 8 Jessie (EOL seit 2020)"},
    {"debian:9", "Debian 9 Stretch (EOL seit 2022)"},
    {"ubuntu:14.04", "Ubuntu 14.04 (EOL seit 2019)"},
    {"ubuntu:16.04", "Ubuntu 16.04 (EOL seit 2021)"},
    {"ubuntu:18.04", "Ubuntu 18.04 (EOL: April 2023 Standard Support)"},
    {"centos:6", "CentOS 6 (EOL seit 2020)"},
    {"centos:7", "CentOS 7 (EOL im Juni 2024)"},
    {"android:4", "Android 4.x (veraltet)"}};

int is_eol_cpe(const char *cpe_string) {
  if (!cpe_string)
    return 0;
  for (int i = 0; i < sizeof(eol_list) / sizeof(eol_list[0]); ++i) {
    if (strstr(cpe_string, eol_list[i].pattern)) {
      return 1;
    }
  }
  return 0;
}

const char *get_eol_reason(const char *cpe_string) {
  if (!cpe_string)
    return NULL;
  for (int i = 0; i < sizeof(eol_list) / sizeof(eol_list[0]); ++i) {
    if (strstr(cpe_string, eol_list[i].pattern)) {
      return eol_list[i].reason;
    }
  }
  return NULL;
}

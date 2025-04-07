#ifndef HTML_WRITER_H
#define HTML_WRITER_H

#include "../lib/cJSON/cJSON.h"
#include <stdio.h>

void generate_html_report(const char *api_key, const char *ip_list_file,
                          const char *output_html_file);

#endif

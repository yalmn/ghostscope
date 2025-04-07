#ifndef EOL_CHECK_H
#define EOL_CHECK_H

int is_eol_cpe(const char *cpe_string);
const char *
get_eol_reason(const char *cpe_string); // Optional: Warum ist es EOL?

#endif

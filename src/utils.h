#ifndef UTILS_H
#define UTILS_H

char* read_apikey(const char *filepath);
char* read_file_line(const char *filepath, int line_num);
int count_lines(const char *filepath);

#endif

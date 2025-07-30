#ifndef FPRINTBSTR_H
#define FPRINTBSTR_H

#include <stdio.h>
#include <ctype.h>
#include <string.h>

void fprintbstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);
void fprintsteps(FILE *fp, char *S, unsigned int *A, unsigned long long L);
int FindMarker(FILE *infile, const char *marker);
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
int read_bi_values(FILE *fp, const char *search_str, int *values, int max_values);

#endif // FPRINTBSTR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "fprintbstr.h"

#define	MAX_MARKER_LEN	50
#define MAX_LINE 1024  // Max line length


void fprintbstr(FILE *fp, char *S, unsigned char *A, unsigned long long L){
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

void fprintsteps(FILE *fp, char *S, unsigned int *A, unsigned long long L){
	unsigned long long  i;	
	fprintf(fp, "%s", S);

	fprintf(fp, "[");
	for ( i=0; i<L; i++ ){
		if(i != L-1){
			fprintf(fp, "%d, ", A[i]);
		}
		else{
			fprintf(fp, "%d ", A[i]);
		}
		
	}
	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "]");
	
	fprintf(fp, "\n");
}

int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	size_t		i, len;
	int curr_line;

	len = strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = (char)curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = (char)curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
	int			i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, (size_t)Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = (unsigned char)(ch - '0');
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = (unsigned char)(ch - 'A' + 10);
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = (unsigned char)(ch - 'a' + 10);
            else // shouldn't ever get here
                ich = 0;

			for ( i=0; i<Length-1; i++ )
				A[i] = (unsigned char)((A[i] << 4) | (A[i+1] >> 4));
			A[Length-1] = (unsigned char)((A[Length-1] << 4) | ich);
		}
	else
		return 0;

	return 1;
}

// Function to read integer values from a file based on a search string
int read_bi_values(FILE *fp, const char *search_str, int *values, int max_values) {
    char line[MAX_LINE];
    int count = 0;

    // Rewind file to ensure reading from the start
    rewind(fp);

    while (fgets(line, sizeof(line), fp)) {
        char *found = strstr(line, search_str);
        if (found) {
            char *numStart = found + strlen(search_str);  // Move past search string

            // Remove brackets if present
            for (char *ptr = numStart; *ptr; ptr++) {
                if (*ptr == '[' || *ptr == ']') {
                    *ptr = ' ';  // Replace brackets with spaces
                }
            }

            // Extract numbers using strtok
            char *token = strtok(numStart, ", ");
            while (token && count < max_values) {
                values[count++] = atoi(token);
                token = strtok(NULL, ", ");
            }
            break;  // Stop after finding the first matching line
        }
    }

    return count;  // Return the number of integers read
}
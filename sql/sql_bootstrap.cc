/* Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */


#include <ctype.h>
#include <string.h>
#include "sql_bootstrap.h"

int read_bootstrap_query(char *query, int *query_length,
                         fgets_input_t input, fgets_fn_t fgets_fn)
{
  char line_buffer[MAX_BOOTSTRAP_LINE_SIZE];
  const char *line;
  int len;
  int query_len= 0;

  for ( ; ; )
  {
    line= (*fgets_fn)(line_buffer, sizeof(line_buffer), input);

    if (line == NULL)
      return (query_len ? READ_BOOTSTRAP_ERROR : READ_BOOTSTRAP_EOF);

    len= strlen(line);

    /*
      Remove trailing whitespace characters.
      This assumes:
      - no multibyte encoded character can be found at the very end of a line,
      - whitespace characters from the "C" locale only.
     which is sufficient for the kind of queries found
     in the bootstrap scripts.
    */
    while (len && (isspace(line[len - 1])))
      len--;
    /*
      Cleanly end the string, so we don't have to test len > x
      all the time before reading line[x], in the code below.
    */
    line_buffer[len]= '\0';

    /* Skip blank lines */
    if (len == 0)
      continue;

    /* Skip # comments */
    if (line[0] == '#')
      continue;
    
    /* Skip -- comments */
    if ((line[0] == '-') && (line[1] == '-'))
      continue;

    /* Skip delimiter, ignored. */
    if (strncmp(line, "delimiter", 9) == 0)
      continue;

    if (query_len == 0)
    {
      if (line[len - 1] == ';')
      {
        /*
          The first line is terminated by ';'.
          This is a valid single line query.
        */
        memcpy(query, line, len);
        *query_length= len;
        query[len]= '\0';
        return 0;
      }
    }
    else
    {
      if ((len >= 2) && (line[0] == 'G') && (line[1] == 'O'))
      {
        /*
          Found the multiline 'GO' delimiter.
          This is a valid multi line query.
        */
        *query_length= query_len;
        query[query_len]= '\0';
        return 0;
      }
    }

    /* Append the current line to a multi line query. */
    if (query_len + len + 1 >= MAX_BOOTSTRAP_QUERY_SIZE)
      return READ_BOOTSTRAP_ERROR;

    if (query_len != 0)
    {
      /*
        Append a \n to the current line, if any,
        to preserve the intended presentation.
       */
      query[query_len]= '\n';
      query_len++;
    }
    memcpy(query + query_len, line, len);
    query_len+= len;
  }
}


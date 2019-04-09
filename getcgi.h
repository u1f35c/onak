/*
 * getcgivars.c - routine to read CGI input variables into an array.
 *
 * Copyright 2002 Jonathan McDowell <noodles@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __GETCGI_H_
#define __GETCGI_H_

/**
 *	txt2html - Takes a string and converts it to HTML.
 *	@string: The string to HTMLize.
 *
 *	Takes a string and escapes any HTML entities.
 */
char *txt2html(const char *string);

/*
 *	start_html - Start HTML output.
 *	@title: The title for the HTML.
 *
 *	Takes a title string and starts HTML output, including the
 *	Content-Type header all the way up to <BODY>.
 */
void start_html(const char *title);

/*
 *	end_html - End HTML output.
 *
 *	Ends HTML output - closes the BODY and HTML tags.
 */
void end_html(void);

char x2c(const char *what); 
void unescape_url(char *url); 
char **getcgivars(int argc, char *argv[]);

/**
 *	cleanupcgi - free the memory allocated for our CGI parameters.
 *	@cgivars: The CGI parameter list to free.
 *
 *	Frees up the elements of the CGI parameter array and then frees the
 *	array.
 */
void cleanupcgi(char **cgivars);

#endif /* __GETCGI_H_ */ 

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

#endif /* __GETCGI_H_ */ 

#ifndef __GETCGI_H_
#define __GETCGI_H_

/**
 *	txt2html - Takes a string and converts it to HTML.
 *	@string: The string to HTMLize.
 *
 *	Takes a string and escapes any HTML entities.
 */
char *txt2html(const char *string);

char x2c(char *what); 
void unescape_url(char *url); 
char **getcgivars(int argc, char *argv[]);

#endif /* __GETCGI_H_ */ 

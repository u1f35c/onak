/*
 * getcgivars.c - routine to read CGI input variables into an array.
 *
 * Jonathan McDowell <noodles@earth.li>
 *
 * The x2c() and unescape_url() routines were lifted directly
 * from NCSA's sample program util.c, packaged with their HTTPD.
 *
 * $Id: getcgi.c,v 1.5 2003/06/04 20:57:07 noodles Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "getcgi.h"

/**
 *	txt2html - Takes a string and converts it to HTML.
 *	@string: The string to HTMLize.
 *
 *	Takes a string and escapes any HTML entities.
 */
char *txt2html(const char *string)
{
	static char buf[1024];
	char *ptr = NULL;
	char *nextptr = NULL;

	memset(buf, 0, 1024);

	ptr = strchr(string, '<');
	if (ptr != NULL) {
		nextptr = ptr + 1;
		*ptr = 0;
		strncpy(buf, string, 1023);
		strncat(buf, "&lt;", 1023 - strlen(buf));
		string = nextptr;
	}

	ptr = strchr(string, '>');
	if (ptr != NULL) {
		nextptr = ptr + 1;
		*ptr = 0;
		strncat(buf, string, 1023 - strlen(buf));
		strncat(buf, "&gt;", 1023 - strlen(buf));
		string = nextptr;
	}
	
	/*
	 * TODO: We need to while() this really as each entity may appear more
	 * than once. We need to start with & and ; as we replace with those
	 * throughout. Fuck it for the moment though; it's Easter and < & > are
	 * the most common and tend to only appear once.
	 */

	strncat(buf, string, 1023 - strlen(buf));

	return buf;
}

/*
 *	start_html - Start HTML output.
 *	@title: The title for the HTML.
 *
 *	Takes a title string and starts HTML output, including the
 *	Content-Type header all the way up to <BODY>.
 */
void start_html(const char *title)
{
	puts("Content-Type: text/html; charset=UTF-8\n");
	puts("<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 3.2 Final//EN'>");
	puts("<HTML>");
	puts("<HEAD>");
	printf("<TITLE>%s</TITLE>\n", title);
	puts("</HEAD>");
	puts("<BODY>");

	return;
}

/*
 *	end_html - End HTML output.
 *
 *	Ends HTML output - closes the BODY and HTML tags.
 */
void end_html(void)
{
	puts("</BODY>");
	puts("</HTML>");

	return;
}


/* Convert a two-char hex string into the char it represents */
char x2c(const char *what) 
{
	register char digit;

	digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 :
					(what[0] - '0'));
	digit *= 16;
	digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 :
					(what[1] - '0'));
	
	return(digit);
}

/* Reduce any %xx escape sequences to the characters they represent */
void unescape_url(char *url) 
{
	register int i,j;

	for(i=0,j=0; url[j]; ++i,++j) {
		if((url[i] = url[j]) == '%') {
			url[i]=x2c(&url[j+1]);
			j+=2;
		}
	}
	
	url[i] = '\0';
}


/* Read the CGI input and place all name/val pairs into list.        */
/* Returns list containing name1, value1, name2, value2, ... , NULL  */
char **getcgivars(int argc, char *argv[]) 
{
	int i;
	char *request_method;
	int content_length, paircount;
	char *cgiinput = NULL;
	char **cgivars = NULL;
	char **pairlist = NULL;
	char *nvpair,*eqpos;

	/* Depending on the request method, read all CGI input into cgiinput */
	/* (really should produce HTML error messages, instead of exit()ing) */

	request_method = getenv("REQUEST_METHOD");
	
	if (request_method == NULL) {
		if (argc > 1) {
			cgiinput = strdup(argv[1]);
		} else {
			return NULL;
		}
	} else if (strlen(request_method)==0) {
		return NULL;
	} else if (!strcmp(request_method, "GET") ||
			!strcmp(request_method, "HEAD")) {
		cgiinput=strdup(getenv("QUERY_STRING"));
	} else if (!strcmp(request_method, "POST")) {
		if (getenv("CONTENT_TYPE") != NULL &&
				strcasecmp(getenv("CONTENT_TYPE"),
					"application/x-www-form-urlencoded")) {
			printf("getcgivars(): Unsupported Content-Type.\n");
			exit(1);
		}
		
		if (!(content_length = atoi(getenv("CONTENT_LENGTH")))) {
			printf("getcgivars(): No Content-Length was sent with"
					" the POST request.\n");
			exit(1);
		}
		
		if (!(cgiinput= (char *) malloc(content_length+1))) {
			printf("getcgivars(): Could not malloc for "
					"cgiinput.\n");
			exit(1);
		}
		
		if (!fread(cgiinput, content_length, 1, stdin)) {
			printf("Couldn't read CGI input from STDIN.\n");
			exit(1);
		}
		
		cgiinput[content_length]='\0';
		
	} else {
		printf("getcgivars(): unsupported REQUEST_METHOD\n");
		exit(1);
	}

	/* Change all plusses back to spaces */

	for(i=0; cgiinput[i]; i++) if (cgiinput[i]=='+') cgiinput[i] = ' ';

	/* First, split on "&" to extract the name-value pairs into pairlist */
	pairlist=(char **) malloc(256*sizeof(char **));
	paircount=0;
	nvpair=strtok(cgiinput, "&");
	while (nvpair) {
		pairlist[paircount++]= strdup(nvpair) ;
		if (!(paircount%256)) {
			pairlist=(char **) realloc(pairlist,
					(paircount+256)*sizeof(char **));
		}
		nvpair=strtok(NULL, "&") ;
	}

	pairlist[paircount]=0;		/* terminate the list with NULL */

	/* Then, from the list of pairs, extract the names and values */
	
	cgivars=(char **) malloc((paircount*2+1)*sizeof(char **));
	
	for (i=0; i<paircount; i++) {
		if ((eqpos=strchr(pairlist[i], '='))!=NULL) {
			*eqpos='\0';
			unescape_url(cgivars[i*2+1]=strdup(eqpos+1));
		} else {
			unescape_url(cgivars[i*2+1]=strdup(""));
		}
		unescape_url(cgivars[i*2]= strdup(pairlist[i])) ;
	}

	cgivars[paircount*2]=NULL;	/* terminate the list with NULL */
    
	/* Free anything that needs to be freed */
	free(cgiinput);
	for (i=0; pairlist[i]; i++) free(pairlist[i]);
	free(pairlist);

	/* Return the list of name-value strings */
	return cgivars;
}


/**
 *	cleanupcgi - free the memory allocated for our CGI parameters.
 *	@cgivars: The CGI parameter list to free.
 *
 *	Frees up the elements of the CGI parameter array and then frees the
 *	array.
 */
void cleanupcgi(char **cgivars)
{
	int i;

	if (cgivars != NULL) {
		for (i = 0; cgivars[i] != NULL; i++) {
			free(cgivars[i]);
			cgivars[i] = NULL;
		}
		free(cgivars);
		cgivars = NULL;
	}

	return;
}

/*
	parse.c - General string parsing routines.
	Copyright 1999 Jonathan McDowell for Project Purple

	19/09/1999 - Started writing.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"

struct strll *addtoend(struct strll *current, char *newstr)
{
	struct strll *new, *tmp;

	if ((new=malloc(sizeof(struct strll)))==NULL) {
		perror("addtoend()");
		exit(1);
	}

	new->str=newstr;
	new->next=NULL;

	if (current==NULL) {
		return new;
	} else {
		tmp=current;
		while (tmp->next!=NULL) tmp=tmp->next;
		tmp->next=new;
	}

	return current;
}

int parseline(struct cfginf commands[], const char *commandline)
{
	int loop=0;
	char *params;
	char command[CMDLEN], *pos=NULL;

	params=NULL;
	if (commands==NULL || commandline==NULL || strlen(commandline)==0) return 0;

	if ((params=strdup(commandline))==NULL) {
		return 0;
	}

	while (params[strlen(params)-1]<' ') params[strlen(params)-1]=0;

	if ((pos=strchr(params, ' '))!=NULL) {
		*pos=0;
		if (strlen(params)>=CMDLEN) {
			/* Hah. No buffer overflow here. (Egg on face approaching....) */
			free(params);
			return 0;
		}
		strncpy(command, params, CMDLEN);
		command[CMDLEN-1]=0;
		memmove(params, pos+1, strlen(commandline)-strlen(params));
	} else {
		if (strlen(params)>=CMDLEN) {
			/* Hah. No buffer overflow here. (Egg on face approaching....) */
			free(params);
			return 0;
		}
		strncpy(command, params, CMDLEN);
		command[CMDLEN-1]=0;
	}

	while (strlen(commands[loop].command)>0 && strcasecmp(command, commands[loop].command)!=0) {
		++loop;
	}

	if (strlen(commands[loop].command)==0) {
		return -1;
	} else {
		if (commands[loop].type==0 && params==NULL) {
			return loop+1;
		} else {
			switch (commands[loop].type) {
			case 1:	*((char **) commands[loop].var) = params;
				break;
			case 2: *((int *) commands[loop].var) = str2bool(params);
				free(params);
				break;
			case 3: *((int *) commands[loop].var) = atoi(params);
				free(params);
				break;
			case 4: *((struct strll **) commands[loop].var) = addtoend(*((struct strll **) commands[loop].var), params);
				break;
			default:
				break;
			}
			return loop+1;
		}
	}
}

int str2bool(const char *buf)
{
	if (strcasecmp("TRUE", buf) == 0 || strcmp("1", buf) == 0 ||
		strcasecmp("Y", buf) == 0 || strcasecmp("YES", buf) == 0 ||
		strcasecmp("T", buf) == 0) return 1;

	if (strcasecmp("FALSE", buf) == 0 || strcmp("0", buf) == 0 ||
		strcasecmp("N", buf) == 0 || strcasecmp("NO", buf) == 0 ||
		strcasecmp("F", buf) == 0) return 0;

	return -1;
}

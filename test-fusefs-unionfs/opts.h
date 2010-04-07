/*
* License: BSD-style license
* Copyright: Radek Podgorny <radek@podgorny.cz>,
*            Bernd Schubert <bernd-schubert@gmx.de>
*/

#ifndef OPTS_H
#define OPTS_H


#include <fuse.h>
#include <stdbool.h>

#include "unionfs.h"


#define ROOT_SEP ":"

typedef struct {
	int nroots;
	root_entry_t *roots;

	bool stats_enabled;
	bool cow_enabled;

	bool initgroups; // initgroups() will cause a deadlock on for a union of /etc

	int doexit;
	int retval;
} uopt_t;

enum {
	KEY_STATS,
	KEY_COW,
	KEY_NOINITGROUPS,
	KEY_HELP,
	KEY_VERSION
};


extern uopt_t uopt;


void uopt_init();
int unionfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs);


#endif

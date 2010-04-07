/*
* License: BSD-style license
* Copyright: Radek Podgorny <radek@podgorny.cz>,
*/

#include <stdio.h>
#include <string.h>

#include "stats.h"
#include "opts.h"


unsigned int stats_read_b, stats_read_k, stats_read_m, stats_read_g, stats_read_t;
unsigned int stats_written_b, stats_written_k, stats_written_m, stats_written_g, stats_written_t;


void stats_init() {
	stats_read_b = stats_read_k = stats_read_m = stats_read_g = stats_read_t = 0;
	stats_written_b = stats_written_k = stats_written_m = stats_written_g = stats_written_t = 0;
}

void stats_sprint(char *s) {
	strcpy(s, "");

	sprintf(s+strlen(s), "Bytes read: %u,%03u,%03u,%03u,%03u\n", stats_read_t, stats_read_g, stats_read_m, stats_read_k, stats_read_b);
	sprintf(s+strlen(s), "Bytes written: %u,%03u,%03u,%03u,%03u\n", stats_written_t, stats_written_g, stats_written_m, stats_written_k, stats_written_b);
}

void stats_add_read(unsigned int bytes) {
	stats_read_b += bytes;

	while (stats_read_b >= 1000) {
		stats_read_k++;
		stats_read_b -= 1000;
	}

	while (stats_read_k >= 1000) {
		stats_read_m++;
		stats_read_k -= 1000;
	}

	while (stats_read_m >= 1000) {
		stats_read_g++;
		stats_read_m -= 1000;
	}

	while (stats_read_g >= 1000) {
		stats_read_t++;
		stats_read_g -= 1000;
	}
}

void stats_add_written(unsigned int bytes) {
	stats_written_b += bytes;

	while (stats_written_b >= 1000) {
		stats_written_k++;
		stats_written_b -= 1000;
	}

	while (stats_written_k >= 1000) {
		stats_written_m++;
		stats_written_k -= 1000;
	}

	while (stats_written_m >= 1000) {
		stats_written_g++;
		stats_written_m -= 1000;
	}

	while (stats_written_g >= 1000) {
		stats_written_t++;
		stats_written_g -= 1000;
	}
}

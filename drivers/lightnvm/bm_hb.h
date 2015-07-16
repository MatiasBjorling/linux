/*
 * Copyright: Matias Bjorling <mb@lightnvm.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#ifndef BM_HB_H_
#define BM_HB_H_

#include <linux/module.h>
#include <linux/lightnvm.h>

struct bm_hb {
	struct nvm_lun *luns;
};

#define bm_for_each_lun(dev, bm, lun, i) \
		for ((i) = 0, lun = &(bm)->luns[0]; \
			(i) < (dev)->nr_luns; (i)++, lun = &(bm)->luns[(i)])

#endif /* BM_HB_H_ */

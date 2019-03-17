
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.0/sys/dev/drm2/radeon/r600_cp.h 338285 2018-08-24 00:02:00Z imp $");

#ifndef __R600_CP_H__
#define	__R600_CP_H__

void	r600_cs_legacy_get_tiling_conf(struct drm_device *dev,
	    u32 *npipes, u32 *nbanks, u32 *group_size);

int	r600_cs_legacy(struct drm_device *dev, void *data, struct drm_file *filp,
	    unsigned family, u32 *ib, int *l);
void	r600_cs_legacy_init(void);

#endif /* !defined(__R600_CP_H__) */

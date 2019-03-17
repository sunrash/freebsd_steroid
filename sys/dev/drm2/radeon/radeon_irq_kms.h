
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.0/sys/dev/drm2/radeon/radeon_irq_kms.h 338285 2018-08-24 00:02:00Z imp $");

#ifndef __RADEON_IRQ_KMS_H__
#define	__RADEON_IRQ_KMS_H__

irqreturn_t radeon_driver_irq_handler_kms(DRM_IRQ_ARGS);
void radeon_driver_irq_preinstall_kms(struct drm_device *dev);
int radeon_driver_irq_postinstall_kms(struct drm_device *dev);
void radeon_driver_irq_uninstall_kms(struct drm_device *dev);

#endif /* !defined(__RADEON_IRQ_KMS_H__) */

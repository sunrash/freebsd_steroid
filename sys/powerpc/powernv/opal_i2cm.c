/*-
 * Copyright (c) 2017-2018 QCM Technologies.
 * Copyright (c) 2017-2018 Semihalf.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: releng/12.0/sys/powerpc/powernv/opal_i2cm.c 330971 2018-03-15 06:19:45Z wma $
 */

#include "opt_platform.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.0/sys/powerpc/powernv/opal_i2cm.c 330971 2018-03-15 06:19:45Z wma $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <machine/bus.h>

#ifdef FDT
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

struct opal_i2cm_softc
{

};

static int opal_i2cm_attach(device_t);
static int opal_i2cm_probe(device_t);
static const struct ofw_bus_devinfo *
    opal_i2cm_get_devinfo(device_t, device_t);

static device_method_t opal_i2cm_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		opal_i2cm_probe),
	DEVMETHOD(device_attach,	opal_i2cm_attach),

	/* ofw_bus interface */
	DEVMETHOD(ofw_bus_get_devinfo,	opal_i2cm_get_devinfo),
	DEVMETHOD(ofw_bus_get_compat,	ofw_bus_gen_get_compat),
	DEVMETHOD(ofw_bus_get_model,	ofw_bus_gen_get_model),
	DEVMETHOD(ofw_bus_get_name,	ofw_bus_gen_get_name),
	DEVMETHOD(ofw_bus_get_node,	ofw_bus_gen_get_node),
	DEVMETHOD(ofw_bus_get_type,	ofw_bus_gen_get_type),

	DEVMETHOD_END
};

static devclass_t opal_i2cm_devclass;

static int
opal_i2cm_probe(device_t dev)
{

	if (!(ofw_bus_is_compatible(dev, "ibm,centaur-i2cm") ||
	    ofw_bus_is_compatible(dev, "ibm,power8-i2cm")))
		return (ENXIO);

	device_set_desc(dev, "centaur-i2cm");
	return (0);
}

static int
opal_i2cm_attach(device_t dev)
{
	phandle_t child;
	device_t cdev;
	struct ofw_bus_devinfo *dinfo;

	for (child = OF_child(ofw_bus_get_node(dev)); child != 0;
	    child = OF_peer(child)) {
		dinfo = malloc(sizeof(*dinfo), M_DEVBUF, M_WAITOK | M_ZERO);
		if (ofw_bus_gen_setup_devinfo(dinfo, child) != 0) {
			free(dinfo, M_DEVBUF);
			continue;
		}
		cdev = device_add_child(dev, NULL, -1);
		if (cdev == NULL) {
			device_printf(dev, "<%s>: device_add_child failed\n",
			    dinfo->obd_name);
			ofw_bus_gen_destroy_devinfo(dinfo);
			free(dinfo, M_DEVBUF);
			continue;
		}
		device_set_ivars(cdev, dinfo);
	}

	return (bus_generic_attach(dev));
}

static const struct ofw_bus_devinfo *
opal_i2cm_get_devinfo(device_t dev, device_t child)
{
        return (device_get_ivars(child));
}

DEFINE_CLASS_0(opal_i2cm, opal_i2cm_driver, opal_i2cm_methods,
    sizeof(struct opal_i2cm_softc));
DRIVER_MODULE(opal_i2cm, powernv_xscom, opal_i2cm_driver, opal_i2cm_devclass, NULL,
    NULL);
DRIVER_MODULE(opal_i2cm, powernv_centaur, opal_i2cm_driver, opal_i2cm_devclass, NULL,
    NULL);


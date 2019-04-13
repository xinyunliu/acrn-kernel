/*
 * Copyright(c) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *    Ke Yu
 *    Zhiyuan Lv <zhiyuan.lv@intel.com>
 *
 * Contributors:
 *    Terrence Xu <terrence.xu@intel.com>
 *    Changbin Du <changbin.du@intel.com>
 *    Bing Niu <bing.niu@intel.com>
 *    Zhi Wang <zhi.a.wang@intel.com>
 *
 */

#include "i915_drv.h"
#include "gvt.h"

static int get_edp_pipe(struct intel_vgpu *vgpu)
{
	u32 data = vgpu_vreg(vgpu, _TRANS_DDI_FUNC_CTL_EDP);
	int pipe = -1;

	switch (data & TRANS_DDI_EDP_INPUT_MASK) {
	case TRANS_DDI_EDP_INPUT_A_ON:
	case TRANS_DDI_EDP_INPUT_A_ONOFF:
		pipe = PIPE_A;
		break;
	case TRANS_DDI_EDP_INPUT_B_ONOFF:
		pipe = PIPE_B;
		break;
	case TRANS_DDI_EDP_INPUT_C_ONOFF:
		pipe = PIPE_C;
		break;
	}
	return pipe;
}

static int edp_pipe_is_enabled(struct intel_vgpu *vgpu)
{
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;

	if (!(vgpu_vreg_t(vgpu, PIPECONF(_PIPE_EDP)) & PIPECONF_ENABLE))
		return 0;

	if (!(vgpu_vreg(vgpu, _TRANS_DDI_FUNC_CTL_EDP) & TRANS_DDI_FUNC_ENABLE))
		return 0;
	return 1;
}

int pipe_is_enabled(struct intel_vgpu *vgpu, int pipe)
{
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;

	if (WARN_ON(pipe < PIPE_A || pipe >= INTEL_INFO(dev_priv)->num_pipes))
		return -EINVAL;

	if (vgpu_vreg_t(vgpu, PIPECONF(pipe)) & PIPECONF_ENABLE)
		return 1;

	if (edp_pipe_is_enabled(vgpu) &&
			get_edp_pipe(vgpu) == pipe)
		return 1;
	return 0;
}

static unsigned char virtual_dp_monitor_edid[GVT_EDID_NUM][EDID_SIZE] = {
	{
/* EDID with 1024x768 as its resolution */
		/*Header*/
		0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
		/* Vendor & Product Identification */
		0x22, 0xf0, 0x54, 0x29, 0x00, 0x00, 0x00, 0x00, 0x04, 0x17,
		/* Version & Revision */
		0x01, 0x04,
		/* Basic Display Parameters & Features */
		0xa5, 0x34, 0x20, 0x78, 0x23,
		/* Color Characteristics */
		0xfc, 0x81, 0xa4, 0x55, 0x4d, 0x9d, 0x25, 0x12, 0x50, 0x54,
		/* Established Timings: maximum resolution is 1024x768 */
		0x21, 0x08, 0x00,
		/* Standard Timings. All invalid */
		0x00, 0xc0, 0x00, 0xc0, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00,
		0x00, 0x40, 0x00, 0x00, 0x00, 0x01,
		/* 18 Byte Data Blocks 1: invalid */
		0x00, 0x00, 0x80, 0xa0, 0x70, 0xb0,
		0x23, 0x40, 0x30, 0x20, 0x36, 0x00, 0x06, 0x44, 0x21, 0x00, 0x00, 0x1a,
		/* 18 Byte Data Blocks 2: invalid */
		0x00, 0x00, 0x00, 0xfd, 0x00, 0x18, 0x3c, 0x18, 0x50, 0x11, 0x00, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		/* 18 Byte Data Blocks 3: invalid */
		0x00, 0x00, 0x00, 0xfc, 0x00, 0x48,
		0x50, 0x20, 0x5a, 0x52, 0x32, 0x34, 0x34, 0x30, 0x77, 0x0a, 0x20, 0x20,
		/* 18 Byte Data Blocks 4: invalid */
		0x00, 0x00, 0x00, 0xff, 0x00, 0x43, 0x4e, 0x34, 0x33, 0x30, 0x34, 0x30,
		0x44, 0x58, 0x51, 0x0a, 0x20, 0x20,
		/* Extension Block Count */
		0x00,
		/* Checksum */
		0xef,
	},
	{
/* EDID with 1920x1200 as its resolution */
		/*Header*/
		0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
		/* Vendor & Product Identification */
		0x22, 0xf0, 0x54, 0x29, 0x00, 0x00, 0x00, 0x00, 0x04, 0x17,
		/* Version & Revision */
		0x01, 0x04,
		/* Basic Display Parameters & Features */
		0xa5, 0x34, 0x20, 0x78, 0x23,
		/* Color Characteristics */
		0xfc, 0x81, 0xa4, 0x55, 0x4d, 0x9d, 0x25, 0x12, 0x50, 0x54,
		/* Established Timings: maximum resolution is 1024x768 */
		0x21, 0x08, 0x00,
		/*
		 * Standard Timings.
		 * below new resolutions can be supported:
		 * 1920x1080, 1280x720, 1280x960, 1280x1024,
		 * 1440x900, 1600x1200, 1680x1050
		 */
		0xd1, 0xc0, 0x81, 0xc0, 0x81, 0x40, 0x81, 0x80, 0x95, 0x00,
		0xa9, 0x40, 0xb3, 0x00, 0x01, 0x01,
		/* 18 Byte Data Blocks 1: max resolution is 1920x1200 */
		0x28, 0x3c, 0x80, 0xa0, 0x70, 0xb0,
		0x23, 0x40, 0x30, 0x20, 0x36, 0x00, 0x06, 0x44, 0x21, 0x00, 0x00, 0x1a,
		/* 18 Byte Data Blocks 2: invalid */
		0x00, 0x00, 0x00, 0xfd, 0x00, 0x18, 0x3c, 0x18, 0x50, 0x11, 0x00, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		/* 18 Byte Data Blocks 3: invalid */
		0x00, 0x00, 0x00, 0xfc, 0x00, 0x48,
		0x50, 0x20, 0x5a, 0x52, 0x32, 0x34, 0x34, 0x30, 0x77, 0x0a, 0x20, 0x20,
		/* 18 Byte Data Blocks 4: invalid */
		0x00, 0x00, 0x00, 0xff, 0x00, 0x43, 0x4e, 0x34, 0x33, 0x30, 0x34, 0x30,
		0x44, 0x58, 0x51, 0x0a, 0x20, 0x20,
		/* Extension Block Count */
		0x00,
		/* Checksum */
		0x45,
	},
};

#define DPCD_HEADER_SIZE        0xb

/* let the virtual display supports DP1.2 */
static u8 dpcd_fix_data[DPCD_HEADER_SIZE] = {
	0x12, 0x014, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void emulate_monitor_status_change(struct intel_vgpu *vgpu)
{
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;
	int pipe;

	if (IS_BROXTON(dev_priv)) {
		vgpu_vreg_t(vgpu, GEN8_DE_PORT_ISR) &= ~(BXT_DE_PORT_HP_DDIA |
			BXT_DE_PORT_HP_DDIB |
			BXT_DE_PORT_HP_DDIC);

		if (intel_vgpu_has_monitor_on_port(vgpu, PORT_A)) {
			vgpu_vreg_t(vgpu, GEN8_DE_PORT_ISR) |=
				BXT_DE_PORT_HP_DDIA;
		}

		if (intel_vgpu_has_monitor_on_port(vgpu, PORT_B)) {
			vgpu_vreg_t(vgpu, GEN8_DE_PORT_ISR) |=
				BXT_DE_PORT_HP_DDIB;
		}

		if (intel_vgpu_has_monitor_on_port(vgpu, PORT_C)) {
			vgpu_vreg_t(vgpu, GEN8_DE_PORT_ISR) |=
				BXT_DE_PORT_HP_DDIC;
		}

		vgpu_vreg_t(vgpu, SKL_FUSE_STATUS) |=
				SKL_FUSE_DOWNLOAD_STATUS |
				SKL_FUSE_PG_DIST_STATUS(SKL_PG0) |
				SKL_FUSE_PG_DIST_STATUS(SKL_PG1) |
				SKL_FUSE_PG_DIST_STATUS(SKL_PG2);

		return;
	}

	vgpu_vreg_t(vgpu, SDEISR) &= ~(SDE_PORTB_HOTPLUG_CPT |
			SDE_PORTC_HOTPLUG_CPT |
			SDE_PORTD_HOTPLUG_CPT);

	if (IS_SKYLAKE(dev_priv) || IS_KABYLAKE(dev_priv)) {
		vgpu_vreg_t(vgpu, SDEISR) &= ~(SDE_PORTA_HOTPLUG_SPT |
				SDE_PORTE_HOTPLUG_SPT);
		vgpu_vreg_t(vgpu, SKL_FUSE_STATUS) |=
				SKL_FUSE_DOWNLOAD_STATUS |
				SKL_FUSE_PG_DIST_STATUS(SKL_PG0) |
				SKL_FUSE_PG_DIST_STATUS(SKL_PG1) |
				SKL_FUSE_PG_DIST_STATUS(SKL_PG2);
		vgpu_vreg_t(vgpu, LCPLL1_CTL) |=
				LCPLL_PLL_ENABLE |
				LCPLL_PLL_LOCK;
		vgpu_vreg_t(vgpu, LCPLL2_CTL) |= LCPLL_PLL_ENABLE;

	}

	if (intel_vgpu_has_monitor_on_port(vgpu, PORT_B)) {
		vgpu_vreg_t(vgpu, SFUSE_STRAP) |= SFUSE_STRAP_DDIB_DETECTED;
		vgpu_vreg_t(vgpu, TRANS_DDI_FUNC_CTL(TRANSCODER_A)) &=
			~(TRANS_DDI_BPC_MASK | TRANS_DDI_MODE_SELECT_MASK |
			TRANS_DDI_PORT_MASK);
		vgpu_vreg_t(vgpu, TRANS_DDI_FUNC_CTL(TRANSCODER_A)) |=
			(TRANS_DDI_BPC_8 | TRANS_DDI_MODE_SELECT_DVI |
			(PORT_B << TRANS_DDI_PORT_SHIFT) |
			TRANS_DDI_FUNC_ENABLE);
		if (IS_BROADWELL(dev_priv)) {
			vgpu_vreg_t(vgpu, PORT_CLK_SEL(PORT_B)) &=
				~PORT_CLK_SEL_MASK;
			vgpu_vreg_t(vgpu, PORT_CLK_SEL(PORT_B)) |=
				PORT_CLK_SEL_LCPLL_810;
		}
		vgpu_vreg_t(vgpu, DDI_BUF_CTL(PORT_B)) &= ~DDI_BUF_CTL_ENABLE;
		vgpu_vreg_t(vgpu, DDI_BUF_CTL(PORT_B)) &= ~DDI_BUF_IS_IDLE;
		vgpu_vreg_t(vgpu, SDEISR) |= SDE_PORTB_HOTPLUG_CPT;
	}

	if (intel_vgpu_has_monitor_on_port(vgpu, PORT_C)) {
		vgpu_vreg_t(vgpu, SDEISR) |= SDE_PORTC_HOTPLUG_CPT;
		vgpu_vreg_t(vgpu, TRANS_DDI_FUNC_CTL(TRANSCODER_A)) &=
			~(TRANS_DDI_BPC_MASK | TRANS_DDI_MODE_SELECT_MASK |
			TRANS_DDI_PORT_MASK);
		vgpu_vreg_t(vgpu, TRANS_DDI_FUNC_CTL(TRANSCODER_A)) |=
			(TRANS_DDI_BPC_8 | TRANS_DDI_MODE_SELECT_DVI |
			(PORT_C << TRANS_DDI_PORT_SHIFT) |
			TRANS_DDI_FUNC_ENABLE);
		if (IS_BROADWELL(dev_priv)) {
			vgpu_vreg_t(vgpu, PORT_CLK_SEL(PORT_C)) &=
				~PORT_CLK_SEL_MASK;
			vgpu_vreg_t(vgpu, PORT_CLK_SEL(PORT_C)) |=
				PORT_CLK_SEL_LCPLL_810;
		}
		vgpu_vreg_t(vgpu, DDI_BUF_CTL(PORT_C)) &= ~DDI_BUF_CTL_ENABLE;
		vgpu_vreg_t(vgpu, DDI_BUF_CTL(PORT_C)) &= ~DDI_BUF_IS_IDLE;
		vgpu_vreg_t(vgpu, SFUSE_STRAP) |= SFUSE_STRAP_DDIC_DETECTED;
	}

	if (intel_vgpu_has_monitor_on_port(vgpu, PORT_D)) {
		vgpu_vreg_t(vgpu, SDEISR) |= SDE_PORTD_HOTPLUG_CPT;
		vgpu_vreg_t(vgpu, TRANS_DDI_FUNC_CTL(TRANSCODER_A)) &=
			~(TRANS_DDI_BPC_MASK | TRANS_DDI_MODE_SELECT_MASK |
			TRANS_DDI_PORT_MASK);
		vgpu_vreg_t(vgpu, TRANS_DDI_FUNC_CTL(TRANSCODER_A)) |=
			(TRANS_DDI_BPC_8 | TRANS_DDI_MODE_SELECT_DVI |
			(PORT_D << TRANS_DDI_PORT_SHIFT) |
			TRANS_DDI_FUNC_ENABLE);
		if (IS_BROADWELL(dev_priv)) {
			vgpu_vreg_t(vgpu, PORT_CLK_SEL(PORT_D)) &=
				~PORT_CLK_SEL_MASK;
			vgpu_vreg_t(vgpu, PORT_CLK_SEL(PORT_D)) |=
				PORT_CLK_SEL_LCPLL_810;
		}
		vgpu_vreg_t(vgpu, DDI_BUF_CTL(PORT_D)) &= ~DDI_BUF_CTL_ENABLE;
		vgpu_vreg_t(vgpu, DDI_BUF_CTL(PORT_D)) &= ~DDI_BUF_IS_IDLE;
		vgpu_vreg_t(vgpu, SFUSE_STRAP) |= SFUSE_STRAP_DDID_DETECTED;
	}

	if ((IS_SKYLAKE(dev_priv) || IS_KABYLAKE(dev_priv)) &&
			intel_vgpu_has_monitor_on_port(vgpu, PORT_E)) {
		vgpu_vreg_t(vgpu, SDEISR) |= SDE_PORTE_HOTPLUG_SPT;
	}

	if (intel_vgpu_has_monitor_on_port(vgpu, PORT_A)) {
		if (IS_BROADWELL(dev_priv))
			vgpu_vreg_t(vgpu, GEN8_DE_PORT_ISR) |=
				GEN8_PORT_DP_A_HOTPLUG;
		else
			vgpu_vreg_t(vgpu, SDEISR) |= SDE_PORTA_HOTPLUG_SPT;

		vgpu_vreg_t(vgpu, DDI_BUF_CTL(PORT_A)) |= DDI_INIT_DISPLAY_DETECTED;
	}

	/* Clear host CRT status, so guest couldn't detect this host CRT. */
	if (IS_BROADWELL(dev_priv))
		vgpu_vreg_t(vgpu, PCH_ADPA) &= ~ADPA_CRT_HOTPLUG_MONITOR_MASK;

	/* Disable Primary/Sprite/Cursor plane */
	for_each_pipe(dev_priv, pipe) {
		vgpu_vreg_t(vgpu, DSPCNTR(pipe)) &= ~DISPLAY_PLANE_ENABLE;
		vgpu_vreg_t(vgpu, SPRCTL(pipe)) &= ~SPRITE_ENABLE;
		vgpu_vreg_t(vgpu, CURCNTR(pipe)) &= ~MCURSOR_MODE;
		vgpu_vreg_t(vgpu, CURCNTR(pipe)) |= MCURSOR_MODE_DISABLE;
	}

	vgpu_vreg_t(vgpu, PIPECONF(PIPE_A)) |= PIPECONF_ENABLE;
}

static void clean_virtual_dp_monitor(struct intel_vgpu *vgpu, int port_num)
{
	struct intel_vgpu_port *port = intel_vgpu_port(vgpu, port_num);

	kfree(port->edid);
	port->edid = NULL;

	kfree(port->dpcd);
	port->dpcd = NULL;
}

static int setup_virtual_monitor(struct intel_vgpu *vgpu, int port_num,
		int type, unsigned int resolution, void *edid, bool is_dp)
{
	struct intel_vgpu_port *port = intel_vgpu_port(vgpu, port_num);
	int valid_extensions = 1;
	struct edid *tmp_edid = NULL;

	if (WARN_ON(resolution >= GVT_EDID_NUM))
		return -EINVAL;

	if (edid)
		valid_extensions += ((struct edid *)edid)->extensions;
	port->edid = kzalloc(sizeof(*(port->edid))
			+ valid_extensions * EDID_SIZE, GFP_KERNEL);
	if (!port->edid)
		return -ENOMEM;

	port->dpcd = kzalloc(sizeof(*(port->dpcd)), GFP_KERNEL);
	if (!port->dpcd) {
		kfree(port->edid);
		return -ENOMEM;
	}

	if (edid)
		memcpy(port->edid->edid_block, edid, EDID_SIZE * valid_extensions);
	else
		memcpy(port->edid->edid_block, virtual_dp_monitor_edid[resolution],
				EDID_SIZE);

	/* Sometimes the physical display will report the EDID with no
	 * digital bit set, which will cause the guest fail to enumerate
	 * the virtual HDMI monitor. So here we will set the digital
	 * bit and re-calculate the checksum.
	 */
	tmp_edid = ((struct edid *)port->edid->edid_block);
	if (!(tmp_edid->input & DRM_EDID_INPUT_DIGITAL)) {
		tmp_edid->input += DRM_EDID_INPUT_DIGITAL;
		tmp_edid->checksum -= DRM_EDID_INPUT_DIGITAL;
	}

	port->edid->data_valid = true;

	if (is_dp) {
		memcpy(port->dpcd->data, dpcd_fix_data, DPCD_HEADER_SIZE);
		port->dpcd->data_valid = true;
		port->dpcd->data[DPCD_SINK_COUNT] = 0x1;
	}
	port->type = type;

	emulate_monitor_status_change(vgpu);

	return 0;
}

/**
 * intel_gvt_check_vblank_emulation - check if vblank emulation timer should
 * be turned on/off when a virtual pipe is enabled/disabled.
 * @gvt: a GVT device
 *
 * This function is used to turn on/off vblank timer according to currently
 * enabled/disabled virtual pipes.
 *
 */
void intel_gvt_check_vblank_emulation(struct intel_gvt *gvt)
{
	struct intel_gvt_irq *irq = &gvt->irq;
	struct intel_vgpu *vgpu;
	int pipe, id;
	int found = false;

	mutex_lock(&gvt->lock);
	for_each_active_vgpu(gvt, vgpu, id) {
		for (pipe = 0; pipe < I915_MAX_PIPES; pipe++) {
			if (pipe_is_enabled(vgpu, pipe) == 1) {
				found = true;
				break;
			}
		}
		if (found)
			break;
	}

	/* all the pipes are disabled */
	if (!found)
		hrtimer_cancel(&irq->vblank_timer.timer);
	else
		hrtimer_start(&irq->vblank_timer.timer,
			ktime_add_ns(ktime_get(), irq->vblank_timer.period),
			HRTIMER_MODE_ABS);
	mutex_unlock(&gvt->lock);
}

static void emulate_vblank_on_pipe(struct intel_vgpu *vgpu, int pipe)
{
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;
	struct intel_vgpu_irq *irq = &vgpu->irq;
	int vblank_event[] = {
		[PIPE_A] = PIPE_A_VBLANK,
		[PIPE_B] = PIPE_B_VBLANK,
		[PIPE_C] = PIPE_C_VBLANK,
	};
	int event;

	if (pipe < PIPE_A || pipe >= INTEL_INFO(dev_priv)->num_pipes)
		return;

	for_each_set_bit(event, irq->flip_done_event[pipe],
			INTEL_GVT_EVENT_MAX) {
		clear_bit(event, irq->flip_done_event[pipe]);
		if (!pipe_is_enabled(vgpu, pipe))
			continue;

		vgpu_vreg_t(vgpu, PIPE_FLIPCOUNT_G4X(pipe))++;
		intel_vgpu_trigger_virtual_event(vgpu, event);
	}

	if (pipe_is_enabled(vgpu, pipe)==1) {
		vgpu_vreg_t(vgpu, PIPE_FRMCOUNT_G4X(pipe))++;
		intel_vgpu_trigger_virtual_event(vgpu, vblank_event[pipe]);
	}
}

static void emulate_vblank(struct intel_vgpu *vgpu)
{
	int pipe;

	mutex_lock(&vgpu->vgpu_lock);
	for_each_pipe(vgpu->gvt->dev_priv, pipe)
		emulate_vblank_on_pipe(vgpu, pipe);
	mutex_unlock(&vgpu->vgpu_lock);
}

/**
 * intel_gvt_emulate_vblank - trigger vblank events for vGPUs on GVT device
 * @gvt: a GVT device
 *
 * This function is used to trigger vblank interrupts for vGPUs on GVT device
 *
 */
void intel_gvt_emulate_vblank(struct intel_gvt *gvt)
{
	struct intel_vgpu *vgpu;
	int id;

	mutex_lock(&gvt->lock);
	for_each_active_vgpu(gvt, vgpu, id)
		emulate_vblank(vgpu);
	mutex_unlock(&gvt->lock);
}

static void intel_gvt_vblank_work(struct work_struct *w)
{
	struct intel_gvt_pipe_info *pipe_info = container_of(w,
			struct intel_gvt_pipe_info, vblank_work);
	struct intel_gvt *gvt = pipe_info->gvt;
	struct intel_vgpu *vgpu;
	int id;

	mutex_lock(&gvt->lock);
	for_each_active_vgpu(gvt, vgpu, id)
		emulate_vblank_on_pipe(vgpu, pipe_info->pipe_num);
	mutex_unlock(&gvt->lock);
}

#define BITS_PER_DOMAIN 4
#define MAX_SCALERS_PER_DOMAIN 2

#define DOMAIN_SCALER_OWNER(owner, pipe, scaler) \
	((((owner) >> (pipe) * BITS_PER_DOMAIN * MAX_SCALERS_PER_DOMAIN) >>  \
	BITS_PER_DOMAIN * (scaler)) & 0xf)

int bxt_check_planes(struct intel_vgpu *vgpu, int pipe)
{
	int plane = 0;
	bool ret = false;

	for (plane = 0;
	     plane < ((INTEL_INFO(vgpu->gvt->dev_priv)->num_sprites[pipe]) + 1);
	     plane++) {
		if (vgpu->gvt->pipe_info[pipe].plane_owner[plane] == vgpu->id) {
			ret = true;
			break;
		}
	}
	return ret;
}

void intel_gvt_init_pipe_info(struct intel_gvt *gvt)
{
	enum pipe pipe;
	unsigned int scaler;
	unsigned int domain_scaler_owner = i915_modparams.domain_scaler_owner;
	struct drm_i915_private *dev_priv = gvt->dev_priv;

	for (pipe = PIPE_A; pipe <= PIPE_C; pipe++) {
		gvt->pipe_info[pipe].pipe_num = pipe;
		gvt->pipe_info[pipe].gvt = gvt;
		INIT_WORK(&gvt->pipe_info[pipe].vblank_work,
				intel_gvt_vblank_work);
		/* Each nibble represents domain id
		 * ids can be from 0-F. 0 for Dom0, 1,2,3...0xF for DomUs
		 * scaler_owner[i] holds the id of the domain that owns it,
		 * eg:0,1,2 etc
		 */
		for_each_universal_scaler(dev_priv, pipe, scaler)
			gvt->pipe_info[pipe].scaler_owner[scaler] =
			DOMAIN_SCALER_OWNER(domain_scaler_owner, pipe, scaler);
	}
}

bool gvt_emulate_hdmi = false;

int setup_virtual_monitors(struct intel_vgpu *vgpu)
{
	struct intel_connector *connector = NULL;
	struct drm_connector_list_iter conn_iter;
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;
	int pipe = 0;
	int ret = 0;
	int type = gvt_emulate_hdmi ? GVT_HDMI_A : GVT_DP_A;
	int port = PORT_B;

	/* BXT have to use port A for HDMI to support 3 HDMI monitors */
	if (IS_BROXTON(dev_priv))
		port = PORT_A;

	drm_connector_list_iter_begin(&vgpu->gvt->dev_priv->drm, &conn_iter);
	for_each_intel_connector_iter(connector, &conn_iter) {
		if (connector->encoder->get_hw_state(connector->encoder, &pipe)
				&& connector->detect_edid) {
			/* if no planes are allocated for this pipe, skip it */
			if (i915_modparams.avail_planes_per_pipe &&
			    !bxt_check_planes(vgpu, pipe))
				continue;
			/* Get (Dom0) port associated with current pipe. */
			port = connector->encoder->port;
			ret = setup_virtual_monitor(vgpu, port,
				type, 0, connector->detect_edid,
				!gvt_emulate_hdmi);
			if (ret)
				return ret;
			type++;
			port++;
		}
	}
	drm_connector_list_iter_end(&conn_iter);
	return 0;
}

void clean_virtual_monitors(struct intel_vgpu *vgpu)
{
	int port = 0;

	for (port = PORT_A; port < I915_MAX_PORTS; port++) {
		struct intel_vgpu_port *p = intel_vgpu_port(vgpu, port);

		if (p->edid)
			clean_virtual_dp_monitor(vgpu, port);
	}
}

/**
 * intel_vgpu_clean_display - clean vGPU virtual display emulation
 * @vgpu: a vGPU
 *
 * This function is used to clean vGPU virtual display emulation stuffs
 *
 */
void intel_vgpu_clean_display(struct intel_vgpu *vgpu)
{
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;

	if (IS_BROXTON(dev_priv) || IS_KABYLAKE(dev_priv))
		clean_virtual_monitors(vgpu);
	else if (IS_SKYLAKE(dev_priv))
		clean_virtual_dp_monitor(vgpu, PORT_D);
	else
		clean_virtual_dp_monitor(vgpu, PORT_B);
}

/**
 * intel_vgpu_init_display- initialize vGPU virtual display emulation
 * @vgpu: a vGPU
 *
 * This function is used to initialize vGPU virtual display emulation stuffs
 *
 * Returns:
 * Zero on success, negative error code if failed.
 *
 */
int intel_vgpu_init_display(struct intel_vgpu *vgpu, u64 resolution)
{
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;

	intel_vgpu_init_i2c_edid(vgpu);

	if (IS_BROXTON(dev_priv) || IS_KABYLAKE(dev_priv))
		return setup_virtual_monitors(vgpu);
	else if (IS_SKYLAKE(dev_priv))
		return setup_virtual_monitor(vgpu, PORT_D, GVT_DP_D,
						resolution, NULL, true);
	else
		return setup_virtual_monitor(vgpu, PORT_B, GVT_DP_B,
						resolution, NULL, true);
}

/**
 * intel_vgpu_reset_display- reset vGPU virtual display emulation
 * @vgpu: a vGPU
 *
 * This function is used to reset vGPU virtual display emulation stuffs
 *
 */
void intel_vgpu_reset_display(struct intel_vgpu *vgpu)
{
	emulate_monitor_status_change(vgpu);
}



int skl_format_to_fourcc(int format, bool rgb_order, bool alpha);
uint_fixed_16_16_t
skl_wm_method1(const struct drm_i915_private *dev_priv, uint32_t pixel_rate,
	       uint8_t cpp, uint32_t latency, uint32_t dbuf_block_size);
uint_fixed_16_16_t
skl_wm_method2(uint32_t pixel_rate,
	       uint32_t pipe_htotal,
	       uint32_t latency,
	       uint_fixed_16_16_t plane_blocks_per_line);
uint_fixed_16_16_t intel_get_linetime_us(struct intel_crtc_state *cstate);


void skl_dump_cursor_ddb(struct drm_i915_private *dev_priv,
		struct skl_ddb_entry *entry, u32 reg)
{
	/* skl_ddb_entry_init_from_hw()

	  val = I915_READ(CUR_BUF_CFG(pipe));
	  skl_ddb_entry_init_from_hw(dev_priv,&ddb->plane[pipe][plane_id], val);
	*/

	u16 mask;

	if (INTEL_GEN(dev_priv) >= 11)
			mask = ICL_DDB_ENTRY_MASK;
	else
			mask = SKL_DDB_ENTRY_MASK;
	entry->start = reg & mask;
	entry->end = (reg >> DDB_ENTRY_END_SHIFT) & mask;

	if (entry->end)
			entry->end += 1;
}


void skl_dump_cursor_wm(uint32_t val, struct skl_wm_level *level)
{
/*	static inline void skl_wm_level_from_reg_val(uint32_t val,
							 struct skl_wm_level *level)

	if (plane_id != PLANE_CURSOR)
		val = I915_READ(PLANE_WM(pipe, plane_id, level));
	else
		val = I915_READ(CUR_WM(pipe, level));
	skl_wm_level_from_reg_val(val, &wm->wm[level]);

	if (plane_id != PLANE_CURSOR)
		val = I915_READ(PLANE_WM_TRANS(pipe, plane_id));
	else
		val = I915_READ(CUR_WM_TRANS(pipe));
	skl_wm_level_from_reg_val(val, &wm->trans_wm);

*/

    level->plane_en = val & PLANE_WM_EN;
	level->plane_res_b = val & PLANE_WM_BLOCKS_MASK;
	level->plane_res_l = (val >> PLANE_WM_LINES_SHIFT) & PLANE_WM_LINES_MASK;

}




void skl_debug_vgpu_watermark(struct intel_vgpu *vgpu, enum pipe pipe)
{
	struct intel_gvt *gvt = vgpu->gvt;
	struct drm_i915_private *dev_priv = gvt->dev_priv;

	u32 reg_val;
	struct skl_ddb_entry ddb_c1;
	struct skl_wm_level wm_vals[9];
	
	int i;

	reg_val = vgpu_vreg_t(vgpu, CUR_BUF_CFG(pipe));	
	skl_dump_cursor_ddb(dev_priv, &ddb_c1, reg_val);
	
	for(i=0; i<8; i++){
		reg_val = vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, i));	
		skl_dump_cursor_wm(reg_val, &wm_vals[i]);
	}

	reg_val = vgpu_vreg_t(vgpu, PLANE_WM_TRANS(pipe, PLANE_CURSOR));	
	skl_dump_cursor_wm(reg_val, &wm_vals[8]);

	DRM_DEBUG_DRIVER("dump watermark: pipe:%d plane:%d\n", pipe, PLANE_CURSOR);
	DRM_DEBUG_DRIVER("cursor ddb: start: %d  end: %d\n", ddb_c1.start, ddb_c1.end);
	DRM_DEBUG_DRIVER("cursor wm trans:  0x%x  enabled:%c\n", vgpu_vreg_t(vgpu, PLANE_WM_TRANS(pipe, PLANE_CURSOR)),
						wm_vals[8].plane_en?'Y':'N');

	
	DRM_DEBUG_DRIVER("cursor wm: [0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x]\n",
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, 0)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, 1)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, 2)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, 3)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, 4)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, 5)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, 6)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_CURSOR, 7)));

	DRM_DEBUG_DRIVER("Primary wm: [0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x]\n",
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_PRIMARY, 0)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_PRIMARY, 1)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_PRIMARY, 2)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_PRIMARY, 3)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_PRIMARY, 4)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_PRIMARY, 5)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_PRIMARY, 6)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_PRIMARY, 7)));	

	DRM_DEBUG_DRIVER("Sprite0 wm: [0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x]\n",
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE0, 0)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE0, 1)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE0, 2)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE0, 3)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE0, 4)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE0, 5)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE0, 6)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE0, 7)));	

	DRM_DEBUG_DRIVER("Sprite1 wm: [0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x]\n",
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE1, 0)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE1, 1)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE1, 2)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE1, 3)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE1, 4)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE1, 5)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE1, 6)),
		 vgpu_vreg_t(vgpu, PLANE_WM(pipe, PLANE_SPRITE1, 7)));		


	reg_val = I915_READ(PLANE_BUF_CFG(PIPE_A, 0));
	skl_dump_cursor_ddb(dev_priv, &ddb_c1, reg_val);
	DRM_DEBUG_DRIVER("1A  hw ddb: start: %d  end: %d\n", ddb_c1.start, ddb_c1.end);

	reg_val = I915_READ(PLANE_BUF_CFG(PIPE_B, 0));
	skl_dump_cursor_ddb(dev_priv, &ddb_c1, reg_val);
	DRM_DEBUG_DRIVER("1B  hw ddb: start: %d  end: %d\n", ddb_c1.start, ddb_c1.end);

	reg_val = I915_READ(CUR_BUF_CFG(PIPE_A));
	skl_dump_cursor_ddb(dev_priv, &ddb_c1, reg_val);
	DRM_DEBUG_DRIVER("CA  hw ddb: start: %d  end: %d\n", ddb_c1.start, ddb_c1.end);

	reg_val = I915_READ(PLANE_WM_TRANS(PIPE_A, PLANE_CURSOR));
	DRM_DEBUG_DRIVER("CA  hw wm trans:	0x%x  enabled:%c\n", reg_val, reg_val&PLANE_WM_EN ?'Y':'N');

	DRM_DEBUG_DRIVER("CA hw wm: [0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x]\n",
	 I915_READ(PLANE_WM(pipe, PLANE_CURSOR, 0)),
	 I915_READ(PLANE_WM(pipe, PLANE_CURSOR, 1)),
	 I915_READ(PLANE_WM(pipe, PLANE_CURSOR, 2)),
	 I915_READ(PLANE_WM(pipe, PLANE_CURSOR, 3)),
	 I915_READ(PLANE_WM(pipe, PLANE_CURSOR, 4)),
	 I915_READ(PLANE_WM(pipe, PLANE_CURSOR, 5)),
	 I915_READ(PLANE_WM(pipe, PLANE_CURSOR, 6)),
	 I915_READ(PLANE_WM(pipe, PLANE_CURSOR, 7)));


	reg_val = I915_READ(CUR_BUF_CFG(PIPE_B));
	skl_dump_cursor_ddb(dev_priv, &ddb_c1, reg_val);
	DRM_DEBUG_DRIVER("CA  hw ddb: start: %d  end: %d\n", ddb_c1.start, ddb_c1.end);

	reg_val = I915_READ(PLANE_WM_TRANS(PIPE_B, PLANE_CURSOR));
	DRM_DEBUG_DRIVER("CA  hw wm trans:	0x%x  enabled:%c\n", reg_val, reg_val&PLANE_WM_EN ?'Y':'N');

	DRM_DEBUG_DRIVER("CB hw wm: [0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x]\n",
	 I915_READ(PLANE_WM(PIPE_B, PLANE_CURSOR, 0)),
	 I915_READ(PLANE_WM(PIPE_B, PLANE_CURSOR, 1)),
	 I915_READ(PLANE_WM(PIPE_B, PLANE_CURSOR, 2)),
	 I915_READ(PLANE_WM(PIPE_B, PLANE_CURSOR, 3)),
	 I915_READ(PLANE_WM(PIPE_B, PLANE_CURSOR, 4)),
	 I915_READ(PLANE_WM(PIPE_B, PLANE_CURSOR, 5)),
	 I915_READ(PLANE_WM(PIPE_B, PLANE_CURSOR, 6)),
	 I915_READ(PLANE_WM(PIPE_B, PLANE_CURSOR, 7)));

}

int
vgpu_compute_plane_wm_params(struct intel_vgpu *vgpu,
			    struct intel_crtc_state *intel_cstate,
			    enum pipe pipe,
			    enum plane_id plane,
			    struct skl_wm_params *wp)
{
	struct intel_gvt *gvt = vgpu->gvt;
	struct drm_i915_private *dev_priv = gvt->dev_priv;
	struct intel_crtc *crtc = to_intel_crtc(intel_cstate->base.crtc);
	struct intel_plane *prim_plane = to_intel_plane(crtc->base.primary);
	struct intel_plane_state *prim_pstate = to_intel_plane_state(prim_plane->base.state);
	uint32_t interm_pbpl;
	u64 original_pixel_rate;
	uint_fixed_16_16_t downscale_amount;
	u32 pipe_src_w, pipe_src_h, src_w, src_h, dst_w, dst_h;
	uint_fixed_16_16_t fp_w_ratio, fp_h_ratio;
	uint_fixed_16_16_t downscale_h, downscale_w;
	bool apply_memory_bw_wa = IS_GEN9_BC(dev_priv) || IS_BROXTON(dev_priv);
	bool rot_90_or_270;
	int scaler, plane_scaler;
	u32 reg_val;

	if (!intel_cstate->base.active || !prim_pstate->base.visible)  {
		DRM_DEBUG_DRIVER("intel_cstate is not active\n");
		return 0;
	}

	//reg_val = vgpu_vreg_t(vgpu, PIPESRC(vgpu->transcoder)); //PIPESRC(crtc->pipe)
	reg_val = vgpu_vreg_t(vgpu, PIPESRC(pipe));
	pipe_src_w = ((reg_val >> 16) & 0xfff) + 1;
	pipe_src_h = (reg_val & 0xfff) + 1;
	original_pixel_rate = intel_cstate->pixel_rate;

	rot_90_or_270 = false;
	if (plane != PLANE_CURSOR)
		return -1;

	if (plane == PLANE_CURSOR) {
		reg_val = vgpu_vreg_t(vgpu, CURCNTR(pipe));
		switch (reg_val & SKL_CURSOR_MODE_MASK) {
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
		case 0x24:
		case 0x27:
			wp->width = 64;
			break;
		case 0x02:
		case 0x22:
		case 0x25:
			wp->width = 128;
			break;
		case 0x03:
		case 0x23:
		case 0x26:
			wp->width = 256;
			break;
		case 0:
			wp->width = 0;
			gvt_dbg_dpy("vgpu-%d: pipe(%d) HW cursor is disabled\n",
				    vgpu->id, pipe);
			return 0;
		default:
			wp->width = 0;
			gvt_dbg_dpy("vgpu-%d: pipe(%d) unsupported HW cursor mode %x\n",
				    vgpu->id, pipe, reg_val & SKL_CURSOR_MODE_MASK);
			return 0;
		}

		// Cursor is always linear
		wp->x_tiled = 0;
		wp->y_tiled = 0;
		wp->rc_surface = 0;

		switch (reg_val & SKL_CURSOR_MODE_MASK) {
		// 32bpp AND/INVERT
		case 0x02:
		case 0x03:
		case 0x07:
		// 32bpp ARGB
		case 0x22:
		case 0x23:
		case 0x27:
		// 32bpp AND/XOR
		case 0x24:
		case 0x25:
		case 0x26:
			wp->cpp = 4;
			break;
		// 2bpp 3/2/4 color
		case 0x04:
		case 0x05:
		case 0x06:
		default:
			wp->width = 0;
			wp->cpp = 0;
			gvt_dbg_dpy("vgpu-%d: pipe(%d) unsupported HW cursor format %x\n",
				    vgpu->id, pipe, reg_val & SKL_CURSOR_MODE_MASK);
			return 0;
		}
	} else {
		return -1;
	}

	if (plane == PLANE_CURSOR) {
		src_w = wp->width;
		src_h = wp->width;
	} else {
		return 0;
	}

	// Assume host scaler has been rebuilt for vgpu
	plane_scaler = -1;

	for (scaler = 0; scaler < crtc->num_scalers; scaler++) {
		reg_val = vgpu_vreg_t(vgpu, SKL_PS_CTRL(pipe, scaler));

		if (reg_val & PS_SCALER_EN &&
		    (reg_val & PS_PLANE_SEL(plane) ||
		    !(reg_val & PS_PLANE_SEL_MASK))) {

			DRM_DEBUG_DRIVER("Pipe has enabled scaler: %d\n", scaler);
			plane_scaler = scaler;
			break;
		}
	}

	plane_scaler = -1;

	if (plane_scaler >= 0) {
		//reg_val = vgpu->ps_conf[vgpu_pipe].win_size[scaler];
		// find the enabled scaler for the pipe
		// get the scaler size
		reg_val = vgpu_vreg_t(vgpu, SKL_PS_CTRL(pipe, scaler));
		reg_val = vgpu_vreg_t(vgpu, SKL_PS_WIN_SZ(pipe, scaler));
		dst_w = reg_val >> 16 & 0xfff;
		dst_h = reg_val & 0xfff;
	} else {
		dst_w = prim_pstate->base.crtc_w;
		dst_h = prim_pstate->base.crtc_h;
	}

	fp_w_ratio = div_fixed16(src_w, dst_w);
	fp_h_ratio = div_fixed16(src_h, dst_h);
	downscale_w = max_fixed16(fp_w_ratio, u32_to_fixed16(1));
	downscale_h = max_fixed16(fp_h_ratio, u32_to_fixed16(1));
	downscale_amount = mul_fixed16(downscale_w, downscale_h);

	wp->plane_pixel_rate = mul_round_up_u32_fixed16(original_pixel_rate,
						    downscale_amount);

	DRM_DEBUG_DRIVER("vgpu-%d: pipe(%d), plane(%d), plane_ctl(%08x), scaler-%d, pipe src(%dx%d) src(%dx%d)->dst(%dx%d), pixel rate(%lld->%d)\n",
		    vgpu->id, pipe, plane,
		    (plane == PLANE_CURSOR) ? vgpu_vreg_t(vgpu, CURCNTR(pipe)) : vgpu_vreg_t(vgpu, PLANE_CTL(pipe, plane)),
		    plane_scaler, pipe_src_w, pipe_src_h,
		    src_w, src_h, dst_w, dst_h, original_pixel_rate, wp->plane_pixel_rate);

	reg_val = vgpu_vreg_t(vgpu, PLANE_CTL(pipe, plane));
	if (INTEL_GEN(dev_priv) >= 11 &&
	    plane != PLANE_CURSOR &&
	    !(reg_val & PLANE_CTL_DECOMPRESSION_ENABLE) &&
	    (reg_val & PLANE_CTL_TILED_YF) &&
	    wp->cpp == 8)
		wp->dbuf_block_size = 256;
	else
		wp->dbuf_block_size = 512;

	if (rot_90_or_270) {
		switch (wp->cpp) {
		case 1:
			wp->y_min_scanlines = 16;
			break;
		case 2:
			wp->y_min_scanlines = 8;
			break;
		case 4:
			wp->y_min_scanlines = 4;
			break;
		default:
			MISSING_CASE(wp->cpp);
			return -EINVAL;
		}
	} else {
		wp->y_min_scanlines = 4;
	}

	if (apply_memory_bw_wa)
		wp->y_min_scanlines *= 2;

	wp->plane_bytes_per_line = wp->width * wp->cpp;
	if (wp->y_tiled) {
		interm_pbpl = DIV_ROUND_UP(wp->plane_bytes_per_line *
					   wp->y_min_scanlines,
					   wp->dbuf_block_size);

		if (INTEL_GEN(dev_priv) >= 10)
			interm_pbpl++;

		wp->plane_blocks_per_line = div_fixed16(interm_pbpl,
							wp->y_min_scanlines);
	} else if (wp->x_tiled && IS_GEN9(dev_priv)) {
		interm_pbpl = DIV_ROUND_UP(wp->plane_bytes_per_line,
					   wp->dbuf_block_size);
		wp->plane_blocks_per_line = u32_to_fixed16(interm_pbpl);
	} else {
		interm_pbpl = DIV_ROUND_UP(wp->plane_bytes_per_line,
					   wp->dbuf_block_size) + 1;
		wp->plane_blocks_per_line = u32_to_fixed16(interm_pbpl);
	}

	wp->y_tile_minimum = mul_u32_fixed16(wp->y_min_scanlines,
					     wp->plane_blocks_per_line);
	wp->linetime_us = fixed16_to_u32_round_up(
					intel_get_linetime_us(intel_cstate));

	DRM_DEBUG_DRIVER("vgpu-%d: pipe(%d), plane(%d), x_tiled(%d), y_tiled(%d), rc_surface(%d), width(%x), cpp(%x), "
		    "plane_pixel_rate(%d), y_min_scanlines(%x), plane_bytes_per_line(%x), plane_blocks_per_line(%x), "
		    "y_tile_minimum(%x), linetime_us(%x), dbuf_block_size(%x)\n",
		    vgpu->id, pipe, plane, wp->x_tiled, wp->y_tiled, wp->rc_surface, wp->width, wp->cpp,
		    wp->plane_pixel_rate, wp->y_min_scanlines, wp->plane_bytes_per_line, wp->plane_blocks_per_line.val,
		    wp->y_tile_minimum.val, wp->linetime_us, wp->dbuf_block_size);

	return 0;
}
void intel_vgpu_update_plane_wm(struct intel_vgpu *vgpu,
		struct intel_crtc *intel_crtc, enum pipe pipe, enum plane_id plane)
{
	struct intel_gvt *gvt = vgpu->gvt;
	struct drm_i915_private *dev_priv = gvt->dev_priv;
	struct intel_crtc_state *intel_cstate = to_intel_crtc_state(intel_crtc->base.state);
	struct drm_atomic_state *drm_state = intel_cstate->base.state;
	struct intel_atomic_state *intel_state = to_intel_atomic_state(drm_state);

	struct skl_plane_wm *wm;
	struct skl_wm_params wm_params;


	struct skl_ddb_allocation *ddb_sw = &intel_state->wm_results.ddb;
	struct skl_ddb_allocation *ddb_hw = &dev_priv->wm.skl_hw.ddb;

	/* PIPE_A, PLANE_CURSOR */

	u16 ddb_blocks;
	int level, max_level = ilk_wm_max_level(dev_priv);

	int ret;

	if (!intel_crtc) {
		return;
	}

/*
	DRM_DEBUG_DRIVER("[xy] ddb_sw: [%d, %d)\n", ddb_sw->plane[PIPE_A][PLANE_CURSOR].start,
		ddb_sw->plane[PIPE_A][PLANE_CURSOR].end);
	DRM_DEBUG_DRIVER("[xy] ddb_hw: [%d, %d)\n", ddb_hw->plane[PIPE_A][PLANE_CURSOR].start,
		ddb_hw->plane[PIPE_A][PLANE_CURSOR].end);
*/
	DRM_DEBUG_DRIVER("[xy] pipe: %d plane: %d\n", pipe, plane);
	skl_debug_vgpu_watermark(vgpu, pipe);

	vgpu_compute_plane_wm_params(vgpu, intel_cstate, pipe, plane, &wm_params);


	//ddb_blocks = skl_ddb_entry_size(&ddb_sw->plane[pipe][plane]);
/*
	for (level = 0; level <= max_level; level++) {
		ret = vgpu_compute_plane_wm(vgpu,
					    intel_cstate,
					    plane,
					    ddb_blocks,
					    level,
					    &wm_params,
					    &wm->wm[level].plane_res_b,
					    &wm->wm[level].plane_res_l,
					    &wm->wm[level].plane_en);
		gvt_dbg_dpy("vgpu-%d: pipe(%d->%d), plane(%d), level(%d), wm(%x)\n",
			    vgpu->id, vgpu_pipe, host_pipe, plane, level,
			    vgpu_calc_wm_level(&wm->wm[level]));
		if (ret)
			break;
	}
*/

/*
	wm = &vgpu->wm[vgpu_pipe].planes[plane];
	ddb_blocks = skl_ddb_entry_size(&ddb_sw->plane[host_pipe][plane]);
	memset(&wm_params, 0, sizeof(struct skl_wm_params));
	ret = vgpu_compute_plane_wm_params(vgpu, intel_cstate,
						  plane, &wm_params);

	for (level = 0; level <= max_level; level++) {
		ret = vgpu_compute_plane_wm(vgpu,
					    intel_cstate,
					    plane,
					    ddb_blocks,
					    level,
					    &wm_params,
					    &wm->wm[level].plane_res_b,
					    &wm->wm[level].plane_res_l,
					    &wm->wm[level].plane_en);
		gvt_dbg_dpy("vgpu-%d: pipe(%d->%d), plane(%d), level(%d), wm(%x)\n",
			    vgpu->id, vgpu_pipe, host_pipe, plane, level,
			    vgpu_calc_wm_level(&wm->wm[level]));
		if (ret)
			break;
	}

	skl_compute_transition_wm(intel_cstate, &wm_params,
		&wm->wm[0], ddb_blocks, &wm->trans_wm);
	gvt_dbg_dpy("vgpu-%d: pipe(%d->%d), plane(%d), wm_trans(%x)\n",
		    vgpu->id, vgpu_pipe, host_pipe, plane,
		    vgpu_calc_wm_level(&wm->trans_wm));
*/

}

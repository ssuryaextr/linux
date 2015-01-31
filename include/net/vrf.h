#ifndef _VRF_H_
#define _VRF_H_

#define VRF_BITS	12
#define VRF_MIN		1
#define VRF_MAX		((1 << VRF_BITS) - 1)
#define VRF_MASK	VRF_MAX

#define VRF_DEFAULT	1
#define VRF_ANY		0xffff

static inline
int vrf_eq(__u32 vrf1, __u32 vrf2)
{
	return vrf1 == vrf2;
}

static inline
int vrf_eq_or_any(__u32 vrf1, __u32 vrf2)
{
	return vrf1 == vrf2 || vrf1 == VRF_ANY || vrf2 == VRF_ANY;
}

static inline int vrf_is_valid(__u32 vrf)
{
	if ((vrf < VRF_MIN || vrf > VRF_MAX) && vrf != VRF_ANY)
		return 0;

	return 1;
}

static inline int vrf_is_any(__u32 vrf)
{
	return vrf == VRF_ANY;
}
#endif

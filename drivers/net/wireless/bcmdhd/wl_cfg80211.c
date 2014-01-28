/*
 * Linux cfg80211 driver
 *
 * Copyright (C) 1999-2011, Broadcom Corporation
 *
 *         Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 * 
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 * $Id: wl_cfg80211.c,v 1.1.4.1.2.14 2011/02/09 01:40:07 Exp $
 */

#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>
#include <linux/kernel.h>

#include <bcmutils.h>
#include <bcmwifi.h>
#include <bcmendian.h>
#include <proto/ethernet.h>
#include <proto/802.11.h>
#include <linux/if_arp.h>
#include <asm/uaccess.h>

#include <dngl_stats.h>
#include <dhd.h>
#include <dhdioctl.h>
#include <wlioctl.h>

#include <proto/ethernet.h>
#include <dngl_stats.h>
#include <dhd.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/wait.h>
#include <net/cfg80211.h>

#include <net/rtnetlink.h>
#include <linux/mmc/sdio_func.h>
#include <linux/firmware.h>
#include <bcmsdbus.h>

#include <wlioctl.h>
#include <wldev_common.h>
#include <wl_cfg80211.h>
#include <wl_cfgp2p.h>

static struct sdio_func *cfg80211_sdio_func;
static struct wl_priv *wlcfg_drv_priv;

u32 wl_dbg_level = WL_DBG_ERR;

#define WL_4329_FW_FILE "brcm/bcm4329-fullmac-4-218-248-5.bin"
#define WL_4329_NVRAM_FILE "brcm/bcm4329-fullmac-4-218-248-5.txt"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAX_WAIT_TIME 1500
static s8 ioctlbuf[WLC_IOCTL_MAXLEN];

#define COEX_DHCP

#if defined(COEX_DHCP)
#define BT_DHCP_eSCO_FIX		/* use New SCO/eSCO smart YG
					 * suppression
					 */
#define BT_DHCP_USE_FLAGS		/* this flag boost wifi pkt priority
					 * to max, caution: -not fair to sco
					 */
#define BT_DHCP_OPPR_WIN_TIME	2500	/* T1 start SCO/ESCo priority
					 * suppression
					 */
#define BT_DHCP_FLAG_FORCE_TIME 5500	/* T2 turn off SCO/SCO supperesion
					 * is (timeout)
					 */
enum wl_cfg80211_btcoex_status {
	BT_DHCP_IDLE,
	BT_DHCP_START,
	BT_DHCP_OPPR_WIN,
	BT_DHCP_FLAG_FORCE_TIMEOUT
};

static int wl_cfg80211_btcoex_init(struct wl_priv *wl);
static void wl_cfg80211_btcoex_deinit(struct wl_priv *wl);
#endif

/* This is to override regulatory domains defined in cfg80211 module (reg.c)
 * By default world regulatory domain defined in reg.c puts the flags NL80211_RRF_PASSIVE_SCAN
 * and NL80211_RRF_NO_IBSS for 5GHz channels (for 36..48 and 149..165).
 * With respect to these flags, wpa_supplicant doesn't start p2p operations on 5GHz channels.
 * All the chnages in world regulatory domain are to be done here.
 */
static const struct ieee80211_regdomain brcm_regdom = {
	.n_reg_rules = 5,
	.alpha2 =  "99",
	.reg_rules = {
		/* IEEE 802.11b/g, channels 1..11 */
		REG_RULE(2412-10, 2462+10, 40, 6, 20, 0),
		/* IEEE 802.11b/g, channels 12..13. No HT40
		 * channel fits here.
		 */
		REG_RULE(2467-10, 2472+10, 20, 6, 20,
		NL80211_RRF_PASSIVE_SCAN |
		NL80211_RRF_NO_IBSS),
		/* IEEE 802.11 channel 14 - Only JP enables
		 * this and for 802.11b only
		 */
		REG_RULE(2484-10, 2484+10, 20, 6, 20,
		NL80211_RRF_PASSIVE_SCAN |
		NL80211_RRF_NO_IBSS |
		NL80211_RRF_NO_OFDM),
		/* IEEE 802.11a, channel 36..64 */
		REG_RULE(5150-10, 5350+10, 40, 6, 20, 0),
		/* IEEE 802.11a, channel 100..165 */
		REG_RULE(5470-10, 5850+10, 40, 6, 20, 0), }
};


/* Data Element Definitions */
#define WPS_ID_CONFIG_METHODS     0x1008
#define WPS_ID_REQ_TYPE           0x103A
#define WPS_ID_DEVICE_NAME        0x1011
#define WPS_ID_VERSION            0x104A
#define WPS_ID_DEVICE_PWD_ID      0x1012
#define WPS_ID_REQ_DEV_TYPE       0x106A
#define WPS_ID_SELECTED_REGISTRAR_CONFIG_METHODS 0x1053
#define WPS_ID_PRIM_DEV_TYPE      0x1054

/* Device Password ID */
#define DEV_PW_DEFAULT 0x0000
#define DEV_PW_USER_SPECIFIED 0x0001,
#define DEV_PW_MACHINE_SPECIFIED 0x0002
#define DEV_PW_REKEY 0x0003
#define DEV_PW_PUSHBUTTON 0x0004
#define DEV_PW_REGISTRAR_SPECIFIED 0x0005

/* Config Methods */
#define WPS_CONFIG_USBA 0x0001
#define WPS_CONFIG_ETHERNET 0x0002
#define WPS_CONFIG_LABEL 0x0004
#define WPS_CONFIG_DISPLAY 0x0008
#define WPS_CONFIG_EXT_NFC_TOKEN 0x0010
#define WPS_CONFIG_INT_NFC_TOKEN 0x0020
#define WPS_CONFIG_NFC_INTERFACE 0x0040
#define WPS_CONFIG_PUSHBUTTON 0x0080
#define WPS_CONFIG_KEYPAD 0x0100
#define WPS_CONFIG_VIRT_PUSHBUTTON 0x0280
#define WPS_CONFIG_PHY_PUSHBUTTON 0x0480
#define WPS_CONFIG_VIRT_DISPLAY 0x2008
#define WPS_CONFIG_PHY_DISPLAY 0x4008

/*
 * cfg80211_ops api/callback list
 */
static s32 wl_frame_get_mgmt(u16 fc, const struct ether_addr *da,
	const struct ether_addr *sa, const struct ether_addr *bssid,
	u8 **pheader, u32 *body_len, u8 *pbody);
static s32 __wl_cfg80211_scan(struct wiphy *wiphy, struct net_device *ndev,
	struct cfg80211_scan_request *request,
	struct cfg80211_ssid *this_ssid);
static s32 wl_cfg80211_scan(struct wiphy *wiphy, struct net_device *ndev,
	struct cfg80211_scan_request *request);
static s32 wl_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed);
static s32 wl_cfg80211_join_ibss(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_ibss_params *params);
static s32 wl_cfg80211_leave_ibss(struct wiphy *wiphy,
	struct net_device *dev);
static s32 wl_cfg80211_get_station(struct wiphy *wiphy,
	struct net_device *dev, u8 *mac,
	struct station_info *sinfo);
static s32 wl_cfg80211_set_power_mgmt(struct wiphy *wiphy,
	struct net_device *dev, bool enabled,
	s32 timeout);
static int wl_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev,
	u16 reason_code);
static s32 wl_cfg80211_set_tx_power(struct wiphy *wiphy,
	enum nl80211_tx_power_setting type,
	s32 dbm);
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, s32 *dbm);
static s32 wl_cfg80211_config_default_key(struct wiphy *wiphy,
	struct net_device *dev,
	u8 key_idx, bool unicast, bool multicast);
static s32 wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr,
	struct key_params *params);
static s32 wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr);
static s32 wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr,
	void *cookie, void (*callback) (void *cookie,
	struct key_params *params));
static s32 wl_cfg80211_config_default_mgmt_key(struct wiphy *wiphy,
	struct net_device *dev,	u8 key_idx);
static s32 wl_cfg80211_resume(struct wiphy *wiphy);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39)
static s32 wl_cfg80211_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wow);
#else
static s32 wl_cfg80211_suspend(struct wiphy *wiphy);
#endif
static s32 wl_cfg80211_set_pmksa(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_pmksa *pmksa);
static s32 wl_cfg80211_del_pmksa(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_pmksa *pmksa);
static s32 wl_cfg80211_flush_pmksa(struct wiphy *wiphy,
	struct net_device *dev);
static void wl_notify_escan_complete(struct wl_priv *wl, bool aborted);
/*
 * event & event Q handlers for cfg80211 interfaces
 */
static s32 wl_create_event_handler(struct wl_priv *wl);
static void wl_destroy_event_handler(struct wl_priv *wl);
static s32 wl_event_handler(void *data);
static void wl_init_eq(struct wl_priv *wl);
static void wl_flush_eq(struct wl_priv *wl);
static unsigned long wl_lock_eq(struct wl_priv *wl);
static void wl_unlock_eq(struct wl_priv *wl, unsigned long flags);
static void wl_init_eq_lock(struct wl_priv *wl);
static void wl_init_event_handler(struct wl_priv *wl);
static struct wl_event_q *wl_deq_event(struct wl_priv *wl);
static s32 wl_enq_event(struct wl_priv *wl, struct net_device *ndev, u32 type,
	const wl_event_msg_t *msg, void *data);
static void wl_put_event(struct wl_event_q *e);
static void wl_wakeup_event(struct wl_priv *wl);
static s32 wl_notify_connect_status(struct wl_priv *wl,
	struct net_device *ndev,
	const wl_event_msg_t *e, void *data);
static s32 wl_notify_roaming_status(struct wl_priv *wl,
	struct net_device *ndev,
	const wl_event_msg_t *e, void *data);
static s32 wl_notify_scan_status(struct wl_priv *wl, struct net_device *ndev,
	const wl_event_msg_t *e, void *data);
static s32 wl_bss_connect_done(struct wl_priv *wl, struct net_device *ndev,
	const wl_event_msg_t *e, void *data, bool completed);
static s32 wl_bss_roaming_done(struct wl_priv *wl, struct net_device *ndev,
	const wl_event_msg_t *e, void *data);
static s32 wl_notify_mic_status(struct wl_priv *wl, struct net_device *ndev,
	const wl_event_msg_t *e, void *data);
/*
 * register/deregister sdio function
 */
struct sdio_func *wl_cfg80211_get_sdio_func(void);
static void wl_clear_sdio_func(void);

/*
 * ioctl utilites
 */
static s32 wl_dev_bufvar_get(struct net_device *dev, s8 *name, s8 *buf,
	s32 buf_len);
static __used s32 wl_dev_bufvar_set(struct net_device *dev, s8 *name,
	s8 *buf, s32 len);
static s32 wl_dev_intvar_set(struct net_device *dev, s8 *name, s32 val);
static s32 wl_dev_intvar_get(struct net_device *dev, s8 *name,
	s32 *retval);

/*
 * cfg80211 set_wiphy_params utilities
 */
static s32 wl_set_frag(struct net_device *dev, u32 frag_threshold);
static s32 wl_set_rts(struct net_device *dev, u32 frag_threshold);
static s32 wl_set_retry(struct net_device *dev, u32 retry, bool l);

/*
 * wl profile utilities
 */
static s32 wl_update_prof(struct wl_priv *wl, const wl_event_msg_t *e,
	void *data, s32 item);
static void *wl_read_prof(struct wl_priv *wl, s32 item);
static void wl_init_prof(struct wl_priv *wl);

/*
 * cfg80211 connect utilites
 */
static s32 wl_set_wpa_version(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_set_auth_type(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_set_set_cipher(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_set_key_mgmt(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_set_set_sharedkey(struct net_device *dev,
	struct cfg80211_connect_params *sme);
static s32 wl_get_assoc_ies(struct wl_priv *wl, struct net_device *ndev);
static void wl_ch_to_chanspec(int ch,
	struct wl_join_params *join_params, size_t *join_params_size);

/*
 * information element utilities
 */
static void wl_rst_ie(struct wl_priv *wl);
static __used s32 wl_add_ie(struct wl_priv *wl, u8 t, u8 l, u8 *v);
static s32 wl_mrg_ie(struct wl_priv *wl, u8 *ie_stream, u16 ie_size);
static s32 wl_cp_ie(struct wl_priv *wl, u8 *dst, u16 dst_size);
static u32 wl_get_ielen(struct wl_priv *wl);

static s32 wl_mode_to_nl80211_iftype(s32 mode);

static struct wireless_dev *wl_alloc_wdev(struct device *sdiofunc_dev);
static void wl_free_wdev(struct wl_priv *wl);

static s32 wl_inform_bss(struct wl_priv *wl);
static s32 wl_inform_single_bss(struct wl_priv *wl, struct wl_bss_info *bi);
static s32 wl_update_bss_info(struct wl_priv *wl, struct net_device *ndev);

static s32 wl_add_keyext(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, const u8 *mac_addr,
	struct key_params *params);
/*
 * key indianess swap utilities
 */
static void swap_key_from_BE(struct wl_wsec_key *key);
static void swap_key_to_BE(struct wl_wsec_key *key);

/*
 * wl_priv memory init/deinit utilities
 */
static s32 wl_init_priv_mem(struct wl_priv *wl);
static void wl_deinit_priv_mem(struct wl_priv *wl);

static void wl_delay(u32 ms);

/*
 * ibss mode utilities
 */
static bool wl_is_ibssmode(struct wl_priv *wl, struct net_device *ndev);
static __used bool wl_is_ibssstarter(struct wl_priv *wl);

/*
 * dongle up/down , default configuration utilities
 */
static bool wl_is_linkdown(struct wl_priv *wl, const wl_event_msg_t *e);
static bool wl_is_linkup(struct wl_priv *wl, const wl_event_msg_t *e, struct net_device *ndev);
static bool wl_is_nonetwork(struct wl_priv *wl, const wl_event_msg_t *e);
static void wl_link_up(struct wl_priv *wl);
static void wl_link_down(struct wl_priv *wl);
static s32 wl_dongle_mode(struct wl_priv *wl, struct net_device *ndev, s32 iftype);
static s32 __wl_cfg80211_up(struct wl_priv *wl);
static s32 __wl_cfg80211_down(struct wl_priv *wl);
static s32 wl_dongle_probecap(struct wl_priv *wl);
static void wl_init_conf(struct wl_conf *conf);
static s32 wl_dongle_add_remove_eventmsg(struct net_device *ndev, u16 event, bool add);

/*
 * dongle configuration utilities
 */
#ifndef EMBEDDED_PLATFORM
static s32 wl_dongle_country(struct net_device *ndev, u8 ccode);
static s32 wl_dongle_up(struct net_device *ndev, u32 up);
static s32 wl_dongle_power(struct net_device *ndev, u32 power_mode);
static s32 wl_dongle_glom(struct net_device *ndev, u32 glom,
	u32 dongle_align);
static s32 wl_dongle_roam(struct net_device *ndev, u32 roamvar,
	u32 bcn_timeout);
static s32 wl_dongle_scantime(struct net_device *ndev, s32 scan_assoc_time,
	s32 scan_unassoc_time);
static s32 wl_dongle_offload(struct net_device *ndev, s32 arpoe,
	s32 arp_ol);
static s32 wl_pattern_atoh(s8 *src, s8 *dst);
static s32 wl_dongle_filter(struct net_device *ndev, u32 filter_mode);
static s32 wl_update_wiphybands(struct wl_priv *wl);
#endif				/* !EMBEDDED_PLATFORM */
static __used void wl_dongle_poweron(struct wl_priv *wl);
static __used void wl_dongle_poweroff(struct wl_priv *wl);
static s32 wl_config_dongle(struct wl_priv *wl, bool need_lock);

/*
 * iscan handler
 */
static void wl_iscan_timer(unsigned long data);
static void wl_term_iscan(struct wl_priv *wl);
static s32 wl_init_scan(struct wl_priv *wl);
static s32 wl_iscan_thread(void *data);
static s32 wl_run_iscan(struct wl_iscan_ctrl *iscan, struct cfg80211_scan_request *request,
	u16 action);
static s32 wl_do_iscan(struct wl_priv *wl,  struct cfg80211_scan_request *request);
static s32 wl_wakeup_iscan(struct wl_iscan_ctrl *iscan);
static s32 wl_invoke_iscan(struct wl_priv *wl);
static s32 wl_get_iscan_results(struct wl_iscan_ctrl *iscan, u32 *status,
	struct wl_scan_results **bss_list);
static void wl_notify_iscan_complete(struct wl_iscan_ctrl *iscan, bool aborted);
static void wl_init_iscan_handler(struct wl_iscan_ctrl *iscan);
static s32 wl_iscan_done(struct wl_priv *wl);
static s32 wl_iscan_pending(struct wl_priv *wl);
static s32 wl_iscan_inprogress(struct wl_priv *wl);
static s32 wl_iscan_aborted(struct wl_priv *wl);

/*
 * fw/nvram downloading handler
 */
static void wl_init_fw(struct wl_fw_ctrl *fw);

/*
 * find most significant bit set
 */
static __used u32 wl_find_msb(u16 bit16);

/*
 * update pmklist to dongle
 */
static __used s32 wl_update_pmklist(struct net_device *dev,
	struct wl_pmk_list *pmk_list, s32 err);

/*
 * debufs support
 */
static int wl_debugfs_add_netdev_params(struct wl_priv *wl);
static void wl_debugfs_remove_netdev(struct wl_priv *wl);

/*
 * rfkill support
 */
static int wl_setup_rfkill(struct wl_priv *wl, bool setup);
static int wl_rfkill_set(void *data, bool blocked);

/*
 * Some external functions, TODO: move them to dhd_linux.h
 */
int dhd_add_monitor(char *name, struct net_device **new_ndev);
int dhd_del_monitor(struct net_device *ndev);
int dhd_monitor_init(void *dhd_pub);
int dhd_monitor_uninit(void);
int dhd_start_xmit(struct sk_buff *skb, struct net_device *net);

#define CHECK_SYS_UP(wlpriv)							\
do {									\
	if (unlikely(!wl_get_drv_status(wlpriv, READY))) {	\
		WL_INFO(("device is not ready : status (%d)\n",		\
			(int)wlpriv->status));			\
		return -EIO;						\
	}								\
} while (0)


#define IS_WPA_AKM(akm) ((akm) == RSN_AKM_NONE || \
				 (akm) == RSN_AKM_UNSPECIFIED || \
				 (akm) == RSN_AKM_PSK)


extern int dhd_wait_pend8021x(struct net_device *dev);

#if (WL_DBG_LEVEL > 0)
#define WL_DBG_ESTR_MAX	50
static s8 wl_dbg_estr[][WL_DBG_ESTR_MAX] = {
	"SET_SSID", "JOIN", "START", "AUTH", "AUTH_IND",
	"DEAUTH", "DEAUTH_IND", "ASSOC", "ASSOC_IND", "REASSOC",
	"REASSOC_IND", "DISASSOC", "DISASSOC_IND", "QUIET_START", "QUIET_END",
	"BEACON_RX", "LINK", "MIC_ERROR", "NDIS_LINK", "ROAM",
	"TXFAIL", "PMKID_CACHE", "RETROGRADE_TSF", "PRUNE", "AUTOAUTH",
	"EAPOL_MSG", "SCAN_COMPLETE", "ADDTS_IND", "DELTS_IND", "BCNSENT_IND",
	"BCNRX_MSG", "BCNLOST_MSG", "ROAM_PREP", "PFN_NET_FOUND",
	"PFN_NET_LOST",
	"RESET_COMPLETE", "JOIN_START", "ROAM_START", "ASSOC_START",
	"IBSS_ASSOC",
	"RADIO", "PSM_WATCHDOG", "WLC_E_CCX_ASSOC_START", "WLC_E_CCX_ASSOC_ABORT",
	"PROBREQ_MSG",
	"SCAN_CONFIRM_IND", "PSK_SUP", "COUNTRY_CODE_CHANGED",
	"EXCEEDED_MEDIUM_TIME", "ICV_ERROR",
	"UNICAST_DECODE_ERROR", "MULTICAST_DECODE_ERROR", "TRACE",
	"WLC_E_BTA_HCI_EVENT", "IF", "WLC_E_P2P_DISC_LISTEN_COMPLETE",
	"RSSI", "PFN_SCAN_COMPLETE", "WLC_E_EXTLOG_MSG",
	"ACTION_FRAME", "ACTION_FRAME_COMPLETE", "WLC_E_PRE_ASSOC_IND",
	"WLC_E_PRE_REASSOC_IND", "WLC_E_CHANNEL_ADOPTED", "WLC_E_AP_STARTED",
	"WLC_E_DFS_AP_STOP", "WLC_E_DFS_AP_RESUME", "WLC_E_WAI_STA_EVENT",
	"WLC_E_WAI_MSG", "WLC_E_ESCAN_RESULT", "WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE",
	"WLC_E_PROBRESP_MSG", "WLC_E_P2P_PROBREQ_MSG", "WLC_E_DCS_REQUEST", "WLC_E_FIFO_CREDIT_MAP",
	"WLC_E_ACTION_FRAME_RX", "WLC_E_WAKE_EVENT", "WLC_E_RM_COMPLETE"
};
#endif				/* WL_DBG_LEVEL */

#define CHAN2G(_channel, _freq, _flags) {			\
	.band			= IEEE80211_BAND_2GHZ,		\
	.center_freq		= (_freq),			\
	.hw_value		= (_channel),			\
	.flags			= (_flags),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define CHAN5G(_channel, _flags) {				\
	.band			= IEEE80211_BAND_5GHZ,		\
	.center_freq		= 5000 + (5 * (_channel)),	\
	.hw_value		= (_channel),			\
	.flags			= (_flags),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define RATE_TO_BASE100KBPS(rate)   (((rate) * 10) / 2)
#define RATETAB_ENT(_rateid, _flags) \
	{								\
		.bitrate	= RATE_TO_BASE100KBPS(_rateid),     \
		.hw_value	= (_rateid),			    \
		.flags	  = (_flags),			     \
	}

static struct ieee80211_rate __wl_rates[] = {
	RATETAB_ENT(WLC_RATE_1M, 0),
	RATETAB_ENT(WLC_RATE_2M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(WLC_RATE_5M5, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(WLC_RATE_11M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(WLC_RATE_6M, 0),
	RATETAB_ENT(WLC_RATE_9M, 0),
	RATETAB_ENT(WLC_RATE_12M, 0),
	RATETAB_ENT(WLC_RATE_18M, 0),
	RATETAB_ENT(WLC_RATE_24M, 0),
	RATETAB_ENT(WLC_RATE_36M, 0),
	RATETAB_ENT(WLC_RATE_48M, 0),
	RATETAB_ENT(WLC_RATE_54M, 0)
};

#define wl_a_rates		(__wl_rates + 4)
#define wl_a_rates_size	8
#define wl_g_rates		(__wl_rates + 0)
#define wl_g_rates_size	12

static struct ieee80211_channel __wl_2ghz_channels[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0)
};

static struct ieee80211_channel __wl_5ghz_a_channels[] = {
	CHAN5G(34, 0), CHAN5G(36, 0),
	CHAN5G(38, 0), CHAN5G(40, 0),
	CHAN5G(42, 0), CHAN5G(44, 0),
	CHAN5G(46, 0), CHAN5G(48, 0),
	CHAN5G(52, 0), CHAN5G(56, 0),
	CHAN5G(60, 0), CHAN5G(64, 0),
	CHAN5G(100, 0), CHAN5G(104, 0),
	CHAN5G(108, 0), CHAN5G(112, 0),
	CHAN5G(116, 0), CHAN5G(120, 0),
	CHAN5G(124, 0), CHAN5G(128, 0),
	CHAN5G(132, 0), CHAN5G(136, 0),
	CHAN5G(140, 0), CHAN5G(149, 0),
	CHAN5G(153, 0), CHAN5G(157, 0),
	CHAN5G(161, 0), CHAN5G(165, 0)
};

static struct ieee80211_supported_band __wl_band_2ghz = {
	.band = IEEE80211_BAND_2GHZ,
	.channels = __wl_2ghz_channels,
	.n_channels = ARRAY_SIZE(__wl_2ghz_channels),
	.bitrates = wl_g_rates,
	.n_bitrates = wl_g_rates_size
};

static struct ieee80211_supported_band __wl_band_5ghz_a = {
	.band = IEEE80211_BAND_5GHZ,
	.channels = __wl_5ghz_a_channels,
	.n_channels = ARRAY_SIZE(__wl_5ghz_a_channels),
	.bitrates = wl_a_rates,
	.n_bitrates = wl_a_rates_size
};

static const u32 __wl_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_AES_CMAC,
};

/* There isn't a lot of sense in it, but you can transmit anything you like */
static const struct ieee80211_txrx_stypes
wl_cfg80211_default_mgmt_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_ADHOC] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_STATION] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_AP] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_AP_VLAN] = {
		/* copy AP */
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_P2P_CLIENT] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_P2P_GO] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	}
};

static void swap_key_from_BE(struct wl_wsec_key *key)
{
	key->index = htod32(key->index);
	key->len = htod32(key->len);
	key->algo = htod32(key->algo);
	key->flags = htod32(key->flags);
	key->rxiv.hi = htod32(key->rxiv.hi);
	key->rxiv.lo = htod16(key->rxiv.lo);
	key->iv_initialized = htod32(key->iv_initialized);
}

static void swap_key_to_BE(struct wl_wsec_key *key)
{
	key->index = dtoh32(key->index);
	key->len = dtoh32(key->len);
	key->algo = dtoh32(key->algo);
	key->flags = dtoh32(key->flags);
	key->rxiv.hi = dtoh32(key->rxiv.hi);
	key->rxiv.lo = dtoh16(key->rxiv.lo);
	key->iv_initialized = dtoh32(key->iv_initialized);
}

/* For debug: Dump the contents of the encoded wps ie buffe */
static void
wl_validate_wps_ie(char *wps_ie, bool *pbc)
{
	#define WPS_IE_FIXED_LEN 6
	u16 len = (u16) wps_ie[TLV_LEN_OFF];
	u8 *subel = wps_ie+  WPS_IE_FIXED_LEN;
	u16 subelt_id;
	u16 subelt_len;
	u16 val;
	u8 *valptr = (uint8*) &val;

	WL_DBG(("wps_ie len=%d\n", len));

	len -= 4;	/* for the WPS IE's OUI, oui_type fields */

	while (len >= 4) {		/* must have attr id, attr len fields */
		valptr[0] = *subel++;
		valptr[1] = *subel++;
		subelt_id = HTON16(val);

		valptr[0] = *subel++;
		valptr[1] = *subel++;
		subelt_len = HTON16(val);

		len -= 4;			/* for the attr id, attr len fields */
		len -= subelt_len;	/* for the remaining fields in this attribute */
		WL_DBG((" subel=%p, subelt_id=0x%x subelt_len=%u\n",
			subel, subelt_id, subelt_len));

		if (subelt_id == WPS_ID_VERSION) {
			WL_DBG(("  attr WPS_ID_VERSION: %u\n", *subel));
		} else if (subelt_id == WPS_ID_REQ_TYPE) {
			WL_DBG(("  attr WPS_ID_REQ_TYPE: %u\n", *subel));
		} else if (subelt_id == WPS_ID_CONFIG_METHODS) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			WL_DBG(("  attr WPS_ID_CONFIG_METHODS: %x\n", HTON16(val)));
		} else if (subelt_id == WPS_ID_DEVICE_NAME) {
			char devname[100];
			memcpy(devname, subel, subelt_len);
			devname[subelt_len] = '\0';
			WL_DBG(("  attr WPS_ID_DEVICE_NAME: %s (len %u)\n",
				devname, subelt_len));
		} else if (subelt_id == WPS_ID_DEVICE_PWD_ID) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			WL_DBG(("  attr WPS_ID_DEVICE_PWD_ID: %u\n", HTON16(val)));
			*pbc = (HTON16(val) == DEV_PW_PUSHBUTTON) ? true : false;
		} else if (subelt_id == WPS_ID_PRIM_DEV_TYPE) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			WL_DBG(("  attr WPS_ID_PRIM_DEV_TYPE: cat=%u \n", HTON16(val)));
			valptr[0] = *(subel + 6);
			valptr[1] = *(subel + 7);
			WL_DBG(("  attr WPS_ID_PRIM_DEV_TYPE: subcat=%u\n", HTON16(val)));
		} else if (subelt_id == WPS_ID_REQ_DEV_TYPE) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			WL_DBG(("  attr WPS_ID_REQ_DEV_TYPE: cat=%u\n", HTON16(val)));
			valptr[0] = *(subel + 6);
			valptr[1] = *(subel + 7);
			WL_DBG(("  attr WPS_ID_REQ_DEV_TYPE: subcat=%u\n", HTON16(val)));
		} else if (subelt_id == WPS_ID_SELECTED_REGISTRAR_CONFIG_METHODS) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			WL_DBG(("  attr WPS_ID_SELECTED_REGISTRAR_CONFIG_METHODS"
				": cat=%u\n", HTON16(val)));
		} else {
			WL_DBG(("  unknown attr 0x%x\n", subelt_id));
		}

		subel += subelt_len;
	}
}

static struct net_device* wl_cfg80211_add_monitor_if(char *name)
{
	int ret = 0;
	struct net_device* ndev = NULL;

	ret = dhd_add_monitor(name, &ndev);
	WL_INFO(("wl_cfg80211_add_monitor_if net device returned: 0x%p\n", ndev));
	return ndev;
}

static struct net_device *
wl_cfg80211_add_virtual_iface(struct wiphy *wiphy, char *name,
	enum nl80211_iftype type, u32 *flags,
	struct vif_params *params)
{
	s32 err;
	s32 timeout = -1;
	s32 wlif_type = -1;
	s32 index = 0;
	s32 mode = 0;
	chanspec_t chspec;
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct net_device *_ndev;
	dhd_pub_t *dhd = (dhd_pub_t *)(wl->pub);
	int (*net_attach)(dhd_pub_t *dhdp, int ifidx);
	bool rollback_lock = false;

	WL_DBG(("if name: %s, type: %d\n", name, type));
	switch (type) {
	case NL80211_IFTYPE_ADHOC:
	case NL80211_IFTYPE_AP_VLAN:
	case NL80211_IFTYPE_WDS:
	case NL80211_IFTYPE_MESH_POINT:
		WL_ERR(("Unsupported interface type\n"));
		mode = WL_MODE_IBSS;
		return NULL;
	case NL80211_IFTYPE_MONITOR:
		return wl_cfg80211_add_monitor_if(name);
	case NL80211_IFTYPE_P2P_CLIENT:
	case NL80211_IFTYPE_STATION:
		wlif_type = WL_P2P_IF_CLIENT;
		mode = WL_MODE_BSS;
		break;
	case NL80211_IFTYPE_P2P_GO:
	case NL80211_IFTYPE_AP:
		wlif_type = WL_P2P_IF_GO;
		mode = WL_MODE_AP;
		break;
	default:
		WL_ERR(("Unsupported interface type\n"));
		return NULL;
		break;
	}

	if (!name) {
		WL_ERR(("name is NULL\n"));
		return NULL;
	}
	if (wl->p2p_supported && (wlif_type != -1)) {
		if (wl_get_p2p_status(wl, IF_DELETING)) {
			/* wait till IF_DEL is complete
			 * release the lock for the unregister to proceed
			 */
			if (rtnl_is_locked()) {
				rtnl_unlock();
				rollback_lock = true;
			}
			WL_INFO(("%s: Released the lock and wait till IF_DEL is complete\n",
				__func__));
			timeout = wait_event_interruptible_timeout(wl->dongle_event_wait,
				(wl_get_p2p_status(wl, IF_DELETING) == false),
				msecs_to_jiffies(MAX_WAIT_TIME));

			/* put back the rtnl_lock again */
			if (rollback_lock) {
				rtnl_lock();
				rollback_lock = false;
			}
			if (timeout > 0) {
				WL_ERR(("IF DEL is Success\n"));

			} else {
				WL_ERR(("timeount < 0, return -EAGAIN\n"));
				return ERR_PTR(-EAGAIN);
			}
		}
		if (!p2p_on(wl) && strstr(name, WL_P2P_INTERFACE_PREFIX)) {
			p2p_on(wl) = true;
			wl_cfgp2p_set_firm_p2p(wl);
			wl_cfgp2p_init_discovery(wl);
		}
		memset(wl->p2p->vir_ifname, 0, IFNAMSIZ);
		strncpy(wl->p2p->vir_ifname, name, IFNAMSIZ - 1);
		wl_cfgp2p_generate_bss_mac(&dhd->mac, &wl->p2p->dev_addr, &wl->p2p->int_addr);

		/* Temporary use channel 11, in case GO will be changed with set_channel API  */
		chspec = wf_chspec_aton(WL_P2P_TEMP_CHAN);

		/* For P2P mode, use P2P-specific driver features to create the
		 * bss: "wl p2p_ifadd"
		 */
		wl_set_p2p_status(wl, IF_ADD);
		err = wl_cfgp2p_ifadd(wl, &wl->p2p->int_addr, htod32(wlif_type), chspec);

		if (unlikely(err))
			return ERR_PTR(-ENOMEM);

		timeout = wait_event_interruptible_timeout(wl->dongle_event_wait,
			(wl_get_p2p_status(wl, IF_ADD) == false),
			msecs_to_jiffies(MAX_WAIT_TIME));
		if (timeout > 0 && (!wl_get_p2p_status(wl, IF_ADD))) {

			struct wireless_dev *vwdev;
			vwdev = kzalloc(sizeof(*vwdev), GFP_KERNEL);
			if (unlikely(!vwdev)) {
				WL_ERR(("Could not allocate wireless device\n"));
				return ERR_PTR(-ENOMEM);
			}
			vwdev->wiphy = wl->wdev->wiphy;
			WL_INFO((" virtual interface(%s) is created memalloc done \n",
			wl->p2p->vir_ifname));
			index = alloc_idx_vwdev(wl);
			wl->vwdev[index] = vwdev;
			vwdev->iftype =
				(wlif_type == WL_P2P_IF_CLIENT) ? NL80211_IFTYPE_STATION
				: NL80211_IFTYPE_AP;
			_ndev =  wl_to_p2p_bss_ndev(wl, P2PAPI_BSSCFG_CONNECTION);
			_ndev->ieee80211_ptr = vwdev;
			SET_NETDEV_DEV(_ndev, wiphy_dev(vwdev->wiphy));
			vwdev->netdev = _ndev;
			wl_set_drv_status(wl, READY);
			wl->p2p->vif_created = true;
			set_mode_by_netdev(wl, _ndev, mode);
			net_attach =  wl_to_p2p_bss_private(wl, P2PAPI_BSSCFG_CONNECTION);
			if (rtnl_is_locked()) {
				rtnl_unlock();
				rollback_lock = true;
			}
			if (net_attach && !net_attach(dhd, _ndev->ifindex)) {
				WL_DBG((" virtual interface(%s) is "
					"created net attach done\n", wl->p2p->vir_ifname));
			} else {
				/* put back the rtnl_lock again */
				if (rollback_lock)
					rtnl_lock();
				goto fail;
			}
			/* put back the rtnl_lock again */
			if (rollback_lock)
				rtnl_lock();
			return _ndev;

		} else {
			wl_clr_p2p_status(wl, IF_ADD);
			WL_ERR((" virtual interface(%s) is not created \n", wl->p2p->vir_ifname));
			memset(wl->p2p->vir_ifname, '\0', IFNAMSIZ);
			wl->p2p->vif_created = false;
		}
	}
fail:
	return ERR_PTR(-ENODEV);
}

static s32
wl_cfg80211_del_virtual_iface(struct wiphy *wiphy, struct net_device *dev)
{
	struct ether_addr p2p_mac;
	struct wl_priv *wl = wiphy_priv(wiphy);
	s32 timeout = -1;
	s32 ret = 0;
	WL_DBG(("Enter\n"));
	if (wl->p2p_supported) {
		memcpy(p2p_mac.octet, wl->p2p->int_addr.octet, ETHER_ADDR_LEN);
		if (wl->p2p->vif_created) {
			if (wl_get_drv_status(wl, SCANNING)) {
				wl_cfg80211_scan_abort(wl, dev);
			}
			wldev_iovar_setint(dev, "mpc", 1);
			wl_set_p2p_status(wl, IF_DELETING);
			ret = wl_cfgp2p_ifdel(wl, &p2p_mac);
			if (ret) {
			/* Firmware could not delete the interface so we will not get WLC_E_IF
			* event for cleaning the dhd virtual nw interace
			* So lets do it here. Failures from fw will ensure the application to do
			* ifconfig <inter> down and up sequnce, which will reload the fw
			* however we should cleanup the linux network virtual interfaces
			*/
				dhd_pub_t *dhd = (dhd_pub_t *)(wl->pub);
				WL_ERR(("Firmware returned an error from p2p_ifdel\n"));
				WL_ERR(("try to remove linux virtual interface %s\n", dev->name));
				dhd_del_if(dhd->info, dhd_net2idx(dhd->info, dev));
			}

			/* Wait for any pending scan req to get aborted from the sysioc context */
			timeout = wait_event_interruptible_timeout(wl->dongle_event_wait,
				(wl_get_p2p_status(wl, IF_DELETING) == false),
				msecs_to_jiffies(MAX_WAIT_TIME));
			if (timeout > 0 && !wl_get_p2p_status(wl, IF_DELETING)) {
				WL_DBG(("IFDEL operation done\n"));
			} else {
				WL_ERR(("IFDEL didn't complete properly\n"));
			}
			ret = dhd_del_monitor(dev);
		}
	}
	return ret;
}

static s32
wl_cfg80211_change_virtual_iface(struct wiphy *wiphy, struct net_device *ndev,
	enum nl80211_iftype type, u32 *flags,
	struct vif_params *params)
{
	s32 ap = 0;
	s32 infra = 0;
	s32 err = BCME_OK;
	s32 timeout = -1;
	s32 wlif_type;
	s32 mode = 0;
	chanspec_t chspec;
	struct wl_priv *wl = wiphy_priv(wiphy);
	WL_DBG(("Enter \n"));
	switch (type) {
	case NL80211_IFTYPE_MONITOR:
	case NL80211_IFTYPE_WDS:
	case NL80211_IFTYPE_MESH_POINT:
		ap = 1;
		WL_ERR(("type (%d) : currently we do not support this type\n",
			type));
		break;
	case NL80211_IFTYPE_ADHOC:
		mode = WL_MODE_IBSS;
		break;
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_P2P_CLIENT:
		mode = WL_MODE_BSS;
		infra = 1;
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_AP_VLAN:
	case NL80211_IFTYPE_P2P_GO:
		mode = WL_MODE_AP;
		ap = 1;
		break;
	default:
		return -EINVAL;
	}


	if (ap) {
		set_mode_by_netdev(wl, ndev, mode);
		if (wl->p2p_supported && wl->p2p->vif_created) {
			WL_DBG(("p2p_vif_created (%d) p2p_on (%d)\n", wl->p2p->vif_created,
			p2p_on(wl)));
			chspec = wf_chspec_aton(WL_P2P_TEMP_CHAN);
			wlif_type = ap ? WL_P2P_IF_GO : WL_P2P_IF_CLIENT;
			WL_ERR(("%s : ap (%d), infra (%d), iftype: (%d)\n",
				ndev->name, ap, infra, type));
			wl_set_p2p_status(wl, IF_CHANGING);
			wl_clr_p2p_status(wl, IF_CHANGED);
			err = wl_cfgp2p_ifchange(wl, &wl->p2p->int_addr, htod32(wlif_type), chspec);
			timeout = wait_event_interruptible_timeout(wl->dongle_event_wait,
				(wl_get_p2p_status(wl, IF_CHANGED) == true),
				msecs_to_jiffies(MAX_WAIT_TIME));
			set_mode_by_netdev(wl, ndev, mode);
			wl_clr_p2p_status(wl, IF_CHANGING);
			wl_clr_p2p_status(wl, IF_CHANGED);
		} else if (ndev == wl_to_prmry_ndev(wl) &&
			!wl_get_drv_status(wl, AP_CREATED)) {
			wl_set_drv_status(wl, AP_CREATING);
			if (!wl->ap_info &&
				!(wl->ap_info = kzalloc(sizeof(struct ap_info), GFP_KERNEL))) {
				WL_ERR(("struct ap_saved_ie allocation failed\n"));
				return -ENOMEM;
			}
		} else {
			WL_ERR(("Cannot change the interface for GO or SOFTAP\n"));
			return -EINVAL;
		}
	}

	ndev->ieee80211_ptr->iftype = type;
	return 0;
}

s32
wl_cfg80211_notify_ifadd(struct net_device *ndev, s32 idx, s32 bssidx,
int (*_net_attach)(dhd_pub_t *dhdp, int ifidx))
{
	struct wl_priv *wl = wlcfg_drv_priv;
	s32 ret = BCME_OK;
	if (!ndev) {
		WL_ERR(("net is NULL\n"));
		return 0;
	}
	if (wl->p2p_supported) {
		WL_DBG(("IF_ADD event called from dongle, old interface name: %s,"
			"new name: %s\n", ndev->name, wl->p2p->vir_ifname));
		/* Assign the net device to CONNECT BSSCFG */
		strncpy(ndev->name, wl->p2p->vir_ifname, IFNAMSIZ - 1);
		wl_to_p2p_bss_ndev(wl, P2PAPI_BSSCFG_CONNECTION) = ndev;
		wl_to_p2p_bss_bssidx(wl, P2PAPI_BSSCFG_CONNECTION) = bssidx;
		wl_to_p2p_bss_private(wl, P2PAPI_BSSCFG_CONNECTION) = _net_attach;
		ndev->ifindex = idx;
		wl_clr_p2p_status(wl, IF_ADD);

		wake_up_interruptible(&wl->dongle_event_wait);
	}
	return ret;
}

s32
wl_cfg80211_notify_ifdel(struct net_device *ndev)
{
	struct wl_priv *wl = wlcfg_drv_priv;
	bool rollback_lock = false;
	s32 index = 0;

	if (!ndev || !ndev->name) {
		WL_ERR(("net is NULL\n"));
		return 0;
	}

	if (p2p_is_on(wl) && wl->p2p->vif_created) {
		if (wl->scan_request) {
			/* Abort any pending scan requests */
			wl->escan_info.escan_state = WL_ESCAN_STATE_IDLE;
			if (!rtnl_is_locked()) {
				rtnl_lock();
				rollback_lock = true;
			}
			WL_DBG(("ESCAN COMPLETED\n"));
			wl_notify_escan_complete(wl, true);
			if (rollback_lock)
				rtnl_unlock();
		}
		WL_ERR(("IF_DEL event called from dongle, net %x, vif name: %s\n",
			(unsigned int)ndev, wl->p2p->vir_ifname));

		memset(wl->p2p->vir_ifname, '\0', IFNAMSIZ);
		index = wl_cfgp2p_find_idx(wl, ndev);
		wl_to_p2p_bss_ndev(wl, index) = NULL;
		wl_to_p2p_bss_bssidx(wl, index) = 0;
		wl->p2p->vif_created = false;
		wl_cfgp2p_clear_management_ie(wl,
			index);
		wl_clr_p2p_status(wl, IF_DELETING);
		WL_DBG(("index : %d\n", index));

	}
	/* Wake up any waiting thread */
	wake_up_interruptible(&wl->dongle_event_wait);

	return 0;
}

s32
wl_cfg80211_is_progress_ifadd(void)
{
	s32 is_progress = 0;
	struct wl_priv *wl = wlcfg_drv_priv;
	if (wl_get_p2p_status(wl, IF_ADD))
		is_progress = 1;
	return is_progress;
}

s32
wl_cfg80211_is_progress_ifchange(void)
{
	s32 is_progress = 0;
	struct wl_priv *wl = wlcfg_drv_priv;
	if (wl_get_p2p_status(wl, IF_CHANGING))
		is_progress = 1;
	return is_progress;
}


s32
wl_cfg80211_notify_ifchange(void)
{
	struct wl_priv *wl = wlcfg_drv_priv;
	if (wl_get_p2p_status(wl, IF_CHANGING)) {
		wl_set_p2p_status(wl, IF_CHANGED);
		wake_up_interruptible(&wl->dongle_event_wait);
	}
	return 0;
}

static void wl_scan_prep(struct wl_scan_params *params, struct cfg80211_scan_request *request)
{
	u32 n_ssids = request->n_ssids;
	u32 n_channels = request->n_channels;
	u16 channel;
	chanspec_t chanspec;
	s32 i, offset;
	char *ptr;
	wlc_ssid_t ssid;

	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->bss_type = DOT11_BSSTYPE_ANY;
	params->scan_type = 0;
	params->nprobes = -1;
	params->active_time = -1;
	params->passive_time = -1;
	params->home_time = -1;
	params->channel_num = 0;
	memset(&params->ssid, 0, sizeof(wlc_ssid_t));

	WL_SCAN(("Preparing Scan request\n"));
	WL_SCAN(("nprobes=%d\n", params->nprobes));
	WL_SCAN(("active_time=%d\n", params->active_time));
	WL_SCAN(("passive_time=%d\n", params->passive_time));
	WL_SCAN(("home_time=%d\n", params->home_time));
	WL_SCAN(("scan_type=%d\n", params->scan_type));

	params->nprobes = htod32(params->nprobes);
	params->active_time = htod32(params->active_time);
	params->passive_time = htod32(params->passive_time);
	params->home_time = htod32(params->home_time);

	/* Copy channel array if applicable */
	WL_SCAN(("### List of channelspecs to scan ###\n"));
	if (n_channels > 0) {
		for (i = 0; i < n_channels; i++) {
			chanspec = 0;
			channel = ieee80211_frequency_to_channel(request->channels[i]->center_freq);
			if (request->channels[i]->band == IEEE80211_BAND_2GHZ)
				chanspec |= WL_CHANSPEC_BAND_2G;
			else
				chanspec |= WL_CHANSPEC_BAND_5G;

			if (request->channels[i]->flags & IEEE80211_CHAN_NO_HT40) {
				chanspec |= WL_CHANSPEC_BW_20;
				chanspec |= WL_CHANSPEC_CTL_SB_NONE;
			} else {
				chanspec |= WL_CHANSPEC_BW_40;
				if (request->channels[i]->flags & IEEE80211_CHAN_NO_HT40PLUS)
					chanspec |= WL_CHANSPEC_CTL_SB_LOWER;
				else
					chanspec |= WL_CHANSPEC_CTL_SB_UPPER;
			}

			params->channel_list[i] = channel;
			params->channel_list[i] &= WL_CHANSPEC_CHAN_MASK;
			params->channel_list[i] |= chanspec;
			WL_SCAN(("Chan : %d, Channel spec: %x \n",
			channel, params->channel_list[i]));
			params->channel_list[i] = htod16(params->channel_list[i]);
		}
	} else {
		WL_SCAN(("Scanning all channels\n"));
	}

	/* Copy ssid array if applicable */
	WL_SCAN(("### List of SSIDs to scan ###\n"));
	if (n_ssids > 0) {
		offset = offsetof(wl_scan_params_t, channel_list) + n_channels * sizeof(u16);
		offset = roundup(offset, sizeof(u32));
		ptr = (char*)params + offset;
		for (i = 0; i < n_ssids; i++) {
			memset(&ssid, 0, sizeof(wlc_ssid_t));
			ssid.SSID_len = request->ssids[i].ssid_len;
			memcpy(ssid.SSID, request->ssids[i].ssid, ssid.SSID_len);
			if (!ssid.SSID_len)
				WL_SCAN(("%d: Broadcast scan\n", i));
			else
				WL_SCAN(("%d: scan  for  %s size =%d\n", i,
				ssid.SSID, ssid.SSID_len));
			memcpy(ptr, &ssid, sizeof(wlc_ssid_t));
			ptr += sizeof(wlc_ssid_t);
		}
	} else {
		WL_SCAN(("Broadcast scan\n"));
	}
	/* Adding mask to channel numbers */
	params->channel_num =
	        htod32((n_ssids << WL_SCAN_PARAMS_NSSID_SHIFT) |
	               (n_channels & WL_SCAN_PARAMS_COUNT_MASK));
}

static s32
wl_run_iscan(struct wl_iscan_ctrl *iscan, struct cfg80211_scan_request *request, u16 action)
{
	u32 n_channels;
	u32 n_ssids;
	s32 params_size =
	    (WL_SCAN_PARAMS_FIXED_SIZE + offsetof(wl_iscan_params_t, params));
	struct wl_iscan_params *params;
	s32 err = 0;

	if (request != NULL) {
		n_channels = request->n_channels;
		n_ssids = request->n_ssids;
		/* Allocate space for populating ssids in wl_iscan_params struct */
		if (n_channels % 2)
			/* If n_channels is odd, add a padd of u16 */
			params_size += sizeof(u16) * (n_channels + 1);
		else
			params_size += sizeof(u16) * n_channels;

		/* Allocate space for populating ssids in wl_iscan_params struct */
		params_size += sizeof(struct wlc_ssid) * n_ssids;
	}
	params = (struct wl_iscan_params *)kzalloc(params_size, GFP_KERNEL);
	if (!params) {
		return -ENOMEM;
	}

	if (request != NULL)
		wl_scan_prep(&params->params, request);

	params->version = htod32(ISCAN_REQ_VERSION);
	params->action = htod16(action);
	params->scan_duration = htod16(0);

	if (params_size + sizeof("iscan") >= WLC_IOCTL_MEDLEN) {
		WL_ERR(("ioctl buffer length is not sufficient\n"));
		err = -ENOMEM;
		goto done;
	}
	err = wldev_iovar_setbuf(iscan->dev, "iscan", params, params_size,
		iscan->ioctl_buf, WLC_IOCTL_MEDLEN);
	if (unlikely(err)) {
		if (err == -EBUSY) {
			WL_ERR(("system busy : iscan canceled\n"));
		} else {
			WL_ERR(("error (%d)\n", err));
		}
	}
done:
	kfree(params);
	return err;
}

static s32 wl_do_iscan(struct wl_priv *wl, struct cfg80211_scan_request *request)
{
	struct wl_iscan_ctrl *iscan = wl_to_iscan(wl);
	struct net_device *ndev = wl_to_prmry_ndev(wl);
	s32 passive_scan;
	s32 err = 0;

	iscan->state = WL_ISCAN_STATE_SCANING;

	passive_scan = wl->active_scan ? 0 : 1;
	err = wldev_ioctl(ndev, WLC_SET_PASSIVE_SCAN,
		&passive_scan, sizeof(passive_scan), false);
	if (unlikely(err)) {
		WL_DBG(("error (%d)\n", err));
		return err;
	}
	wl->iscan_kickstart = true;
	wl_run_iscan(iscan, request, WL_SCAN_ACTION_START);
	mod_timer(&iscan->timer, jiffies + iscan->timer_ms * HZ / 1000);
	iscan->timer_on = 1;

	return err;
}

static s32
wl_run_escan(struct wl_priv *wl, struct net_device *ndev,
	struct cfg80211_scan_request *request, uint16 action)
{
	s32 err = BCME_OK;
	u32 n_channels;
	u32 n_ssids;
	s32 params_size = (WL_SCAN_PARAMS_FIXED_SIZE + OFFSETOF(wl_escan_params_t, params));
	wl_escan_params_t *params;
	struct cfg80211_scan_request *scan_request = wl->scan_request;
	u32 num_chans = 0;
	s32 search_state = WL_P2P_DISC_ST_SCAN;
	u32 i;
	u16 *default_chan_list = NULL;
	struct net_device *dev = NULL;
	WL_DBG(("Enter \n"));


	if (!wl->p2p_supported || ((ndev == wl_to_prmry_ndev(wl)) &&
		!p2p_scan(wl))) {
		/* LEGACY SCAN TRIGGER */
		WL_SCAN((" LEGACY E-SCAN START\n"));

		if (request != NULL) {
			n_channels = request->n_channels;
			n_ssids = request->n_ssids;
			/* Allocate space for populating ssids in wl_iscan_params struct */
			if (n_channels % 2)
				/* If n_channels is odd, add a padd of u16 */
				params_size += sizeof(u16) * (n_channels + 1);
			else
				params_size += sizeof(u16) * n_channels;

			/* Allocate space for populating ssids in wl_iscan_params struct */
			params_size += sizeof(struct wlc_ssid) * n_ssids;
		}
		params = (wl_escan_params_t *) kzalloc(params_size, GFP_KERNEL);
		if (params == NULL) {
			err = -ENOMEM;
			goto exit;
		}

		if (request != NULL)
			wl_scan_prep(&params->params, request);
		params->version = htod32(ESCAN_REQ_VERSION);
		params->action =  htod16(action);
		params->sync_id = htod16(0x1234);
		if (params_size + sizeof("escan") >= WLC_IOCTL_MEDLEN) {
			WL_ERR(("ioctl buffer length not sufficient\n"));
			kfree(params);
			err = -ENOMEM;
			goto exit;
		}
		err = wldev_iovar_setbuf(ndev, "escan", params, params_size,
			wl->escan_ioctl_buf, WLC_IOCTL_MEDLEN);
		if (unlikely(err))
			WL_ERR((" Escan set error (%d)\n", err));
		kfree(params);
	}
	else if (p2p_on(wl) && p2p_scan(wl)) {
		/* P2P SCAN TRIGGER */
		if (scan_request && scan_request->n_channels) {
			num_chans = scan_request->n_channels;
			WL_SCAN((" chann number : %d\n", num_chans));
			default_chan_list = kzalloc(num_chans * sizeof(*default_chan_list),
				GFP_KERNEL);
			if (default_chan_list == NULL) {
				WL_ERR(("channel list allocation failed \n"));
				err = -ENOMEM;
				goto exit;
			}
			for (i = 0; i < num_chans; i++)
			{
				default_chan_list[i] =
				ieee80211_frequency_to_channel(
					scan_request->channels[i]->center_freq);
			}
			if (num_chans == 3 && (
						(default_chan_list[0] == SOCIAL_CHAN_1) &&
						(default_chan_list[1] == SOCIAL_CHAN_2) &&
						(default_chan_list[2] == SOCIAL_CHAN_3))) {
				/* SOCIAL CHANNELS 1, 6, 11 */
				search_state = WL_P2P_DISC_ST_SEARCH;
				WL_INFO(("P2P SEARCH PHASE START \n"));
			} else if ((dev = wl_to_p2p_bss_ndev(wl, P2PAPI_BSSCFG_CONNECTION)) &&
				(get_mode_by_netdev(wl, dev) == WL_MODE_AP)) {
				/* If you are already a GO, then do SEARCH only */
				WL_INFO(("Already a GO. Do SEARCH Only"));
				search_state = WL_P2P_DISC_ST_SEARCH;
			} else {
				WL_INFO(("P2P SCAN STATE START \n"));
			}

		}
		err = wl_cfgp2p_escan(wl, ndev, wl->active_scan, num_chans, default_chan_list,
			search_state, action,
			wl_to_p2p_bss_bssidx(wl, P2PAPI_BSSCFG_DEVICE));
		kfree(default_chan_list);
	}
exit:
	if (unlikely(err)) {
		WL_ERR(("error (%d)\n", err));
	}
	return err;
}


static s32
wl_do_escan(struct wl_priv *wl, struct wiphy *wiphy, struct net_device *ndev,
	struct cfg80211_scan_request *request)
{
	s32 err = BCME_OK;
	s32 passive_scan;
	wl_scan_results_t *results;
	WL_SCAN(("Enter \n"));

	wl->escan_info.wiphy = wiphy;
	wl->escan_info.escan_state = WL_ESCAN_STATE_SCANING;
	passive_scan = wl->active_scan ? 0 : 1;
	err = wldev_ioctl(ndev, WLC_SET_PASSIVE_SCAN,
		&passive_scan, sizeof(passive_scan), false);
	if (unlikely(err)) {
		WL_ERR(("error (%d)\n", err));
		return err;
	}
	results = (wl_scan_results_t *) wl->escan_info.escan_buf;
	results->version = 0;
	results->count = 0;
	results->buflen = WL_SCAN_RESULTS_FIXED_SIZE;

	err = wl_run_escan(wl, ndev, request, WL_SCAN_ACTION_START);
	return err;
}

static s32
__wl_cfg80211_scan(struct wiphy *wiphy, struct net_device *ndev,
	struct cfg80211_scan_request *request,
	struct cfg80211_ssid *this_ssid)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct cfg80211_ssid *ssids;
	struct wl_scan_req *sr = wl_to_sr(wl);
	wpa_ie_fixed_t *wps_ie;
	s32 passive_scan;
	bool iscan_req;
	bool escan_req;
	bool spec_scan;
	bool p2p_ssid;
	s32 err = 0;
	s32 i;
	u32 wpsie_len = 0;
	u8 wpsie[IE_MAX_LEN];

	WL_DBG(("Enter wiphy (%p)\n", wiphy));
	if (unlikely(wl_get_drv_status(wl, SCANNING))) {
		WL_ERR(("Scanning already : status (%d)\n", (int)wl->status));
		return -EAGAIN;
	}
	if (unlikely(wl_get_drv_status(wl, SCAN_ABORTING))) {
		WL_ERR(("Scanning being aborted : status (%d)\n",
			(int)wl->status));
		return -EAGAIN;
	}
	if (request->n_ssids > WL_SCAN_PARAMS_SSID_MAX) {
		WL_ERR(("n_ssids > WL_SCAN_PARAMS_SSID_MAX\n"));
		return -EOPNOTSUPP;
	}

	/* Arm scan timeout timer */
	mod_timer(&wl->scan_timeout, jiffies + WL_SCAN_TIMER_INTERVAL_MS * HZ / 1000);
	iscan_req = false;
	spec_scan = false;
	if (request) {		/* scan bss */
		ssids = request->ssids;
		if (wl->iscan_on && (!ssids || !ssids->ssid_len || request->n_ssids != 1)) {
			iscan_req = true;
		} else if (wl->escan_on) {
			escan_req = true;
			p2p_ssid = false;
			for (i = 0; i < request->n_ssids; i++) {
				if (ssids[i].ssid_len && IS_P2P_SSID(ssids[i].ssid)) {
					p2p_ssid = true;
					break;
				}
			}
			if (p2p_ssid) {
				if (wl->p2p_supported) {
					/* p2p scan trigger */
					if (p2p_on(wl) == false) {
						/* p2p on at the first time */
						p2p_on(wl) = true;
						wl_cfgp2p_set_firm_p2p(wl);
					}
					p2p_scan(wl) = true;
				}
			} else {
				/* legacy scan trigger
				 * So, we have to disable p2p discovery if p2p discovery is on
				 */
				if (wl->p2p_supported) {
					p2p_scan(wl) = false;
					/* If Netdevice is not equals to primary and p2p is on
					*  , we will do p2p scan using P2PAPI_BSSCFG_DEVICE.
					*/
					if (p2p_on(wl) && (ndev != wl_to_prmry_ndev(wl)))
						p2p_scan(wl) = true;

					if (p2p_scan(wl) == false) {
						if (wl_get_p2p_status(wl, DISCOVERY_ON)) {
							err = wl_cfgp2p_discover_enable_search(wl,
							false);
							if (unlikely(err)) {
								goto scan_out;
							}

						}
					}
				}
				if (!wl->p2p_supported || !p2p_scan(wl)) {
					if (ndev == wl_to_prmry_ndev(wl)) {
						/* find the WPSIE */
						memset(wpsie, 0, sizeof(wpsie));
						if ((wps_ie = wl_cfgp2p_find_wpsie(
							(u8 *)request->ie,
							request->ie_len)) != NULL) {
							wpsie_len =
							wps_ie->length + WPA_RSN_IE_TAG_FIXED_LEN;
							memcpy(wpsie, wps_ie, wpsie_len);
						} else {
							wpsie_len = 0;
						}
						err = wl_cfgp2p_set_management_ie(wl, ndev, -1,
							VNDR_IE_PRBREQ_FLAG, wpsie, wpsie_len);
						if (unlikely(err)) {
							goto scan_out;
						}
					}
				}
			}
		}
	} else {		/* scan in ibss */
		/* we don't do iscan in ibss */
		ssids = this_ssid;
	}
	wl->scan_request = request;
	wl_set_drv_status(wl, SCANNING);
	if (iscan_req) {
		err = wl_do_iscan(wl, request);
		if (likely(!err))
			return err;
		else
			goto scan_out;
	} else if (escan_req) {
		if (wl->p2p_supported) {
			if (p2p_on(wl) && p2p_scan(wl)) {

				err = wl_cfgp2p_enable_discovery(wl, ndev,
				request->ie, request->ie_len);

				if (unlikely(err)) {
					goto scan_out;
				}
			}
		}
		err = wl_do_escan(wl, wiphy, ndev, request);
		if (likely(!err))
			return err;
		else
			goto scan_out;


	} else {
		memset(&sr->ssid, 0, sizeof(sr->ssid));
		sr->ssid.SSID_len =
			min_t(u8, sizeof(sr->ssid.SSID), ssids->ssid_len);
		if (sr->ssid.SSID_len) {
			memcpy(sr->ssid.SSID, ssids->ssid, sr->ssid.SSID_len);
			sr->ssid.SSID_len = htod32(sr->ssid.SSID_len);
			WL_SCAN(("Specific scan ssid=\"%s\" len=%d\n",
				sr->ssid.SSID, sr->ssid.SSID_len));
			spec_scan = true;
		} else {
			WL_SCAN(("Broadcast scan\n"));
		}
		WL_SCAN(("sr->ssid.SSID_len (%d)\n", sr->ssid.SSID_len));
		passive_scan = wl->active_scan ? 0 : 1;
		err = wldev_ioctl(ndev, WLC_SET_PASSIVE_SCAN,
			&passive_scan, sizeof(passive_scan), false);
		if (unlikely(err)) {
			WL_SCAN(("WLC_SET_PASSIVE_SCAN error (%d)\n", err));
			goto scan_out;
		}
		err = wldev_ioctl(ndev, WLC_SCAN, &sr->ssid,
			sizeof(sr->ssid), false);
		if (err) {
			if (err == -EBUSY) {
				WL_ERR(("system busy : scan for \"%s\" "
					"canceled\n", sr->ssid.SSID));
			} else {
				WL_ERR(("WLC_SCAN error (%d)\n", err));
			}
			goto scan_out;
		}
	}

	return 0;

scan_out:
	wl_clr_drv_status(wl, SCANNING);
	wl->scan_request = NULL;
	return err;
}

static s32
wl_cfg80211_scan(struct wiphy *wiphy, struct net_device *ndev,
	struct cfg80211_scan_request *request)
{
	s32 err = 0;
	struct wl_priv *wl = wiphy_priv(wiphy);

	WL_DBG(("Enter \n"));
	CHECK_SYS_UP(wl);

	err = __wl_cfg80211_scan(wiphy, ndev, request, NULL);
	if (unlikely(err)) {
		WL_ERR(("scan error (%d)\n", err));
		return err;
	}

	return err;
}

static s32 wl_dev_intvar_set(struct net_device *dev, s8 *name, s32 val)
{
	s8 buf[WLC_IOCTL_SMLEN];
	u32 len;
	s32 err = 0;

	val = htod32(val);
	len = bcm_mkiovar(name, (char *)(&val), sizeof(val), buf, sizeof(buf));
	BUG_ON(unlikely(!len));

	err = wldev_ioctl(dev, WLC_SET_VAR, buf, len, false);
	if (unlikely(err)) {
		WL_ERR(("error (%d)\n", err));
	}

	return err;
}

static s32
wl_dev_intvar_get(struct net_device *dev, s8 *name, s32 *retval)
{
	union {
		s8 buf[WLC_IOCTL_SMLEN];
		s32 val;
	} var;
	u32 len;
	u32 data_null;
	s32 err = 0;

	len = bcm_mkiovar(name, (char *)(&data_null), 0,
		(char *)(&var), sizeof(var.buf));
	BUG_ON(unlikely(!len));
	err = wldev_ioctl(dev, WLC_GET_VAR, &var, len, false);
	if (unlikely(err)) {
		WL_ERR(("error (%d)\n", err));
	}
	*retval = dtoh32(var.val);

	return err;
}

static s32 wl_set_rts(struct net_device *dev, u32 rts_threshold)
{
	s32 err = 0;

	err = wl_dev_intvar_set(dev, "rtsthresh", rts_threshold);
	if (unlikely(err)) {
		WL_ERR(("Error (%d)\n", err));
		return err;
	}
	return err;
}

static s32 wl_set_frag(struct net_device *dev, u32 frag_threshold)
{
	s32 err = 0;

	err = wl_dev_intvar_set(dev, "fragthresh", frag_threshold);
	if (unlikely(err)) {
		WL_ERR(("Error (%d)\n", err));
		return err;
	}
	return err;
}

static s32 wl_set_retry(struct net_device *dev, u32 retry, bool l)
{
	s32 err = 0;
	u32 cmd = (l ? WLC_SET_LRL : WLC_SET_SRL);

	retry = htod32(retry);
	err = wldev_ioctl(dev, cmd, &retry, sizeof(retry), false);
	if (unlikely(err)) {
		WL_ERR(("cmd (%d) , error (%d)\n", cmd, err));
		return err;
	}
	return err;
}

static s32 wl_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed)
{
	struct wl_priv *wl = (struct wl_priv *)wiphy_priv(wiphy);
	struct net_device *ndev = wl_to_prmry_ndev(wl);
	s32 err = 0;

	CHECK_SYS_UP(wl);
	if (changed & WIPHY_PARAM_RTS_THRESHOLD &&
		(wl->conf->rts_threshold != wiphy->rts_threshold)) {
		wl->conf->rts_threshold = wiphy->rts_threshold;
		err = wl_set_rts(ndev, wl->conf->rts_threshold);
		if (!err)
			return err;
	}
	if (changed & WIPHY_PARAM_FRAG_THRESHOLD &&
		(wl->conf->frag_threshold != wiphy->frag_threshold)) {
		wl->conf->frag_threshold = wiphy->frag_threshold;
		err = wl_set_frag(ndev, wl->conf->frag_threshold);
		if (!err)
			return err;
	}
	if (changed & WIPHY_PARAM_RETRY_LONG &&
		(wl->conf->retry_long != wiphy->retry_long)) {
		wl->conf->retry_long = wiphy->retry_long;
		err = wl_set_retry(ndev, wl->conf->retry_long, true);
		if (!err)
			return err;
	}
	if (changed & WIPHY_PARAM_RETRY_SHORT &&
		(wl->conf->retry_short != wiphy->retry_short)) {
		wl->conf->retry_short = wiphy->retry_short;
		err = wl_set_retry(ndev, wl->conf->retry_short, false);
		if (!err) {
			return err;
		}
	}

	return err;
}

static s32
wl_cfg80211_join_ibss(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_ibss_params *params)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct cfg80211_bss *bss;
	struct ieee80211_channel *chan;
	struct wl_join_params join_params;
	struct cfg80211_ssid ssid;
	s32 scan_retry = 0;
	s32 err = 0;
	bool rollback_lock = false;

	WL_TRACE(("In\n"));
	CHECK_SYS_UP(wl);
	if (params->bssid) {
		WL_ERR(("Invalid bssid\n"));
		return -EOPNOTSUPP;
	}
	bss = cfg80211_get_ibss(wiphy, NULL, params->ssid, params->ssid_len);
	if (!bss) {
		memcpy(ssid.ssid, params->ssid, params->ssid_len);
		ssid.ssid_len = params->ssid_len;
		do {
			if (unlikely
				(__wl_cfg80211_scan(wiphy, dev, NULL, &ssid) ==
				 -EBUSY)) {
				wl_delay(150);
			} else {
				break;
			}
		} while (++scan_retry < WL_SCAN_RETRY_MAX);
		/* to allow scan_inform to propagate to cfg80211 plane */
		if (rtnl_is_locked()) {
			rtnl_unlock();
			rollback_lock = true;
		}

		/* wait 4 secons till scan done.... */
		schedule_timeout_interruptible(4 * HZ);
		if (rollback_lock)
			rtnl_lock();
		bss = cfg80211_get_ibss(wiphy, NULL,
			params->ssid, params->ssid_len);
	}
	if (bss) {
		wl->ibss_starter = false;
		WL_DBG(("Found IBSS\n"));
	} else {
		wl->ibss_starter = true;
	}
	chan = params->channel;
	if (chan)
		wl->channel = ieee80211_frequency_to_channel(chan->center_freq);
	/*
	 * Join with specific BSSID and cached SSID
	 * If SSID is zero join based on BSSID only
	 */
	memset(&join_params, 0, sizeof(join_params));
	memcpy((void *)join_params.ssid.SSID, (void *)params->ssid,
		params->ssid_len);
	join_params.ssid.SSID_len = htod32(params->ssid_len);
	if (params->bssid)
		memcpy(&join_params.params.bssid, params->bssid,
			ETHER_ADDR_LEN);
	else
		memset(&join_params.params.bssid, 0, ETHER_ADDR_LEN);

	err = wldev_ioctl(dev, WLC_SET_SSID, &join_params,
		sizeof(join_params), false);
	if (unlikely(err)) {
		WL_ERR(("Error (%d)\n", err));
		return err;
	}
	return err;
}

static s32 wl_cfg80211_leave_ibss(struct wiphy *wiphy, struct net_device *dev)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	s32 err = 0;

	CHECK_SYS_UP(wl);
	wl_link_down(wl);

	return err;
}

static s32
wl_set_wpa_version(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_priv *wl = wlcfg_drv_priv;
	struct wl_security *sec;
	s32 val = 0;
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);

	if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_1)
		val = WPA_AUTH_PSK | WPA_AUTH_UNSPECIFIED;
	else if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_2)
		val = WPA2_AUTH_PSK| WPA2_AUTH_UNSPECIFIED;
	else
		val = WPA_AUTH_DISABLED;

	if (is_wps_conn(sme))
		val = WPA_AUTH_DISABLED;

	WL_DBG(("setting wpa_auth to 0x%0x\n", val));
	err = wldev_iovar_setint_bsscfg(dev, "wpa_auth", val, bssidx);
	if (unlikely(err)) {
		WL_ERR(("set wpa_auth failed (%d)\n", err));
		return err;
	}
	sec = wl_read_prof(wl, WL_PROF_SEC);
	sec->wpa_versions = sme->crypto.wpa_versions;
	return err;
}

static s32
wl_set_auth_type(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_priv *wl = wlcfg_drv_priv;
	struct wl_security *sec;
	s32 val = 0;
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);
	switch (sme->auth_type) {
	case NL80211_AUTHTYPE_OPEN_SYSTEM:
		val = 0;
		WL_DBG(("open system\n"));
		break;
	case NL80211_AUTHTYPE_SHARED_KEY:
		val = 1;
		WL_DBG(("shared key\n"));
		break;
	case NL80211_AUTHTYPE_AUTOMATIC:
		val = 2;
		WL_DBG(("automatic\n"));
		break;
	case NL80211_AUTHTYPE_NETWORK_EAP:
		WL_DBG(("network eap\n"));
	default:
		val = 2;
		WL_ERR(("invalid auth type (%d)\n", sme->auth_type));
		break;
	}

	err = wldev_iovar_setint_bsscfg(dev, "auth", val, bssidx);
	if (unlikely(err)) {
		WL_ERR(("set auth failed (%d)\n", err));
		return err;
	}
	sec = wl_read_prof(wl, WL_PROF_SEC);
	sec->auth_type = sme->auth_type;
	return err;
}

static s32
wl_set_set_cipher(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_priv *wl = wlcfg_drv_priv;
	struct wl_security *sec;
	s32 pval = 0;
	s32 gval = 0;
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);

	if (sme->crypto.n_ciphers_pairwise) {
		switch (sme->crypto.ciphers_pairwise[0]) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			pval = WEP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			pval = TKIP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			pval = AES_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			pval = AES_ENABLED;
			break;
		default:
			WL_ERR(("invalid cipher pairwise (%d)\n",
				sme->crypto.ciphers_pairwise[0]));
			return -EINVAL;
		}
	}
	if (sme->crypto.cipher_group) {
		switch (sme->crypto.cipher_group) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			gval = WEP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			gval = TKIP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			gval = AES_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			gval = AES_ENABLED;
			break;
		default:
			WL_ERR(("invalid cipher group (%d)\n",
				sme->crypto.cipher_group));
			return -EINVAL;
		}
	}

	WL_DBG(("pval (%d) gval (%d)\n", pval, gval));

	if (is_wps_conn(sme)) {
		err = wldev_iovar_setint_bsscfg(dev, "wsec", 4, bssidx);
	} else {
		WL_DBG((" NO, is_wps_conn, Set pval | gval to WSEC"));
		err = wldev_iovar_setint_bsscfg(dev, "wsec",
				pval | gval, bssidx);
	}
	if (unlikely(err)) {
		WL_ERR(("error (%d)\n", err));
		return err;
	}

	sec = wl_read_prof(wl, WL_PROF_SEC);
	sec->cipher_pairwise = sme->crypto.ciphers_pairwise[0];
	sec->cipher_group = sme->crypto.cipher_group;

	return err;
}

static s32
wl_set_key_mgmt(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_priv *wl = wlcfg_drv_priv;
	struct wl_security *sec;
	s32 val = 0;
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);

	if (sme->crypto.n_akm_suites) {
		err = wl_dev_intvar_get(dev, "wpa_auth", &val);
		if (unlikely(err)) {
			WL_ERR(("could not get wpa_auth (%d)\n", err));
			return err;
		}
		if (val & (WPA_AUTH_PSK | WPA_AUTH_UNSPECIFIED)) {
			switch (sme->crypto.akm_suites[0]) {
			case WLAN_AKM_SUITE_8021X:
				val = WPA_AUTH_UNSPECIFIED;
				break;
			case WLAN_AKM_SUITE_PSK:
				val = WPA_AUTH_PSK;
				break;
			default:
				WL_ERR(("invalid cipher group (%d)\n",
					sme->crypto.cipher_group));
				return -EINVAL;
			}
		} else if (val & (WPA2_AUTH_PSK | WPA2_AUTH_UNSPECIFIED)) {
			switch (sme->crypto.akm_suites[0]) {
			case WLAN_AKM_SUITE_8021X:
				val = WPA2_AUTH_UNSPECIFIED;
				break;
			case WLAN_AKM_SUITE_PSK:
				val = WPA2_AUTH_PSK;
				break;
			default:
				WL_ERR(("invalid cipher group (%d)\n",
					sme->crypto.cipher_group));
				return -EINVAL;
			}
		}
		WL_DBG(("setting wpa_auth to %d\n", val));

		err = wldev_iovar_setint_bsscfg(dev, "wpa_auth", val, bssidx);
		if (unlikely(err)) {
			WL_ERR(("could not set wpa_auth (%d)\n", err));
			return err;
		}
	}
	sec = wl_read_prof(wl, WL_PROF_SEC);
	sec->wpa_auth = sme->crypto.akm_suites[0];

	return err;
}

static s32
wl_set_set_sharedkey(struct net_device *dev,
	struct cfg80211_connect_params *sme)
{
	struct wl_priv *wl = wlcfg_drv_priv;
	struct wl_security *sec;
	struct wl_wsec_key key;
	s32 val;
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);

	WL_DBG(("key len (%d)\n", sme->key_len));
	if (sme->key_len) {
		sec = wl_read_prof(wl, WL_PROF_SEC);
		WL_DBG(("wpa_versions 0x%x cipher_pairwise 0x%x\n",
			sec->wpa_versions, sec->cipher_pairwise));
		if (!(sec->wpa_versions & (NL80211_WPA_VERSION_1 |
			NL80211_WPA_VERSION_2)) &&
			(sec->cipher_pairwise & (WLAN_CIPHER_SUITE_WEP40 |
			WLAN_CIPHER_SUITE_WEP104))) {
			memset(&key, 0, sizeof(key));
			key.len = (u32) sme->key_len;
			key.index = (u32) sme->key_idx;
			if (unlikely(key.len > sizeof(key.data))) {
				WL_ERR(("Too long key length (%u)\n", key.len));
				return -EINVAL;
			}
			memcpy(key.data, sme->key, key.len);
			key.flags = WL_PRIMARY_KEY;
			switch (sec->cipher_pairwise) {
			case WLAN_CIPHER_SUITE_WEP40:
				key.algo = CRYPTO_ALGO_WEP1;
				break;
			case WLAN_CIPHER_SUITE_WEP104:
				key.algo = CRYPTO_ALGO_WEP128;
				break;
			default:
				WL_ERR(("Invalid algorithm (%d)\n",
					sme->crypto.ciphers_pairwise[0]));
				return -EINVAL;
			}
			/* Set the new key/index */
			WL_DBG(("key length (%d) key index (%d) algo (%d)\n",
				key.len, key.index, key.algo));
			WL_DBG(("key \"%s\"\n", key.data));
			swap_key_from_BE(&key);
			err = wldev_iovar_setbuf_bsscfg(dev, "wsec_key", &key, sizeof(key),
				ioctlbuf, sizeof(ioctlbuf), bssidx);
			if (unlikely(err)) {
				WL_ERR(("WLC_SET_KEY error (%d)\n", err));
				return err;
			}
			if (sec->auth_type == NL80211_AUTHTYPE_OPEN_SYSTEM) {
				WL_DBG(("set auth_type to shared key\n"));
				val = 1;	/* shared key */
				err = wldev_iovar_setint_bsscfg(dev, "auth", val, bssidx);
				if (unlikely(err)) {
					WL_ERR(("set auth failed (%d)\n", err));
					return err;
				}
			}
		}
	}
	return err;
}

static s32
wl_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_connect_params *sme)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct ieee80211_channel *chan = sme->channel;
	wl_extjoin_params_t *ext_join_params;
	struct wl_join_params join_params;
	size_t join_params_size;
	s32 err = 0;
	wpa_ie_fixed_t *wpa_ie;
	wpa_ie_fixed_t *wps_ie;
	bcm_tlv_t *wpa2_ie;
	u8* wpaie  = 0;
	u32 wpaie_len = 0;
	u32 wpsie_len = 0;
	u32 chan_cnt = 0;
	u8 wpsie[IE_MAX_LEN];
	struct ether_addr bssid;

	WL_DBG(("In\n"));
	CHECK_SYS_UP(wl);

	/*
	 * Cancel ongoing scan to sync up with sme state machine of cfg80211.
	 */
	if (wl->scan_request) {
		wl_cfg80211_scan_abort(wl, dev);
	}
	/* Clean BSSID */
	bzero(&bssid, sizeof(bssid));
	wl_update_prof(wl, NULL, (void *)&bssid, WL_PROF_BSSID);

	if (IS_P2P_SSID(sme->ssid) && (dev != wl_to_prmry_ndev(wl))) {
		/* we only allow to connect using virtual interface in case of P2P */
		if (p2p_on(wl) && is_wps_conn(sme)) {
			WL_DBG(("ASSOC1 p2p index : %d sme->ie_len %d\n",
				wl_cfgp2p_find_idx(wl, dev), sme->ie_len));
			/* Have to apply WPS IE + P2P IE in assoc req frame */
			wl_cfgp2p_set_management_ie(wl, dev,
				wl_cfgp2p_find_idx(wl, dev), VNDR_IE_PRBREQ_FLAG,
				wl_to_p2p_bss_saved_ie(wl, P2PAPI_BSSCFG_DEVICE).p2p_probe_req_ie,
				wl_to_p2p_bss_saved_ie(wl,
				P2PAPI_BSSCFG_DEVICE).p2p_probe_req_ie_len);
			wl_cfgp2p_set_management_ie(wl, dev, wl_cfgp2p_find_idx(wl, dev),
				VNDR_IE_ASSOCREQ_FLAG, sme->ie, sme->ie_len);
		} else if (p2p_on(wl) && (sme->crypto.wpa_versions & NL80211_WPA_VERSION_2)) {
			/* This is the connect req after WPS is done [credentials exchanged]
			 * currently identified with WPA_VERSION_2 .
			 * Update the previously set IEs with
			 * the newly received IEs from Supplicant. This will remove the WPS IE from
			 * the Assoc Req.
			 */
			WL_DBG(("ASSOC2 p2p index : %d sme->ie_len %d\n",
				wl_cfgp2p_find_idx(wl, dev), sme->ie_len));
			wl_cfgp2p_set_management_ie(wl, dev, wl_cfgp2p_find_idx(wl, dev),
				VNDR_IE_ASSOCREQ_FLAG, sme->ie, sme->ie_len);
		}

	} else if (dev == wl_to_prmry_ndev(wl)) {
			/* find the RSN_IE */
			if ((wpa2_ie = bcm_parse_tlvs((u8 *)sme->ie, sme->ie_len,
				DOT11_MNG_RSN_ID)) != NULL) {
				WL_DBG((" WPA2 IE is found\n"));
			}
			/* find the WPA_IE */
			if ((wpa_ie = wl_cfgp2p_find_wpaie((u8 *)sme->ie,
				sme->ie_len)) != NULL) {
				WL_DBG((" WPA IE is found\n"));
			}
			if (wpa_ie != NULL || wpa2_ie != NULL) {
				wpaie = (wpa_ie != NULL) ? (u8 *)wpa_ie : (u8 *)wpa2_ie;
				wpaie_len = (wpa_ie != NULL) ? wpa_ie->length : wpa2_ie->len;
				wpaie_len += WPA_RSN_IE_TAG_FIXED_LEN;
				wldev_iovar_setbuf(dev, "wpaie", wpaie, wpaie_len,
				ioctlbuf, sizeof(ioctlbuf));
			} else {
				wldev_iovar_setbuf(dev, "wpaie", NULL, 0,
				ioctlbuf, sizeof(ioctlbuf));
			}

			/* find the WPSIE */
			memset(wpsie, 0, sizeof(wpsie));
			if ((wps_ie = wl_cfgp2p_find_wpsie((u8 *)sme->ie,
				sme->ie_len)) != NULL) {
				wpsie_len = wps_ie->length +WPA_RSN_IE_TAG_FIXED_LEN;
				memcpy(wpsie, wps_ie, wpsie_len);
			} else {
				wpsie_len = 0;
			}
			err = wl_cfgp2p_set_management_ie(wl, dev, -1,
				VNDR_IE_ASSOCREQ_FLAG, wpsie, wpsie_len);
			if (unlikely(err)) {
				return err;
			}
	}
	if (unlikely(!sme->ssid)) {
		WL_ERR(("Invalid ssid\n"));
		return -EOPNOTSUPP;
	}
	if (chan) {
		wl->channel = ieee80211_frequency_to_channel(chan->center_freq);
		chan_cnt = 1;
		WL_DBG(("channel (%d), center_req (%d)\n", wl->channel,
			chan->center_freq));
	} else
		wl->channel = 0;
	WL_DBG(("ie (%p), ie_len (%zd)\n", sme->ie, sme->ie_len));
	err = wl_set_wpa_version(dev, sme);
	if (unlikely(err)) {
		WL_ERR(("Invalid wpa_version\n"));
		return err;
	}

	err = wl_set_auth_type(dev, sme);
	if (unlikely(err)) {
		WL_ERR(("Invalid auth type\n"));
		return err;
	}

	err = wl_set_set_cipher(dev, sme);
	if (unlikely(err)) {
		WL_ERR(("Invalid ciper\n"));
		return err;
	}

	err = wl_set_key_mgmt(dev, sme);
	if (unlikely(err)) {
		WL_ERR(("Invalid key mgmt\n"));
		return err;
	}

	err = wl_set_set_sharedkey(dev, sme);
	if (unlikely(err)) {
		WL_ERR(("Invalid shared key\n"));
		return err;
	}

	/*
	 *  Join with specific BSSID and cached SSID
	 *  If SSID is zero join based on BSSID only
	 */
	join_params_size = WL_EXTJOIN_PARAMS_FIXED_SIZE +
		chan_cnt * sizeof(chanspec_t);
	ext_join_params =  (wl_extjoin_params_t*)kzalloc(join_params_size, GFP_KERNEL);
	if (ext_join_params == NULL) {
		err = -ENOMEM;
		wl_clr_drv_status(wl, CONNECTING);
		goto exit;
	}
	ext_join_params->ssid.SSID_len = min(sizeof(ext_join_params->ssid.SSID), sme->ssid_len);
	memcpy(&ext_join_params->ssid.SSID, sme->ssid, ext_join_params->ssid.SSID_len);
	ext_join_params->ssid.SSID_len = htod32(ext_join_params->ssid.SSID_len);
	/* Set up join scan parameters */
	ext_join_params->scan.scan_type = -1;
	ext_join_params->scan.nprobes = 2;
	/* increate dwell time to receive probe response
	* from target AP at a noisy air
	*/
	ext_join_params->scan.active_time = 150;
	ext_join_params->scan.passive_time = 300;
	ext_join_params->scan.home_time = -1;
	if (sme->bssid)
		memcpy(&ext_join_params->assoc.bssid, sme->bssid, ETH_ALEN);
	else
		memcpy(&ext_join_params->assoc.bssid, &ether_bcast, ETH_ALEN);
	ext_join_params->assoc.chanspec_num = chan_cnt;
	if (chan_cnt) {
		u16 channel, band, bw, ctl_sb;
		chanspec_t chspec;
		channel = wl->channel;
		band = (channel <= CH_MAX_2G_CHANNEL) ? WL_CHANSPEC_BAND_2G
			: WL_CHANSPEC_BAND_5G;
		bw = WL_CHANSPEC_BW_20;
		ctl_sb = WL_CHANSPEC_CTL_SB_NONE;
		chspec = (channel | band | bw | ctl_sb);
		ext_join_params->assoc.chanspec_list[0]  &= WL_CHANSPEC_CHAN_MASK;
		ext_join_params->assoc.chanspec_list[0] |= chspec;
		ext_join_params->assoc.chanspec_list[0] =
			htodchanspec(ext_join_params->assoc.chanspec_list[0]);
	}
	ext_join_params->assoc.chanspec_num = htod32(ext_join_params->assoc.chanspec_num);
	if (ext_join_params->ssid.SSID_len < IEEE80211_MAX_SSID_LEN) {
		WL_INFO(("ssid \"%s\", len (%d)\n", ext_join_params->ssid.SSID,
			ext_join_params->ssid.SSID_len));
	}
	wl_set_drv_status(wl, CONNECTING);
	err = wldev_iovar_setbuf_bsscfg(dev, "join", ext_join_params, join_params_size, ioctlbuf,
		sizeof(ioctlbuf), wl_cfgp2p_find_idx(wl, dev));
	kfree(ext_join_params);
	if (err) {
		wl_clr_drv_status(wl, CONNECTING);
		if (err == BCME_UNSUPPORTED) {
			WL_DBG(("join iovar is not supported\n"));
			goto set_ssid;
		} else
			WL_ERR(("error (%d)\n", err));
	} else
		goto exit;

set_ssid:
	memset(&join_params, 0, sizeof(join_params));
	join_params_size = sizeof(join_params.ssid);

	join_params.ssid.SSID_len = min(sizeof(join_params.ssid.SSID), sme->ssid_len);
	memcpy(&join_params.ssid.SSID, sme->ssid, join_params.ssid.SSID_len);
	join_params.ssid.SSID_len = htod32(join_params.ssid.SSID_len);
	wl_update_prof(wl, NULL, &join_params.ssid, WL_PROF_SSID);
	if (sme->bssid)
		memcpy(&join_params.params.bssid, sme->bssid, ETH_ALEN);
	else
		memcpy(&join_params.params.bssid, &ether_bcast, ETH_ALEN);

	wl_ch_to_chanspec(wl->channel, &join_params, &join_params_size);
	WL_DBG(("join_param_size %d\n", join_params_size));

	if (join_params.ssid.SSID_len < IEEE80211_MAX_SSID_LEN) {
		WL_INFO(("ssid \"%s\", len (%d)\n", join_params.ssid.SSID,
			join_params.ssid.SSID_len));
	}
	wl_set_drv_status(wl, CONNECTING);
	err = wldev_ioctl(dev, WLC_SET_SSID, &join_params, join_params_size, true);
	if (err) {
		WL_ERR(("error (%d)\n", err));
		wl_clr_drv_status(wl, CONNECTING);
	}
exit:
	return err;
}

static s32
wl_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev,
	u16 reason_code)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	scb_val_t scbval;
	bool act = false;
	s32 err = 0;
	u8 *curbssid;
	WL_ERR(("Reason %d\n", reason_code));
	CHECK_SYS_UP(wl);
	act = *(bool *) wl_read_prof(wl, WL_PROF_ACT);
	curbssid = wl_read_prof(wl, WL_PROF_BSSID);
	if (likely(act)) {
		/*
		* Cancel ongoing scan to sync up with sme state machine of cfg80211.
		*/
		if (wl->scan_request) {
			wl_cfg80211_scan_abort(wl, dev);
		}
		wl_set_drv_status(wl, DISCONNECTING);
		scbval.val = reason_code;
		memcpy(&scbval.ea, curbssid, ETHER_ADDR_LEN);
		scbval.val = htod32(scbval.val);
		err = wldev_ioctl(dev, WLC_DISASSOC, &scbval,
			sizeof(scb_val_t), true);
		if (unlikely(err)) {
			wl_clr_drv_status(wl, DISCONNECTING);
			WL_ERR(("error (%d)\n", err));
			return err;
		}
	}

	return err;
}

static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy,
	enum nl80211_tx_power_setting type, s32 dbm)
{

	struct wl_priv *wl = wiphy_priv(wiphy);
	struct net_device *ndev = wl_to_prmry_ndev(wl);
	u16 txpwrmw;
	s32 err = 0;
	s32 disable = 0;

	CHECK_SYS_UP(wl);
	switch (type) {
	case NL80211_TX_POWER_AUTOMATIC:
		break;
	case NL80211_TX_POWER_LIMITED:
		if (dbm < 0) {
			WL_ERR(("TX_POWER_LIMITTED - dbm is negative\n"));
			return -EINVAL;
		}
		break;
	case NL80211_TX_POWER_FIXED:
		if (dbm < 0) {
			WL_ERR(("TX_POWER_FIXED - dbm is negative..\n"));
			return -EINVAL;
		}
		break;
	}
	/* Make sure radio is off or on as far as software is concerned */
	disable = WL_RADIO_SW_DISABLE << 16;
	disable = htod32(disable);
	err = wldev_ioctl(ndev, WLC_SET_RADIO, &disable, sizeof(disable), true);
	if (unlikely(err)) {
		WL_ERR(("WLC_SET_RADIO error (%d)\n", err));
		return err;
	}

	if (dbm > 0xffff)
		txpwrmw = 0xffff;
	else
		txpwrmw = (u16) dbm;
	err = wl_dev_intvar_set(ndev, "qtxpower",
		(s32) (bcm_mw_to_qdbm(txpwrmw)));
	if (unlikely(err)) {
		WL_ERR(("qtxpower error (%d)\n", err));
		return err;
	}
	wl->conf->tx_power = dbm;

	return err;
}

static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, s32 *dbm)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct net_device *ndev = wl_to_prmry_ndev(wl);
	s32 txpwrdbm;
	u8 result;
	s32 err = 0;

	CHECK_SYS_UP(wl);
	err = wl_dev_intvar_get(ndev, "qtxpower", &txpwrdbm);
	if (unlikely(err)) {
		WL_ERR(("error (%d)\n", err));
		return err;
	}
	result = (u8) (txpwrdbm & ~WL_TXPWR_OVERRIDE);
	*dbm = (s32) bcm_qdbm_to_mw(result);

	return err;
}

static s32
wl_cfg80211_config_default_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool unicast, bool multicast)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	u32 index;
	s32 wsec;
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);

	WL_DBG(("key index (%d)\n", key_idx));
	CHECK_SYS_UP(wl);
	err = wldev_iovar_getint_bsscfg(dev, "wsec", &wsec, bssidx);
	if (unlikely(err)) {
		WL_ERR(("WLC_GET_WSEC error (%d)\n", err));
		return err;
	}
	if (wsec & WEP_ENABLED) {
		/* Just select a new current key */
		index = (u32) key_idx;
		index = htod32(index);
		err = wldev_ioctl(dev, WLC_SET_KEY_PRIMARY, &index,
			sizeof(index), true);
		if (unlikely(err)) {
			WL_ERR(("error (%d)\n", err));
		}
	}
	return err;
}

static s32
wl_add_keyext(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, const u8 *mac_addr, struct key_params *params)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct wl_wsec_key key;
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);
	s32 mode = get_mode_by_netdev(wl, dev);
	memset(&key, 0, sizeof(key));
	key.index = (u32) key_idx;

	if (!ETHER_ISMULTI(mac_addr))
		memcpy((char *)&key.ea, (void *)mac_addr, ETHER_ADDR_LEN);
	key.len = (u32) params->key_len;

	/* check for key index change */
	if (key.len == 0) {
		/* key delete */
		swap_key_from_BE(&key);
		wldev_iovar_setbuf_bsscfg(dev, "wsec_key", &key, sizeof(key), ioctlbuf,
			sizeof(ioctlbuf), bssidx);
		if (unlikely(err)) {
			WL_ERR(("key delete error (%d)\n", err));
			return err;
		}
	} else {
		if (key.len > sizeof(key.data)) {
			WL_ERR(("Invalid key length (%d)\n", key.len));
			return -EINVAL;
		}
		WL_DBG(("Setting the key index %d\n", key.index));
		memcpy(key.data, params->key, key.len);

		if ((mode == WL_MODE_BSS) &&
			(params->cipher == WLAN_CIPHER_SUITE_TKIP)) {
			u8 keybuf[8];
			memcpy(keybuf, &key.data[24], sizeof(keybuf));
			memcpy(&key.data[24], &key.data[16], sizeof(keybuf));
			memcpy(&key.data[16], keybuf, sizeof(keybuf));
		}

		/* if IW_ENCODE_EXT_RX_SEQ_VALID set */
		if (params->seq && params->seq_len == 6) {
			/* rx iv */
			u8 *ivptr;
			ivptr = (u8 *) params->seq;
			key.rxiv.hi = (ivptr[5] << 24) | (ivptr[4] << 16) |
				(ivptr[3] << 8) | ivptr[2];
			key.rxiv.lo = (ivptr[1] << 8) | ivptr[0];
			key.iv_initialized = true;
		}

		switch (params->cipher) {
		case WLAN_CIPHER_SUITE_WEP40:
			key.algo = CRYPTO_ALGO_WEP1;
			WL_DBG(("WLAN_CIPHER_SUITE_WEP40\n"));
			break;
		case WLAN_CIPHER_SUITE_WEP104:
			key.algo = CRYPTO_ALGO_WEP128;
			WL_DBG(("WLAN_CIPHER_SUITE_WEP104\n"));
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			key.algo = CRYPTO_ALGO_TKIP;
			WL_DBG(("WLAN_CIPHER_SUITE_TKIP\n"));
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			key.algo = CRYPTO_ALGO_AES_CCM;
			WL_DBG(("WLAN_CIPHER_SUITE_AES_CMAC\n"));
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			key.algo = CRYPTO_ALGO_AES_CCM;
			WL_DBG(("WLAN_CIPHER_SUITE_CCMP\n"));
			break;
		default:
			WL_ERR(("Invalid cipher (0x%x)\n", params->cipher));
			return -EINVAL;
		}
		swap_key_from_BE(&key);
#ifdef CONFIG_WIRELESS_EXT
		dhd_wait_pend8021x(dev);
#endif
		wldev_iovar_setbuf_bsscfg(dev, "wsec_key", &key, sizeof(key), ioctlbuf,
			sizeof(ioctlbuf), bssidx);
		if (unlikely(err)) {
			WL_ERR(("WLC_SET_KEY error (%d)\n", err));
			return err;
		}
	}
	return err;
}

static s32
wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr,
	struct key_params *params)
{
	struct wl_wsec_key key;
	s32 val = 0;
	s32 wsec = 0;
	s32 err = 0;
	u8 keybuf[8];
	s32 bssidx = 0;
	struct wl_priv *wl = wiphy_priv(wiphy);
	s32 mode = get_mode_by_netdev(wl, dev);
	WL_DBG(("key index (%d)\n", key_idx));
	CHECK_SYS_UP(wl);

	bssidx = wl_cfgp2p_find_idx(wl, dev);

	if (mac_addr) {
		wl_add_keyext(wiphy, dev, key_idx, mac_addr, params);
		goto exit;
	}
	memset(&key, 0, sizeof(key));

	key.len = (u32) params->key_len;
	key.index = (u32) key_idx;

	if (unlikely(key.len > sizeof(key.data))) {
		WL_ERR(("Too long key length (%u)\n", key.len));
		return -EINVAL;
	}
	memcpy(key.data, params->key, key.len);

	key.flags = WL_PRIMARY_KEY;
	switch (params->cipher) {
	case WLAN_CIPHER_SUITE_WEP40:
		key.algo = CRYPTO_ALGO_WEP1;
		val = WEP_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_WEP40\n"));
		break;
	case WLAN_CIPHER_SUITE_WEP104:
		key.algo = CRYPTO_ALGO_WEP128;
		val = WEP_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_WEP104\n"));
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		key.algo = CRYPTO_ALGO_TKIP;
		val = TKIP_ENABLED;
		/* wpa_supplicant switches the third and fourth quarters of the TKIP key */
		if (mode == WL_MODE_BSS) {
			bcopy(&key.data[24], keybuf, sizeof(keybuf));
			bcopy(&key.data[16], &key.data[24], sizeof(keybuf));
			bcopy(keybuf, &key.data[16], sizeof(keybuf));
		}
		WL_DBG(("WLAN_CIPHER_SUITE_TKIP\n"));
		break;
	case WLAN_CIPHER_SUITE_AES_CMAC:
		key.algo = CRYPTO_ALGO_AES_CCM;
		val = AES_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_AES_CMAC\n"));
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		key.algo = CRYPTO_ALGO_AES_CCM;
		val = AES_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_CCMP\n"));
		break;
	default:
		WL_ERR(("Invalid cipher (0x%x)\n", params->cipher));
		return -EINVAL;
	}

	/* Set the new key/index */
	swap_key_from_BE(&key);
	err = wldev_iovar_setbuf_bsscfg(dev, "wsec_key", &key, sizeof(key), ioctlbuf,
		sizeof(ioctlbuf), bssidx);
	if (unlikely(err)) {
		WL_ERR(("WLC_SET_KEY error (%d)\n", err));
		return err;
	}

exit:
	err = wldev_iovar_getint_bsscfg(dev, "wsec", &wsec, bssidx);
	if (unlikely(err)) {
		WL_ERR(("get wsec error (%d)\n", err));
		return err;
	}

	wsec |= val;
	err = wldev_iovar_setint_bsscfg(dev, "wsec", wsec, bssidx);
	if (unlikely(err)) {
		WL_ERR(("set wsec error (%d)\n", err));
		return err;
	}

	return err;
}

static s32
wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr)
{
	struct wl_wsec_key key;
	struct wl_priv *wl = wiphy_priv(wiphy);
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);

	WL_DBG(("Enter\n"));
	CHECK_SYS_UP(wl);
	memset(&key, 0, sizeof(key));

	key.index = (u32) key_idx;
	key.flags = WL_PRIMARY_KEY;
	key.algo = CRYPTO_ALGO_OFF;

	WL_DBG(("key index (%d)\n", key_idx));
	/* Set the new key/index */
	swap_key_from_BE(&key);
	wldev_iovar_setbuf_bsscfg(dev, "wsec_key", &key, sizeof(key), ioctlbuf,
		sizeof(ioctlbuf), bssidx);
	if (unlikely(err)) {
		if (err == -EINVAL) {
			if (key.index >= DOT11_MAX_DEFAULT_KEYS) {
				/* we ignore this key index in this case */
				WL_DBG(("invalid key index (%d)\n", key_idx));
			}
		} else {
			WL_ERR(("WLC_SET_KEY error (%d)\n", err));
		}
		return err;
	}
	return err;
}

static s32
wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
	u8 key_idx, bool pairwise, const u8 *mac_addr, void *cookie,
	void (*callback) (void *cookie, struct key_params * params))
{
	struct key_params params;
	struct wl_wsec_key key;
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct wl_security *sec;
	s32 wsec;
	s32 err = 0;
	s32 bssidx = wl_cfgp2p_find_idx(wl, dev);

	WL_DBG(("key index (%d)\n", key_idx));
	CHECK_SYS_UP(wl);
	memset(&key, 0, sizeof(key));
	key.index = key_idx;
	swap_key_to_BE(&key);
	memset(&params, 0, sizeof(params));
	params.key_len = (u8) min_t(u8, DOT11_MAX_KEY_SIZE, key.len);
	memcpy(params.key, key.data, params.key_len);

	wldev_iovar_getint_bsscfg(dev, "wsec", &wsec, bssidx);
	if (unlikely(err)) {
		WL_ERR(("WLC_GET_WSEC error (%d)\n", err));
		return err;
	}
	switch (wsec & ~SES_OW_ENABLED) {
		case WEP_ENABLED:
			sec = wl_read_prof(wl, WL_PROF_SEC);
			if (sec->cipher_pairwise & WLAN_CIPHER_SUITE_WEP40) {
				params.cipher = WLAN_CIPHER_SUITE_WEP40;
				WL_DBG(("WLAN_CIPHER_SUITE_WEP40\n"));
			} else if (sec->cipher_pairwise & WLAN_CIPHER_SUITE_WEP104) {
				params.cipher = WLAN_CIPHER_SUITE_WEP104;
				WL_DBG(("WLAN_CIPHER_SUITE_WEP104\n"));
			}
			break;
		case TKIP_ENABLED:
			params.cipher = WLAN_CIPHER_SUITE_TKIP;
			WL_DBG(("WLAN_CIPHER_SUITE_TKIP\n"));
			break;
		case AES_ENABLED:
			params.cipher = WLAN_CIPHER_SUITE_AES_CMAC;
			WL_DBG(("WLAN_CIPHER_SUITE_AES_CMAC\n"));
			break;
		default:
			WL_ERR(("Invalid algo (0x%x)\n", wsec));
			return -EINVAL;
	}

	callback(cookie, &params);
	return err;
}

static s32
wl_cfg80211_config_default_mgmt_key(struct wiphy *wiphy,
	struct net_device *dev, u8 key_idx)
{
	WL_INFO(("Not supported\n"));
	return -EOPNOTSUPP;
}

static s32
wl_cfg80211_get_station(struct wiphy *wiphy, struct net_device *dev,
	u8 *mac, struct station_info *sinfo)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	scb_val_t scb_val;
	s32 rssi;
	s32 rate;
	s32 err = 0;
	sta_info_t *sta;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	s8 eabuf[ETHER_ADDR_STR_LEN];
#endif
	dhd_pub_t *dhd =  (dhd_pub_t *)(wl->pub);

	CHECK_SYS_UP(wl);
	if (get_mode_by_netdev(wl, dev) == WL_MODE_AP) {
		err = wldev_iovar_getbuf(dev, "sta_info", (struct ether_addr *)mac,
			ETHER_ADDR_LEN, ioctlbuf, sizeof(ioctlbuf));
		if (err < 0) {
			WL_ERR(("GET STA INFO failed, %d\n", err));
			return err;
		}
		sinfo->filled = STATION_INFO_INACTIVE_TIME;
		sta = (sta_info_t *)ioctlbuf;
		sta->len = dtoh16(sta->len);
		sta->cap = dtoh16(sta->cap);
		sta->flags = dtoh32(sta->flags);
		sta->idle = dtoh32(sta->idle);
		sta->in = dtoh32(sta->in);
		sinfo->inactive_time = sta->idle * 1000;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
		if (sta->flags & WL_STA_ASSOC) {
			sinfo->filled |= STATION_INFO_CONNECTED_TIME;
			sinfo->connected_time = sta->in;
		}
		WL_INFO(("STA %s : idle time : %d sec, connected time :%d ms\n",
			bcm_ether_ntoa((const struct ether_addr *)mac, eabuf), sinfo->inactive_time,
			sta->idle * 1000));
#endif
	} else if (get_mode_by_netdev(wl, dev) == WL_MODE_BSS) {
			u8 *curmacp = wl_read_prof(wl, WL_PROF_BSSID);

			if (!wl_get_drv_status(wl, CONNECTED) ||
			    (dhd_is_associated(dhd, NULL) == FALSE)) {
				WL_ERR(("NOT assoc\n"));
				err = -ENODEV;
				goto get_station_err;
			}
			if (memcmp(mac, curmacp, ETHER_ADDR_LEN)) {
				WL_ERR(("Wrong Mac address: "MACSTR" != "MACSTR"\n",
					MAC2STR(mac), MAC2STR(curmacp)));
			}

			/* Report the current tx rate */
			err = wldev_ioctl(dev, WLC_GET_RATE, &rate, sizeof(rate), false);
			if (err) {
				WL_ERR(("Could not get rate (%d)\n", err));
			} else {
				rate = dtoh32(rate);
				sinfo->filled |= STATION_INFO_TX_BITRATE;
				sinfo->txrate.legacy = rate * 5;
				WL_DBG(("Rate %d Mbps\n", (rate / 2)));
			}

			memset(&scb_val, 0, sizeof(scb_val));
			scb_val.val = 0;
			err = wldev_ioctl(dev, WLC_GET_RSSI, &scb_val,
					sizeof(scb_val_t), false);
			if (err) {
				WL_ERR(("Could not get rssi (%d)\n", err));
				goto get_station_err;
			}

			rssi = dtoh32(scb_val.val);
			sinfo->filled |= STATION_INFO_SIGNAL;
			sinfo->signal = rssi;
			WL_DBG(("RSSI %d dBm\n", rssi));

get_station_err:
		if (err) {
			/* Disconnect due to zero BSSID or error to get RSSI */
			WL_ERR(("force cfg80211_disconnected\n"));
			wl_clr_drv_status(wl, CONNECTED);
			cfg80211_disconnected(dev, 0, NULL, 0, GFP_KERNEL);
			wl_link_down(wl);
		}
	}

	return err;
}

static s32
wl_cfg80211_set_power_mgmt(struct wiphy *wiphy, struct net_device *dev,
	bool enabled, s32 timeout)
{
	s32 pm;
	s32 err = 0;
	struct wl_priv *wl = wiphy_priv(wiphy);

	CHECK_SYS_UP(wl);
	pm = enabled ? PM_FAST : PM_OFF;
	/* Do not enable the power save after assoc if it is p2p interface */
	if (wl->p2p && wl->p2p->vif_created) {
		WL_DBG(("Do not enable the power save for p2p interfaces even after assoc\n"));
		pm = PM_OFF;
	}
	pm = htod32(pm);
	WL_DBG(("power save %s\n", (pm ? "enabled" : "disabled")));
	err = wldev_ioctl(dev, WLC_SET_PM, &pm, sizeof(pm), true);
	if (unlikely(err)) {
		if (err == -ENODEV)
			WL_DBG(("net_device is not ready yet\n"));
		else
			WL_ERR(("error (%d)\n", err));
		return err;
	}
	return err;
}

static __used u32 wl_find_msb(u16 bit16)
{
	u32 ret = 0;

	if (bit16 & 0xff00) {
		ret += 8;
		bit16 >>= 8;
	}

	if (bit16 & 0xf0) {
		ret += 4;
		bit16 >>= 4;
	}

	if (bit16 & 0xc) {
		ret += 2;
		bit16 >>= 2;
	}

	if (bit16 & 2)
		ret += bit16 & 2;
	else if (bit16)
		ret += bit16;

	return ret;
}

static s32 wl_cfg80211_resume(struct wiphy *wiphy)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	s32 err = 0;

	if (unlikely(!wl_get_drv_status(wl, READY))) {
		WL_INFO(("device is not ready : status (%d)\n",
			(int)wl->status));
		return 0;
	}

	wl_invoke_iscan(wl);

	return err;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39)
static s32 wl_cfg80211_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wow)
#else
static s32 wl_cfg80211_suspend(struct wiphy *wiphy)
#endif
{
#ifdef DHD_CLEAR_ON_SUSPEND
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct net_device *ndev = wl_to_prmry_ndev(wl);
	unsigned long flags;

	if (unlikely(!wl_get_drv_status(wl, READY))) {
		WL_INFO(("device is not ready : status (%d)\n",
			(int)wl->status));
		return 0;
	}

	wl_set_drv_status(wl, SCAN_ABORTING);
	wl_term_iscan(wl);
	flags = dhd_os_spin_lock((dhd_pub_t *)(wl->pub));
	if (wl->scan_request) {
		cfg80211_scan_done(wl->scan_request, true);
		wl->scan_request = NULL;
	}
	wl_clr_drv_status(wl, SCANNING);
	wl_clr_drv_status(wl, SCAN_ABORTING);
	dhd_os_spin_unlock((dhd_pub_t *)(wl->pub), flags);
	if (wl_get_drv_status(wl, CONNECTING)) {
		wl_bss_connect_done(wl, ndev, NULL, NULL, false);
	}
#endif
	return 0;
}

static __used s32
wl_update_pmklist(struct net_device *dev, struct wl_pmk_list *pmk_list,
	s32 err)
{
	int i, j;
	struct wl_priv *wl = wlcfg_drv_priv;
	struct net_device *primary_dev = wl_to_prmry_ndev(wl);

	/* Firmware is supporting pmk list only for STA interface i.e. primary interface
	  * Refer code wlc_bsscfg.c->wlc_bsscfg_sta_init
	  * Do we really need to support PMK cache in P2P in firmware?
	*/
	if (primary_dev != dev) {
		WL_INFO(("Not supporting Flushing pmklist on virtual"
			" interfaces than primary interface\n"));
		return err;
	}

	WL_DBG(("No of elements %d\n", pmk_list->pmkids.npmkid));
	for (i = 0; i < pmk_list->pmkids.npmkid; i++) {
		WL_DBG(("PMKID[%d]: %pM =\n", i,
			&pmk_list->pmkids.pmkid[i].BSSID));
		for (j = 0; j < WPA2_PMKID_LEN; j++) {
			WL_DBG(("%02x\n", pmk_list->pmkids.pmkid[i].PMKID[j]));
		}
	}
	if (likely(!err)) {
		err = wl_dev_bufvar_set(dev, "pmkid_info", (char *)pmk_list,
			sizeof(*pmk_list));
	}

	return err;
}

static s32
wl_cfg80211_set_pmksa(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_pmksa *pmksa)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	s32 err = 0;
	int i;

	CHECK_SYS_UP(wl);
	for (i = 0; i < wl->pmk_list->pmkids.npmkid; i++)
		if (!memcmp(pmksa->bssid, &wl->pmk_list->pmkids.pmkid[i].BSSID,
			ETHER_ADDR_LEN))
			break;
	if (i < WL_NUM_PMKIDS_MAX) {
		memcpy(&wl->pmk_list->pmkids.pmkid[i].BSSID, pmksa->bssid,
			ETHER_ADDR_LEN);
		memcpy(&wl->pmk_list->pmkids.pmkid[i].PMKID, pmksa->pmkid,
			WPA2_PMKID_LEN);
		if (i == wl->pmk_list->pmkids.npmkid)
			wl->pmk_list->pmkids.npmkid++;
	} else {
		err = -EINVAL;
	}
	WL_DBG(("set_pmksa,IW_PMKSA_ADD - PMKID: %pM =\n",
		&wl->pmk_list->pmkids.pmkid[wl->pmk_list->pmkids.npmkid - 1].BSSID));
	for (i = 0; i < WPA2_PMKID_LEN; i++) {
		WL_DBG(("%02x\n",
			wl->pmk_list->pmkids.pmkid[wl->pmk_list->pmkids.npmkid - 1].
			PMKID[i]));
	}

	err = wl_update_pmklist(dev, wl->pmk_list, err);

	return err;
}

static s32
wl_cfg80211_del_pmksa(struct wiphy *wiphy, struct net_device *dev,
	struct cfg80211_pmksa *pmksa)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	struct _pmkid_list pmkid;
	s32 err = 0;
	int i;

	CHECK_SYS_UP(wl);
	memcpy(&pmkid.pmkid[0].BSSID, pmksa->bssid, ETHER_ADDR_LEN);
	memcpy(&pmkid.pmkid[0].PMKID, pmksa->pmkid, WPA2_PMKID_LEN);

	WL_DBG(("del_pmksa,IW_PMKSA_REMOVE - PMKID: %pM =\n",
		&pmkid.pmkid[0].BSSID));
	for (i = 0; i < WPA2_PMKID_LEN; i++) {
		WL_DBG(("%02x\n", pmkid.pmkid[0].PMKID[i]));
	}

	for (i = 0; i < wl->pmk_list->pmkids.npmkid; i++)
		if (!memcmp
		    (pmksa->bssid, &wl->pmk_list->pmkids.pmkid[i].BSSID,
		     ETHER_ADDR_LEN))
			break;

	if ((wl->pmk_list->pmkids.npmkid > 0) &&
		(i < wl->pmk_list->pmkids.npmkid)) {
		memset(&wl->pmk_list->pmkids.pmkid[i], 0, sizeof(pmkid_t));
		for (; i < (wl->pmk_list->pmkids.npmkid - 1); i++) {
			memcpy(&wl->pmk_list->pmkids.pmkid[i].BSSID,
				&wl->pmk_list->pmkids.pmkid[i + 1].BSSID,
				ETHER_ADDR_LEN);
			memcpy(&wl->pmk_list->pmkids.pmkid[i].PMKID,
				&wl->pmk_list->pmkids.pmkid[i + 1].PMKID,
				WPA2_PMKID_LEN);
		}
		wl->pmk_list->pmkids.npmkid--;
	} else {
		err = -EINVAL;
	}

	err = wl_update_pmklist(dev, wl->pmk_list, err);

	return err;

}

static s32
wl_cfg80211_flush_pmksa(struct wiphy *wiphy, struct net_device *dev)
{
	struct wl_priv *wl = wiphy_priv(wiphy);
	s32 err = 0;
	CHECK_SYS_UP(wl);
	memset(wl->pmk_list, 0, sizeof(*wl->pmk_list));
	err = wl_update_pmklist(dev, wl->pmk_list, err);
	return err;

}

wl_scan_params_t *
wl_cfg80211_scan_alloc_params(int channel, int nprobes, int *out_params_size)
{
	wl_scan_params_t *params;
	int params_size;
	int num_chans;

	*out_params_size = 0;

	/* Our scan params only need space for 1 channel and 0 ssids */
	params_size = WL_SCAN_PARAMS_FIXED_SIZE + 1 * sizeof(uint16);
	params = (wl_scan_params_t*) kzalloc(params_size, GFP_KERNEL);
	if (params == NULL) {
		WL_ERR(("%s: mem alloc failed (%d bytes)\n", __func__, params_size));
		return params;
	}
	memset(params, 0, params_size);
	params->nprobes = nprobes;

	num_chans = (channel == 0) ? 0 : 1;

	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->bss_type = DOT11_BSSTYPE_ANY;
	params->scan_type = DOT11_SCANTYPE_ACTIVE;
	params->nprobes = htod32(1);
	params->active_time = htod32(-1);
	params->passive_time = htod32(-1);
	params->home_time = htod32(10);
	params->channel_list[0] = htodchanspec(channel);

	/* Our scan params have 1 channel and 0 ssids */
	params->channel_num = htod32((0 << WL_SCAN_PARAMS_NSSID_SHIFT) |
	(num_chans & WL_SCAN_PARAMS_COUNT_MASK));

	*out_params_size = params_size;	/* rtn size to the caller */
	return params;
}

s32
wl_cfg80211_scan_abort(struct wl_priv *wl, struct net_device *ndev)
{
	wl_scan_params_t *params = NULL;
	s32 params_size = 0;
	s32 err = BCME_OK;
	unsigned long flags;

	WL_DBG(("Enter\n"));

	/* Our scan params only need space for 1 channel and 0 ssids */
	params = wl_cfg80211_scan_alloc_params(-1, 0, &params_size);
	if (params == NULL) {
		WL_ERR(("scan params allocation failed \n"));
		err = -ENOMEM;
	} else {
		/* Do a scan abort to stop the driver's scan engine */
		err = wldev_ioctl(ndev, WLC_SCAN, params, params_size, true);
		if (err < 0) {
			WL_ERR(("scan abort  failed \n"));
		}
	}
	del_timer_sync(&wl->scan_timeout);
	flags = dhd_os_spin_lock((dhd_pub_t *)(wl->pub));
	if (wl->scan_request) {
		cfg80211_scan_done(wl->scan_request, true);
		wl->scan_request = NULL;
	}
	wl_clr_drv_status(wl, SCANNING);
	dhd_os_spin_unlock((dhd_pub_t *)(wl->pub), flags);
	if (params)
		kfree(params);
	return err;
}

static s32
wl_cfg80211_remain_on_channel(struct wiphy *wiphy, struct net_device *dev,
	struct ieee80211_channel * channel,
	enum nl80211_channel_type channel_type,
	unsigned int duration, u64 *cookie)
{
	s32 target_channel;

	s32 err = BCME_OK;
	struct wl_priv *wl = wiphy_priv(wiphy);
	dhd_pub_t *dhd = (dhd_pub_t *)(wl->pub);
	WL_DBG(("Enter, netdev_ifidx: %d \n", dev->ifindex));
	if (likely(wl_get_drv_status(wl, SCANNING))) {
		wl_cfg80211_scan_abort(wl, dev);
	}

	target_channel = ieee80211_frequency_to_channel(channel->center_freq);
	memcpy(&wl->remain_on_chan, channel, sizeof(struct ieee80211_channel));
	wl->remain_on_chan_type = channel_type;
	wl->cache_cookie = *cookie;
	cfg80211_ready_on_channel(dev, *cookie, channel,
		channel_type, duration, GFP_KERNEL);
	if (!p2p_on(wl)) {
		wl_cfgp2p_generate_bss_mac(&dhd->mac, &wl->p2p->dev_addr, &wl->p2p->int_addr);

		/* In case of p2p_listen command, supplicant send remain_on_channel
		 * without turning on P2P
		 */

		p2p_on(wl) = true;
		err = wl_cfgp2p_enable_discovery(wl, dev, NULL, 0);

		if (unlikely(err)) {
			goto exit;
		}
	}
	if (p2p_on(wl))
		wl_cfgp2p_discover_listen(wl, target_channel, duration);


exit:
	return err;
}

static s32
wl_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy, struct net_device *dev,
	u64 cookie)
{
	s32 err = 0;
	WL_DBG((" enter ) netdev_ifidx: %d \n", dev->ifindex));
	return err;
}

static s32
wl_cfg80211_mgmt_tx(struct wiphy *wiphy, struct net_device *dev,
	struct ieee80211_channel *channel, bool offchan,
	enum nl80211_channel_type channel_type,
	bool channel_type_valid, unsigned int wait,
	const u8* buf, size_t len, u64 *cookie)
{
	wl_action_frame_t *action_frame;
	wl_af_params_t *af_params;
	wifi_p2p_ie_t *p2p_ie;
	wpa_ie_fixed_t *wps_ie;
	const struct ieee80211_mgmt *mgmt;
	struct wl_priv *wl = wiphy_priv(wiphy);
	dhd_pub_t *dhd = (dhd_pub_t *)(wl->pub);
	s32 err = BCME_OK;
	s32 bssidx = 0;
	u32 p2pie_len = 0;
	u32 wpsie_len = 0;
	u16 fc;
	bool ack = false;
	wifi_p2p_pub_act_frame_t *act_frm;
	WL_DBG(("Enter \n"));
	/* find bssidx based on ndev */
	bssidx = wl_cfgp2p_find_idx(wl, dev);
	/* cookie generation */
	*cookie = (unsigned long) buf;

	if (bssidx == -1) {

		WL_ERR(("Can not find the bssidx for dev( %p )\n", dev));
		return -ENODEV;
	}
	if (wl->p2p_supported && p2p_on(wl)) {
		wl_cfgp2p_generate_bss_mac(&dhd->mac, &wl->p2p->dev_addr, &wl->p2p->int_addr);
		/* Suspend P2P discovery search-listen to prevent it from changing the
		 * channel.
		 */
		if ((err = wl_cfgp2p_discover_enable_search(wl, false)) < 0) {
			WL_ERR(("Can not disable discovery mode\n"));
			return -EFAULT;
		}
	}

	mgmt = (const struct ieee80211_mgmt *) buf;
	fc = mgmt->frame_control;
	if (fc != IEEE80211_STYPE_ACTION) {
		if (fc == IEEE80211_STYPE_PROBE_RESP) {
			s32 ie_offset =  DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN;
			s32 ie_len = len - ie_offset;
			if ((p2p_ie = wl_cfgp2p_find_p2pie((u8 *)(buf + ie_offset), ie_len))
				!= NULL) {
				/* Total length of P2P Information Element */
				p2pie_len = p2p_ie->len + sizeof(p2p_ie->len) + sizeof(p2p_ie->id);
				/* Have to change p2p device address in dev_info attribute
				 * because Supplicant use primary eth0 address
				 */
			#ifdef ENABLE_DRIVER_CHANGE_IFADDR /* We are now doing this in supplicant */
				wl_cfg80211_change_ifaddr((u8 *)p2p_ie,
					&wl->p2p_dev_addr, P2P_SEID_DEV_INFO);
			#endif
			}
			if ((wps_ie = wl_cfgp2p_find_wpsie((u8 *)(buf + ie_offset), ie_len))
				!= NULL) {
				/* Order of Vendor IE is 1) WPS IE +
				 * 2) P2P IE created by supplicant
				 *  So, it is ok to find start address of WPS IE
				 *  to save IEs to firmware
				 */
				wpsie_len = wps_ie->length + sizeof(wps_ie->length) +
					sizeof(wps_ie->tag);
				wl_cfgp2p_set_management_ie(wl, dev, bssidx,
					VNDR_IE_PRBRSP_FLAG,
					(u8 *)wps_ie, wpsie_len + p2pie_len);
			}
		}
		cfg80211_mgmt_tx_status(dev, *cookie, buf, len, true, GFP_KERNEL);
		goto exit;
	} else {
	    /* Abort the dwell time of any previous off-channel action frame that may
	     * be still in effect.  Sending off-channel action frames relies on the
	     * driver's scan engine.  If a previous off-channel action frame tx is
	     * still in progress (including the dwell time), then this new action
	     * frame will not be sent out.
	     */
		wl_cfg80211_scan_abort(wl, dev);
	}
	af_params = (wl_af_params_t *) kzalloc(WL_WIFI_AF_PARAMS_SIZE, GFP_KERNEL);

	if (af_params == NULL)
	{
		WL_ERR(("unable to allocate frame\n"));
		return -ENOMEM;
	}

	action_frame = &af_params->action_frame;

	/* Add the packet Id */
	action_frame->packetId = (u32) action_frame;
	WL_DBG(("action frame %d\n", action_frame->packetId));
	/* Add BSSID */
	memcpy(&action_frame->da, &mgmt->da[0], ETHER_ADDR_LEN);
	memcpy(&af_params->BSSID, &mgmt->bssid[0], ETHER_ADDR_LEN);

	/* Add the length exepted for 802.11 header  */
	action_frame->len = len - DOT11_MGMT_HDR_LEN;
	WL_DBG(("action_frame->len: %d\n", action_frame->len));

	/* Add the channel */
	af_params->channel =
		ieee80211_frequency_to_channel(channel->center_freq);

	/* Add the dwell time
	 * Dwell time to stay off-channel to wait for a response action frame
	 * after transmitting an GO Negotiation action frame
	 */
	af_params->dwell_time = WL_DWELL_TIME;

	memcpy(action_frame->data, &buf[DOT11_MGMT_HDR_LEN], action_frame->len);

	act_frm = (wifi_p2p_pub_act_frame_t *) (action_frame->data);
	WL_DBG(("action_frame->len: %d chan %d category %d subtype %d\n",
		action_frame->len, af_params->channel,
		act_frm->category, act_frm->subtype));
	if (wl->p2p->vif_created) {
		/*
		 * To make sure to send successfully action frame, we have to turn off mpc
		 */
		if ((act_frm->subtype == P2P_PAF_GON_REQ)||
		  (act_frm->subtype == P2P_PAF_GON_RSP)) {
			wldev_iovar_setint(dev, "mpc", 0);
		} else if (act_frm->subtype == P2P_PAF_GON_CONF) {
			wldev_iovar_setint(dev, "mpc", 1);
		} else if (act_frm->subtype == P2P_PAF_DEVDIS_REQ) {
			af_params->dwell_time = WL_LONG_DWELL_TIME;
		}
	}

	ack = (wl_cfgp2p_tx_action_frame(wl, dev, af_params, bssidx)) ? false : true;
	cfg80211_mgmt_tx_status(dev, *cookie, buf, len, ack, GFP_KERNEL);

	kfree(af_params);
exit:
	return err;
}


static void
wl_cfg80211_mgmt_frame_register(struct wiphy *wiphy, struct net_device *dev,
	u16 frame_type, bool reg)
{

	WL_DBG(("%s: frame_type: %x, reg: %d\n", __func__, frame_type, reg));

	if (frame_type != (IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ))
		return;

	return;
}


static s32
wl_cfg80211_change_bss(struct wiphy *wiphy,
	struct net_device *dev,
	struct bss_parameters *params)
{
	if (params->use_cts_prot >= 0) {
	}

	if (params->use_short_preamble >= 0) {
	}

	if (params->use_short_slot_time >= 0) {
	}

	if (params->basic_rates) {
	}

	if (params->ap_isolate >= 0) {
	}

	if (params->ht_opmode >= 0) {
	}

	return 0;
}

static s32
wl_cfg80211_set_channel(struct wiphy *wiphy, struct net_device *dev,
	struct ieee80211_channel *chan,
	enum nl80211_channel_type channel_type)
{
	s32 channel;
	s32 err = BCME_OK;

	channel = ieee80211_frequency_to_channel(chan->center_freq);
	WL_DBG(("netdev_ifidx(%d), chan_type(%d) target channel(%d) \n",
		dev->ifindex, channel_type, channel));
	err = wldev_ioctl(dev, WLC_SET_CHANNEL, &channel, sizeof(channel), true);
	if (err < 0) {
		WL_ERR(("WLC_SET_CHANNEL error %d chip may not be supporting this channel\n", err));
	}
	return err;
}

static s32
wl_validate_wpa2ie(struct net_device *dev, bcm_tlv_t *wpa2ie, s32 bssidx)
{
	s32 len = 0;
	s32 err = BCME_OK;
	u16 auth = 0; /* d11 open authentication */
	u16 count;
	u32 wsec;
	u32 pval = 0;
	u32 gval = 0;
	u32 wpa_auth = 0;
	u8* tmp;
	wpa_suite_mcast_t *mcast;
	wpa_suite_ucast_t *ucast;
	wpa_suite_auth_key_mgmt_t *mgmt;
	if (wpa2ie == NULL)
		goto exit;

	WL_DBG(("Enter \n"));
	len =  wpa2ie->len;
	/* check the mcast cipher */
	mcast = (wpa_suite_mcast_t *)&wpa2ie->data[WPA2_VERSION_LEN];
	tmp = mcast->oui;
	switch (tmp[DOT11_OUI_LEN]) {
		case WPA_CIPHER_NONE:
			gval = 0;
			break;
		case WPA_CIPHER_WEP_40:
		case WPA_CIPHER_WEP_104:
			gval = WEP_ENABLED;
			break;
		case WPA_CIPHER_TKIP:
			gval = TKIP_ENABLED;
			break;
		case WPA_CIPHER_AES_CCM:
			gval = AES_ENABLED;
			break;
		default:
			WL_ERR(("No Security Info\n"));
			break;
	}
	len -= WPA_SUITE_LEN;
	/* check the unicast cipher */
	ucast = (wpa_suite_ucast_t *)&mcast[1];
	count = ltoh16_ua(&ucast->count);
	tmp = ucast->list[0].oui;
	switch (tmp[DOT11_OUI_LEN]) {
		case WPA_CIPHER_NONE:
			pval = 0;
			break;
		case WPA_CIPHER_WEP_40:
		case WPA_CIPHER_WEP_104:
			pval = WEP_ENABLED;
			break;
		case WPA_CIPHER_TKIP:
			pval = TKIP_ENABLED;
			break;
		case WPA_CIPHER_AES_CCM:
			pval = AES_ENABLED;
			break;
		default:
			WL_ERR(("No Security Info\n"));
	}
	/* FOR WPS , set SEC_OW_ENABLED */
	wsec = (pval | gval | SES_OW_ENABLED);
	/* check the AKM */
	mgmt = (wpa_suite_auth_key_mgmt_t *)&ucast->list[1];
	count = ltoh16_ua(&mgmt->count);
	tmp = (u8 *)&mgmt->list[0];
	switch (tmp[DOT11_OUI_LEN]) {
		case RSN_AKM_NONE:
			wpa_auth = WPA_AUTH_NONE;
			break;
		case RSN_AKM_UNSPECIFIED:
			wpa_auth = WPA2_AUTH_UNSPECIFIED;
			break;
		case RSN_AKM_PSK:
			wpa_auth = WPA2_AUTH_PSK;
			break;
		default:
			WL_ERR(("No Key Mgmt Info\n"));
	}
	/* set auth */
	err = wldev_iovar_setint_bsscfg(dev, "auth", auth, bssidx);
	if (err < 0) {
		WL_ERR(("auth error %d\n", err));
		return BCME_ERROR;
	}
	/* set wsec */
	err = wldev_iovar_setint_bsscfg(dev, "wsec", wsec, bssidx);
	if (err < 0) {
		WL_ERR(("wsec error %d\n", err));
		return BCME_ERROR;
	}
	/* set upper-layer auth */
	err = wldev_iovar_setint_bsscfg(dev, "wpa_auth", wpa_auth, bssidx);
	if (err < 0) {
		WL_ERR(("wpa_auth error %d\n", err));
		return BCME_ERROR;
	}
exit:
	return 0;
}

static s32
wl_validate_wpaie(struct net_device *dev, wpa_ie_fixed_t *wpaie, s32 bssidx)
{
	wpa_suite_mcast_t *mcast;
	wpa_suite_ucast_t *ucast;
	wpa_suite_auth_key_mgmt_t *mgmt;
	u16 auth = 0; /* d11 open authentication */
	u16 count;
	s32 err = BCME_OK;
	s32 len = 0;
	u32 i;
	u32 wsec;
	u32 pval = 0;
	u32 gval = 0;
	u32 wpa_auth = 0;
	u32 tmp = 0;

	if (wpaie == NULL)
		goto exit;
	WL_DBG(("Enter \n"));
	len = wpaie->length;    /* value length */
	len -= WPA_IE_TAG_FIXED_LEN;
	/* check for multicast cipher suite */
	if (len < WPA_SUITE_LEN) {
		WL_INFO(("no multicast cipher suite\n"));
		goto exit;
	}

	/* pick up multicast cipher */
	mcast = (wpa_suite_mcast_t *)&wpaie[1];
	len -= WPA_SUITE_LEN;
	if (!bcmp(mcast->oui, WPA_OUI, WPA_OUI_LEN)) {
		if (IS_WPA_CIPHER(mcast->type)) {
			tmp = 0;
			switch (mcast->type) {
				case WPA_CIPHER_NONE:
					tmp = 0;
					break;
				case WPA_CIPHER_WEP_40:
				case WPA_CIPHER_WEP_104:
					tmp = WEP_ENABLED;
					break;
				case WPA_CIPHER_TKIP:
					tmp = TKIP_ENABLED;
					break;
				case WPA_CIPHER_AES_CCM:
					tmp = AES_ENABLED;
					break;
				default:
					WL_ERR(("No Security Info\n"));
			}
			gval |= tmp;
		}
	}
	/* Check for unicast suite(s) */
	if (len < WPA_IE_SUITE_COUNT_LEN) {
		WL_INFO(("no unicast suite\n"));
		goto exit;
	}
	/* walk thru unicast cipher list and pick up what we recognize */
	ucast = (wpa_suite_ucast_t *)&mcast[1];
	count = ltoh16_ua(&ucast->count);
	len -= WPA_IE_SUITE_COUNT_LEN;
	for (i = 0; i < count && len >= WPA_SUITE_LEN;
		i++, len -= WPA_SUITE_LEN) {
		if (!bcmp(ucast->list[i].oui, WPA_OUI, WPA_OUI_LEN)) {
			if (IS_WPA_CIPHER(ucast->list[i].type)) {
				tmp = 0;
				switch (ucast->list[i].type) {
					case WPA_CIPHER_NONE:
						tmp = 0;
						break;
					case WPA_CIPHER_WEP_40:
					case WPA_CIPHER_WEP_104:
						tmp = WEP_ENABLED;
						break;
					case WPA_CIPHER_TKIP:
						tmp = TKIP_ENABLED;
						break;
					case WPA_CIPHER_AES_CCM:
						tmp = AES_ENABLED;
						break;
					default:
						WL_ERR(("No Security Info\n"));
				}
				pval |= tmp;
			}
		}
	}
	len -= (count - i) * WPA_SUITE_LEN;
	/* Check for auth key management suite(s) */
	if (len < WPA_IE_SUITE_COUNT_LEN) {
		WL_INFO((" no auth 

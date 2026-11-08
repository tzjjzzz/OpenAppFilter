// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/jhash.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include "fwx.h"
#include "fwx_log.h"
#include "fwx_mac_filter.h"
#include "fwx_app_filter.h"
#include "fwx_client.h"
int af_log_lvl = 0;
int fwx_test_mode = 0;

int g_record_enable = 0;
int g_by_pass_accl = 1;
int g_user_mode = 0;
int af_work_mode = AF_MODE_GATEWAY;
unsigned int fwx_lan_ip = 0;
unsigned int fwx_lan_mask = 0;
char g_lan_ifname[64] = "br-lan";

/*
 * g_lan_ifname may hold several bridge names separated by ',', ' ' or ';'
 * (e.g. "br-lan,br-guest"). A device is a LAN device if its name contains
 * any one of the tokens (same substring semantics as the old single name).
 */
int fwx_is_lan_dev(const char *name)
{
	const char *p = g_lan_ifname;
	char tok[32];
	int len;

	if (!name)
		return 0;
	while (*p) {
		while (*p == ',' || *p == ' ' || *p == ';')
			p++;
		len = 0;
		while (p[len] && p[len] != ',' && p[len] != ' ' && p[len] != ';')
			len++;
		if (len > 0 && len < (int)sizeof(tok)) {
			memcpy(tok, p, len);
			tok[len] = 0;
			if (strstr(name, tok))
				return 1;
		}
		p += len;
	}
	return 0;
}

/*
 * Get the client key (MAC) of a packet.
 * Ethernet devices carry a real source MAC. L3 devices (WireGuard/tun/ppp...)
 * have no link-layer header, so eth_hdr() would read garbage; for those build
 * a stable pseudo MAC (locally administered) from the source IP instead, so
 * every VPN peer address is tracked as its own client.
 */
void af_get_smac(struct sk_buff *skb, u_int8_t *smac)
{
	struct net_device *dev = skb->dev;

	if (dev && dev->type == ARPHRD_ETHER && skb_mac_header_was_set(skb)) {
		memcpy(smac, eth_hdr(skb)->h_source, ETH_ALEN);
		return;
	}

	memset(smac, 0, ETH_ALEN);
	smac[0] = 0x02;
	if (skb->protocol == htons(ETH_P_IP)) {
		smac[1] = 0xfe;
		memcpy(&smac[2], &ip_hdr(skb)->saddr, 4);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		u32 h = jhash(&ipv6_hdr(skb)->saddr, sizeof(struct in6_addr), 0);
		smac[1] = 0xfd;
		memcpy(&smac[2], &h, 4);
	} else {
		memcpy(smac, &skb->cb[40], ETH_ALEN);
	}
}
int g_tcp_rst = 1;
int g_feature_init = 0;
char g_fwx_version[64] = FWX_VERSION;
int g_feature_count = 0;
char g_record_whitelist[1024] = {0};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0))
static int fwx_proc_record_whitelist_handler(struct ctl_table *table, int write,
					      void *buffer, size_t *lenp, loff_t *ppos)
#else
static int fwx_proc_record_whitelist_handler(const struct ctl_table *table, int write,
					      void *buffer, size_t *lenp, loff_t *ppos)
#endif
{
	int ret = 0;

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret || !write) {
		return ret;
	}

	fwx_set_record_whitelist(g_record_whitelist);
	return ret;
}

static struct ctl_table fwx_table[] = {
	{
		.procname	= "debug",
		.data		= &af_log_lvl,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "feature_init",
		.data		= &g_feature_init,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "version",
		.data		= g_fwx_version,
		.maxlen 	= 64,
		.mode		= 0444,
		.proc_handler = proc_dostring,
	},
	{
		.procname	= "feature_count",
		.data		= &g_feature_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "test_mode",
		.data		= &fwx_test_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "appfilter_enable",
		.data		= &g_appfilter_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "macfilter_enable",
		.data		= &g_mac_filter_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "by_pass_accl",
		.data		= &g_by_pass_accl,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tcp_rst",
		.data		= &g_tcp_rst,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "lan_ifname",
		.data		= g_lan_ifname,
		.maxlen 	= 64,
		.mode		= 0666,
		.proc_handler = proc_dostring,
	},
	{
		.procname	= "record_enable",
		.data		= &g_record_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "record_whitelist",
		.data		= g_record_whitelist,
		.maxlen 	= sizeof(g_record_whitelist),
		.mode		= 0666,
		.proc_handler	= fwx_proc_record_whitelist_handler,
	},
	{
		.procname	= "user_mode",
		.data		= &g_user_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "work_mode",
		.data		= &af_work_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "lan_ip",
		.data		= &fwx_lan_ip,
		.maxlen = 	sizeof(unsigned int),
		.mode		= 0666,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname = "lan_mask",
		.data = &fwx_lan_mask,
		.maxlen = sizeof(unsigned int),
		.mode = 0666,
		.proc_handler = proc_douintvec,
	},
	{
		.procname	= "max_app_report_count",
		.data		= &g_max_app_report_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "min_http_match_count",
		.data		= &g_min_http_match_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
		
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0))
	{
	}
#endif
};
#define FWX_SYS_PROC_DIR "fwx"

static struct ctl_table fwx_root_table[] = {
	{
		.procname	= FWX_SYS_PROC_DIR,
		.mode		= 0555,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		.child		= fwx_table,
#endif
	},
	{}
};
static struct ctl_table_header *fwx_table_header;


static int af_init_log_sysctl(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		fwx_table_header = register_sysctl_table(fwx_root_table);
#else
	fwx_table_header = register_sysctl(FWX_SYS_PROC_DIR, fwx_table);
#endif
	if (fwx_table_header == NULL){
		printk("init log sysctl...failed\n");
		return -ENOMEM;
	}
	return 0;
}

static int af_fini_log_sysctl(void)
{
	if (fwx_table_header)
		unregister_sysctl_table(fwx_table_header);
	return 0;
}

int af_log_init(void){
	af_init_log_sysctl();
	return 0;
}

int af_log_exit(void){
	af_fini_log_sysctl();
	return 0;
}

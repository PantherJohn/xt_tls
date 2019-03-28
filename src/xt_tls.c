#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/ctype.h>
#include <asm/errno.h>

#ifdef XT_TLS_GROUP_SUPPORT
//#include "dnset.h"
#endif

#include "compat.h"
#include "xt_tls.h"
#include "dustin.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nils Andreas Svee <nils@stokkdalen.no>");
MODULE_DESCRIPTION("Xtables: TLS (SNI) matching");
MODULE_ALIAS("ipt_tls");

static int __init tls_mt_init(void);
static void __exit tls_mt_exit(void);
static bool tls_mt(const struct sk_buff *, struct xt_action_param *);
static int tls_mt_check(const struct xt_mtchk_param *);

module_init(tls_mt_init);
module_exit(tls_mt_exit);

static struct xt_match tls_mt_regs[] __read_mostly = {
    {
        .name       = "tls",
        .revision   = 0,
        .family     = NFPROTO_IPV4,
        .checkentry = tls_mt_check,
        .match      = tls_mt,
        .matchsize  = sizeof(struct xt_tls_info),
        .me         = THIS_MODULE,
    },
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    {
        .name       = "tls",
        .revision   = 0,
        .family     = NFPROTO_IPV6,
        .checkentry = tls_mt_check,
        .match      = tls_mt,
        .matchsize  = sizeof(struct xt_tls_info),
        .me         = THIS_MODULE,
    },
#endif
};



static int __init tls_mt_init(void)
{
    return xt_register_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
}

static void __exit tls_mt_exit(void)
{
    xt_unregister_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
}

static bool tls_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    char *parsed_host;
    const struct xt_tls_info *info = par->matchinfo;
    int result = -1, proto = IPPROTO_MAX;
    bool invert = (info->invert & XT_TLS_OP_HOST);

    bool match = false;
    unsigned char *header = skb_network_header(skb);
    unsigned char *theader = skb_transport_header(skb);
    struct iphdr *ip_header = (struct iphdr *) header;
    struct tcphdr *tcp_header; struct udphdr *udp_header;
    char *data; size_t len = 0;

    switch (ip_header->version) {
        case 4:
            proto = ip_header->protocol;
            break;
        case 6:
            proto = ((struct ipv6hdr *) header)->nexthdr;
            break;
    }

    switch (proto) {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *) theader;
            data = (char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
            len = (uintptr_t)skb_tail_pointer(skb) - (uintptr_t)data;
            if (!(result = get_tls_hostname(data, len, &parsed_host)))
                result = get_http_hostname(data, len, &parsed_host);
            break;
        case IPPROTO_UDP:
            udp_header = (struct udphdr *) theader;
            data = (char *)udp_header + 8;
            result = get_quic_hostname(data, ntohs(udp_header->len), &parsed_host);
            break;
#ifdef XT_TLS_DEBUG
        default:
            printk("[xt_tls] neither TCP nor UDP %d\n", proto);
            break;
#endif
    }

    if (!result)
        return false;

    printk("match type: %d", info->match_type);
    switch (info->match_type) {
        case XT_TLS_OP_GROUP:
            //match = dnset_match((u8 *)info->tls_group, parsed_host);
            break;
        case XT_TLS_OP_HOST:
            match = glob_match(info->tls_host, parsed_host);
            break;
    }

#ifdef XT_TLS_DEBUG
    printk("[xt_tls] Parsed domain: %s\n", parsed_host);
    printk("[xt_tls] Hostname length: %d\n", result);
    printk("[xt_tls] Domain matches: %s, invert: %s\n", match ? "true" : "false", invert ? "true" : "false");
#endif
    if (invert)
        match = !match;

    kfree(parsed_host);
    return match;
}

static int tls_mt_check(const struct xt_mtchk_param *par)
{
    __u16 proto;

    switch(par->family) {
        case NFPROTO_IPV4:
            proto = ((const struct ipt_ip *) par->entryinfo)->proto;
            break;
        case NFPROTO_IPV6:
            proto = ((const struct ip6t_ip6 *) par->entryinfo)->proto;
            break;
        default:
            return -EINVAL;
    }

    if (proto != IPPROTO_TCP &&
        proto != IPPROTO_UDP) {
        pr_info("Can be used only in combination with "
            "-p tcp or -p udp\n");
        return -EINVAL;
    }

    return 0;
}

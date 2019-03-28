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
#include "dnset.h"
#endif

#include "compat.h"
#include "xt_tls.h"


#define HTTP_ERR_INCOMPLETE -1
#define HTTP_ERR_NO_HOSTHDR -2
#define HTTP_ERR_INVALID_HOSTNAME -3
#define HTTP_ERR_MALLOC -4
#define HTTP_ERR_INVALID_HLO -5

#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#define QUIC_DATA_LEN 1358

const char tls_alert[] = {
    0x15, /* TLS Alert */
    0x03, 0x01, /* TLS version  */
    0x00, 0x02, /* Payload length */
    0x02, 0x28, /* Fatal, handshake failure */
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nils Andreas Svee <nils@stokkdalen.no>");
MODULE_DESCRIPTION("Xtables: TLS (SNI) matching");
MODULE_ALIAS("ipt_tls");

int __init tls_mt_init(void);
void __exit tls_mt_exit(void);
bool tls_mt(const struct sk_buff *, struct xt_action_param *);
int tls_mt_check(const struct xt_mtchk_param *);

int get_http_hostname(const char *, size_t, char **);
int parse_http_headers(const char *, const char *, size_t, char **);
size_t fetch_http_header_next(const char **, size_t *);

int get_tls_hostname(const uint8_t*, size_t, char **);
int parse_tls_extensions(const uint8_t*, size_t, char **);
int parse_server_name_extension(const uint8_t*, size_t, char **);

int get_quic_hostname(const char *, size_t, char **);

module_init(tls_mt_init);
module_exit(tls_mt_exit);

struct xt_match tls_mt_regs[] __read_mostly = {
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



int __init tls_mt_init(void)
{
	return xt_register_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
}

void __exit tls_mt_exit(void)
{
	xt_unregister_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
}

bool tls_mt(const struct sk_buff *skb, struct xt_action_param *par)
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
            if ((result = get_tls_hostname(data, len, &parsed_host)) != 0)
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

    if (result < 0)
    	return false;

	printk("match type: %d", info->match_type);
	switch (info->match_type) {
		case XT_TLS_OP_GROUP:
			match = dnset_match((u8 *)info->tls_group, parsed_host);
			break;
		case XT_TLS_OP_HOST:
			match = glob_match(info->tls_host, parsed_host);
			break;
	}

#ifdef XT_TLS_DEBUG
	printk("[xt_tls] Parsed domain: %s\n", parsed_host);
	printk("[xt_tls] Domain matches: %s, invert: %s\n", match ? "true" : "false", invert ? "true" : "false");
#endif
	if (invert)
		match = !match;

	kfree(parsed_host);
	return match;
}

int tls_mt_check(const struct xt_mtchk_param *par)
{
	__u16 proto;
	struct xt_tls_info * info = par->matchinfo;

	if (par->family == NFPROTO_IPV4) {
		proto = ((const struct ipt_ip *) par->entryinfo)->proto;
	} else if (par->family == NFPROTO_IPV6) {
		proto = ((const struct ip6t_ip6 *) par->entryinfo)->proto;
	} else {
		return -EINVAL;
	}

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		pr_info("Can be used only in combination with "
			"-p tcp or -p udp\n");
		return -EINVAL;
	}

	// This does probably not belong here, but I'm not sure where else it fits
	if (strlen(info->tls_group) > 0)
		info->match_type = XT_TLS_OP_GROUP;
	if (strlen(info->tls_host) > 0)
		info->match_type = XT_TLS_OP_HOST;

	return 0;
}



/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * - get_http_hostname
 * Parses a HTTP request for the Host: header
 * - get_tls_hostname
 * Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  HTTP_ERR_INCOMPLETE   - Incomplete request
 *  HTTP_ERR_NO_HOSTHDR   - No Host header included in this request
 *  HTTP_ERR_INVALID_HOSTNAME   - Invalid hostname pointer
 *  HTTP_ERR_MALLOC   - malloc failure
 *  HTTP_ERR_INVALID_HLO - Invalid TLS client hello
 **/

int 
get_http_hostname(const char* data, size_t data_len, char **hostname) {
    int result, i;

    if (hostname == NULL)
        return HTTP_ERR_INVALID_HOSTNAME;

    result = parse_http_headers("Host:", data, data_len, hostname);
    if (result < 0)
        return result;

    /*
     *  if the user specifies the port in the request, it is included here.
     *  Host: example.com:80
     *  Host: [2001:db8::1]:8080
     *  so we trim off port portion
     */
    for (i = result - 1; i >= 0; i--)
        if ((*hostname)[i] == ':') {
            (*hostname)[i] = '\0';
            result = i;
            break;
        } else if (!isdigit((*hostname)[i])) {
            break;
        }

    return result;
}

int
parse_http_headers(const char *header, const char *data, size_t data_len, char **value) {
    size_t len, header_len;

    header_len = strlen(header);

    /* loop through headers stopping at first blank line */
    while ((len = fetch_http_header_next(&data, &data_len)) != 0)
        if (len > header_len && strncasecmp(header, data, header_len) == 0) {
            /* Eat leading whitespace */
            while (header_len < len && isblank(data[header_len]))
                header_len++;

            *value = malloc(len - header_len + 1);
            if (*value == NULL)
                return HTTP_ERR_MALLOC;

            strncpy(*value, data + header_len, len - header_len);
            (*value)[len - header_len] = '\0';

            return len - header_len;
        }

    /* If there is no data left after reading all the headers then we do not
     * have a complete HTTP request, there must be a blank line */
    if (data_len == 0)
        return HTTP_ERR_INCOMPLETE;

    return HTTP_ERR_NO_HOSTHDR;
}

size_t
fetch_http_header_next(const char **data, size_t *len) {
    size_t header_len;

    /* perhaps we can optimize this to reuse the value of header_len, rather
     * than scanning twice.
     * Walk our data stream until the end of the header */
    while (*len > 2 && (*data)[0] != '\r' && (*data)[1] != '\n') {
        (*len)--;
        (*data)++;
    }

    /* advanced past the <CR><LF> pair */
    *data += 2;
    *len -= 2;

    /* Find the length of the next header */
    header_len = 0;
    while (*len > header_len + 1
            && (*data)[header_len] != '\r'
            && (*data)[header_len + 1] != '\n')
        header_len++;

    return header_len;
}


int
get_tls_hostname(const uint8_t *data, size_t data_len, char **hostname) {
    uint8_t tls_content_type;
    uint8_t tls_version_major;
    uint8_t tls_version_minor;
    size_t pos = TLS_HEADER_LEN;
    size_t len;

    if (hostname == NULL)
        return HTTP_ERR_INVALID_HOSTNAME;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return HTTP_ERR_INCOMPLETE;

    /* SSL 2.0 compatible Client Hello
     *
     * High bit of first byte (length) and content type is Client Hello
     *
     * See RFC5246 Appendix E.2
     */
    if (data[0] & 0x80 && data[2] == 1)
        return HTTP_ERR_NO_HOSTHDR;

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE)
        return HTTP_ERR_INVALID_HLO;

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3)
        return HTTP_ERR_NO_HOSTHDR;

    /* TLS record length */
    len = ((size_t)data[3] << 8) +
        (size_t)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return HTTP_ERR_INCOMPLETE;

    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return HTTP_ERR_INVALID_HLO;
    }
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
        return HTTP_ERR_INVALID_HLO;

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > data_len)
        return HTTP_ERR_INVALID_HLO;
    len = (size_t)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return HTTP_ERR_INVALID_HLO;
    len = ((size_t)data[pos] << 8) + (size_t)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return HTTP_ERR_INVALID_HLO;
    len = (size_t)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0)
        return HTTP_ERR_NO_HOSTHDR;

    /* Extensions */
    if (pos + 2 > data_len)
        return HTTP_ERR_INVALID_HLO;
    len = ((size_t)data[pos] << 8) + (size_t)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return HTTP_ERR_INVALID_HLO;
    return parse_tls_extensions(data + pos, len, hostname);
}

int
parse_tls_extensions(const uint8_t *data, size_t data_len, char **hostname) {
    size_t pos = 0;
    size_t len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = ((size_t)data[pos + 2] << 8) +
            (size_t)data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len)
                return HTTP_ERR_INVALID_HLO;
            return parse_server_name_extension(data + pos + 4, len, hostname);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return HTTP_ERR_INVALID_HLO;

    return HTTP_ERR_NO_HOSTHDR;
}

int
parse_server_name_extension(const uint8_t *data, size_t data_len, char **hostname) {
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = ((size_t)data[pos + 1] << 8) +
            (size_t)data[pos + 2];

        if (pos + 3 + len > data_len)
            return HTTP_ERR_INVALID_HLO;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                *hostname = malloc(len + 1);
                if (*hostname == NULL)
                    return HTTP_ERR_MALLOC;

                strncpy(*hostname, (const char *)(data + pos + 3), len);
                (*hostname)[len] = '\0';

                return len;
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return HTTP_ERR_INVALID_HLO;

    return HTTP_ERR_NO_HOSTHDR;
}

int 
get_quic_hostname(const char* data, size_t data_len, char **hostname)
{
	// Base offset, skip to packet number
	u_int16_t base_offset = 13, offset;
    
	if (data_len != QUIC_DATA_LEN)
		return HTTP_ERR_INCOMPLETE;
	// Packet Number must be 1
	if (data[base_offset] != 1)
		return HTTP_ERR_INVALID_HLO;
	offset = base_offset + 17; // Skip data length
	// Only continue if this is a client hello
	if (strncmp(&data[offset], "CHLO", 4) == 0)
	{	
		u_int32_t prev_end_offset = 0;
		int tag_offset = 0;
		u_int16_t tag_number;
		int i;

		offset += 4; // Size of tag
		memcpy(&tag_number, &data[offset], 2);

		offset += 4; // Size of tag number + padding
		base_offset=offset;
		for (i = 0; i < tag_number; i++)
		{
			u_int32_t tag_end_offset;
			int match = strncmp("SNI", &data[offset + tag_offset], 4);

			tag_offset += 4;
			memcpy(&tag_end_offset, &data[offset + tag_offset], 4);
			tag_offset += 4;

			if (match == 0) {
				int len = tag_end_offset - prev_end_offset;
				*hostname = malloc(len + 1);
				strncpy(*hostname, &data[base_offset + tag_number * 8 + prev_end_offset], len);
				(*hostname)[len] = '\0'; //make sure string is null terminated
				return len;
			} else {
				prev_end_offset = tag_end_offset;
			}
		}
	}

	return HTTP_ERR_INVALID_HLO;
}

/*
 * Copyright (C) ST-Ericsson 2010-2012
 * Contact: Alexey Orishko <alexey.orishko@stericsson.com>
 * Original author: Hans Petter Selasky <hans.petter.selasky@stericsson.com>
 *
 * USB Host Driver for Network Control Model (NCM)
 * http://www.usb.org/developers/devclass_docs/NCM10.zip
 *
 * The NCM encoding, decoding and initialization logic
 * derives from FreeBSD 8.x. if_cdce.c and if_cdcereg.h
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose this file to be licensed under the terms
 * of the GNU General Public License (GPL) Version 2 or the 2-clause
 * BSD license listed below:
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
 */

#define USB_CDC_SUBCLASS_NCM			0x0d
#define USB_CDC_SUBCLASS_MBIM			0x0e

#define USB_CDC_NCM_TYPE			0x1a
#define USB_CDC_MBIM_TYPE			0x1b

#define USB_CDC_NCM_PROTO_NTB			1
#define USB_CDC_MBIM_PROTO_NTB			2

#define CDC_NCM_COMM_ALTSETTING_NCM		0
#define CDC_NCM_COMM_ALTSETTING_MBIM		1

#define CDC_NCM_DATA_ALTSETTING_NCM		1
#define CDC_NCM_DATA_ALTSETTING_MBIM		2

/* CDC NCM subclass 3.2.1 */
#define USB_CDC_NCM_NDP16_LENGTH_MIN		0x10

/* Maximum NTB length */
#define	CDC_NCM_NTB_MAX_SIZE_TX			32768	/* bytes */
#define	CDC_NCM_NTB_MAX_SIZE_RX			32768	/* bytes */

/* Minimum value for MaxDatagramSize, ch. 6.2.9 */
#define	CDC_NCM_MIN_DATAGRAM_SIZE		1514	/* bytes */

/* Minimum value for MaxDatagramSize, ch. 8.1.3 */
#define CDC_MBIM_MIN_DATAGRAM_SIZE		2048	/* bytes */

#define	CDC_NCM_MIN_TX_PKT			512	/* bytes */

/* Default value for MaxDatagramSize */
#define	CDC_NCM_MAX_DATAGRAM_SIZE		8192	/* bytes */

/*
 * Maximum amount of datagrams in NCM Datagram Pointer Table, not counting
 * the last NULL entry.
 */
#define	CDC_NCM_DPT_DATAGRAMS_MAX		40

/* Restart the timer, if amount of datagrams is less than given value */
#define	CDC_NCM_RESTART_TIMER_DATAGRAM_CNT	3
#define	CDC_NCM_TIMER_PENDING_CNT		2
#define CDC_NCM_TIMER_INTERVAL			(400UL * NSEC_PER_USEC)

/* The following macro defines the minimum header space */
#define	CDC_NCM_MIN_HDR_SIZE \
	(sizeof(struct usb_cdc_ncm_nth16) + sizeof(struct usb_cdc_ncm_ndp16) + \
	(CDC_NCM_DPT_DATAGRAMS_MAX + 1) * sizeof(struct usb_cdc_ncm_dpe16))

#define CDC_NCM_NDP_SIZE \
	(sizeof(struct usb_cdc_ncm_ndp16) +				\
	      (CDC_NCM_DPT_DATAGRAMS_MAX + 1) * sizeof(struct usb_cdc_ncm_dpe16))

#define cdc_ncm_comm_intf_is_mbim(x)  ((x)->desc.bInterfaceSubClass == USB_CDC_SUBCLASS_MBIM && \
				       (x)->desc.bInterfaceProtocol == USB_CDC_PROTO_NONE)
#define cdc_ncm_data_intf_is_mbim(x)  ((x)->desc.bInterfaceProtocol == USB_CDC_MBIM_PROTO_NTB)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
/* "NCM Control Model Functional Descriptor" */
struct usb_cdc_ncm_desc {
	__u8	bLength;
	__u8	bDescriptorType;
	__u8	bDescriptorSubType;

	__le16	bcdNcmVersion;
	__u8	bmNetworkCapabilities;
} __attribute__ ((packed));
#endif

/* "MBIM Control Model Functional Descriptor" */
struct usb_cdc_mbim_desc {
	__u8	bLength;
	__u8	bDescriptorType;
	__u8	bDescriptorSubType;

	__le16	bcdMBIMVersion;
	__le16  wMaxControlMessage;
	__u8    bNumberFilters;
	__u8    bMaxFilterSize;
	__le16  wMaxSegmentSize;
	__u8    bmNetworkCapabilities;
} __attribute__ ((packed));

/*-------------------------------------------------------------------------*/

/*
 * Class-Specific Notifications (6.3) sent by interrupt transfers
 *
 * section 3.8.2 table 11 of the CDC spec lists Ethernet notifications
 * section 3.6.2.1 table 5 specifies ACM notifications, accepted by RNDIS
 * RNDIS also defines its own bit-incompatible notifications
 */

struct usb_cdc_speed_change {
	__le32	DLBitRRate;	/* contains the downlink bit rate (IN pipe) */
	__le32	ULBitRate;	/* contains the uplink bit rate (OUT pipe) */
} __attribute__ ((packed));

/*-------------------------------------------------------------------------*/

/*
 * Class Specific structures and constants
 *
 * CDC NCM NTB parameters structure, CDC NCM subclass 6.2.1
 *
 */

struct usb_cdc_ncm_ntb_parameters {
	__le16	wLength;
	__le16	bmNtbFormatsSupported;
	__le32	dwNtbInMaxSize;
	__le16	wNdpInDivisor;
	__le16	wNdpInPayloadRemainder;
	__le16	wNdpInAlignment;
	__le16	wPadding1;
	__le32	dwNtbOutMaxSize;
	__le16	wNdpOutDivisor;
	__le16	wNdpOutPayloadRemainder;
	__le16	wNdpOutAlignment;
	__le16	wNtbOutMaxDatagrams;
} __attribute__ ((packed));

/*
 * CDC NCM transfer headers, CDC NCM subclass 3.2
 */

#define USB_CDC_NCM_NTH16_SIGN		0x484D434E /* NCMH */
#define USB_CDC_NCM_NTH32_SIGN		0x686D636E /* ncmh */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
struct usb_cdc_ncm_nth16 {
	__le32	dwSignature;
	__le16	wHeaderLength;
	__le16	wSequence;
	__le16	wBlockLength;
	__le16	wFpIndex;
} __attribute__ ((packed));

struct usb_cdc_ncm_nth32 {
	__le32	dwSignature;
	__le16	wHeaderLength;
	__le16	wSequence;
	__le32	dwBlockLength;
	__le32	dwFpIndex;
} __attribute__ ((packed));
#endif

/*
 * CDC NCM datagram pointers, CDC NCM subclass 3.3
 */

#define USB_CDC_NCM_NDP16_CRC_SIGN	0x314D434E /* NCM1 */
#define USB_CDC_NCM_NDP16_NOCRC_SIGN	0x304D434E /* NCM0 */
#define USB_CDC_NCM_NDP32_CRC_SIGN	0x316D636E /* ncm1 */
#define USB_CDC_NCM_NDP32_NOCRC_SIGN	0x306D636E /* ncm0 */

#define USB_CDC_MBIM_NDP16_IPS_SIGN     0x00535049 /* IPS<sessionID> : IPS0 for now */
#define USB_CDC_MBIM_NDP32_IPS_SIGN     0x00737069 /* ips<sessionID> : ips0 for now */
#define USB_CDC_MBIM_NDP16_DSS_SIGN     0x00535344 /* DSS<sessionID> */
#define USB_CDC_MBIM_NDP32_DSS_SIGN     0x00737364 /* dss<sessionID> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
/* 16-bit NCM Datagram Pointer Entry */
struct usb_cdc_ncm_dpe16 {
	__le16	wDatagramIndex;
	__le16	wDatagramLength;
} __attribute__((__packed__));

/* 32-bit NCM Datagram Pointer Entry */
struct usb_cdc_ncm_dpe32 {
	__le32	dwDatagramIndex;
	__le32	dwDatagramLength;
} __attribute__((__packed__));
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
/* 16-bit NCM Datagram Pointer Table */
struct usb_cdc_ncm_ndp16 {
	__le32	dwSignature;
	__le16	wLength;
	__le16	wNextFpIndex;
	struct	usb_cdc_ncm_dpe16 data[0];
} __attribute__ ((packed));

/* 32-bit NCM Datagram Pointer Table */
struct usb_cdc_ncm_ndp32 {
	__le32	dwSignature;
	__le16	wLength;
	__le16	wReserved6;
	__le32	dwNextFpIndex;
	__le32	dwReserved12;
	struct	usb_cdc_ncm_dpe32 data[0];
} __attribute__ ((packed));
#endif

/* CDC NCM subclass 3.2.1 and 3.2.2 */
#define USB_CDC_NCM_NDP16_INDEX_MIN			0x000C
#define USB_CDC_NCM_NDP32_INDEX_MIN			0x0010

/* CDC NCM subclass 3.3.3 Datagram Formatting */
#define USB_CDC_NCM_DATAGRAM_FORMAT_CRC			0x30
#define USB_CDC_NCM_DATAGRAM_FORMAT_NOCRC		0X31

/* CDC NCM subclass 4.2 NCM Communications Interface Protocol Code */
#define USB_CDC_NCM_PROTO_CODE_NO_ENCAP_COMMANDS	0x00
#define USB_CDC_NCM_PROTO_CODE_EXTERN_PROTO		0xFE

/* CDC NCM subclass 5.2.1 NCM Functional Descriptor, bmNetworkCapabilities */
#define USB_CDC_NCM_NCAP_ETH_FILTER			(1 << 0)
#define USB_CDC_NCM_NCAP_NET_ADDRESS			(1 << 1)
#define USB_CDC_NCM_NCAP_ENCAP_COMMAND			(1 << 2)
#define USB_CDC_NCM_NCAP_MAX_DATAGRAM_SIZE		(1 << 3)
#define USB_CDC_NCM_NCAP_CRC_MODE			(1 << 4)
#define	USB_CDC_NCM_NCAP_NTB_INPUT_SIZE			(1 << 5)

/* CDC NCM subclass Table 6-3: NTB Parameter Structure */
#define USB_CDC_NCM_NTB16_SUPPORTED			(1 << 0)
#define USB_CDC_NCM_NTB32_SUPPORTED			(1 << 1)

/* CDC NCM subclass Table 6-3: NTB Parameter Structure */
#define USB_CDC_NCM_NDP_ALIGN_MIN_SIZE			0x04
#define USB_CDC_NCM_NTB_MAX_LENGTH			0x1C

/* CDC NCM subclass 6.2.5 SetNtbFormat */
#define USB_CDC_NCM_NTB16_FORMAT			0x00
#define USB_CDC_NCM_NTB32_FORMAT			0x01

/* CDC NCM subclass 6.2.7 SetNtbInputSize */
#define USB_CDC_NCM_NTB_MIN_IN_SIZE			2048
#define USB_CDC_NCM_NTB_MIN_OUT_SIZE			2048

/* NTB Input Size Structure */
struct usb_cdc_ncm_ndp_input_size {
	__le32	dwNtbInMaxSize;
	__le16	wNtbInMaxDatagrams;
	__le16	wReserved;
} __attribute__ ((packed));

/* CDC NCM subclass 6.2.11 SetCrcMode */
#define USB_CDC_NCM_CRC_NOT_APPENDED			0x00
#define USB_CDC_NCM_CRC_APPENDED			0x01

#define USB_CDC_GET_NTB_PARAMETERS			0x80
#define USB_CDC_SET_NTB_FORMAT				0x84
#define USB_CDC_SET_NTB_INPUT_SIZE			0x86
#define USB_CDC_GET_MAX_DATAGRAM_SIZE			0x87
#define USB_CDC_SET_MAX_DATAGRAM_SIZE			0x88
#define USB_CDC_SET_CRC_MODE				0x8a

struct cdc_ncm_ctx {
	struct usb_cdc_ncm_ntb_parameters ncm_parm;
	struct hrtimer tx_timer;
	struct tasklet_struct bh;

	const struct usb_cdc_ncm_desc *func_desc;
	const struct usb_cdc_mbim_desc   *mbim_desc;
	const struct usb_cdc_header_desc *header_desc;
	const struct usb_cdc_union_desc *union_desc;
	const struct usb_cdc_ether_desc *ether_desc;

	struct net_device *netdev;
	struct usb_device *udev;
	struct usb_host_endpoint *in_ep;
	struct usb_host_endpoint *out_ep;
	struct usb_host_endpoint *status_ep;
	struct usb_interface *intf;
	struct usb_interface *control;
	struct usb_interface *data;

	struct sk_buff *tx_curr_skb;
	struct sk_buff *tx_rem_skb;
	__le32 tx_rem_sign;

	spinlock_t mtx;
	atomic_t stop;

	u32 tx_timer_pending;
	u32 tx_curr_frame_num;
	u32 rx_speed;
	u32 tx_speed;
	u32 rx_max;
	u32 tx_max;
	u32 max_datagram_size;
	u16 tx_max_datagrams;
	u16 tx_remainder;
	u16 tx_modulus;
	u16 tx_ndp_modulus;
	u16 tx_seq;
	u16 rx_seq;
	u16 connected;
};

/*
 *  * swap - swap value of @a and @b
 *   */
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

extern u8 cdc_ncm_select_altsetting(struct usbnet *dev, struct usb_interface *intf);
extern int cdc_ncm_bind_common(struct usbnet *dev, struct usb_interface *intf, u8 data_altsetting);
extern void cdc_ncm_unbind(struct usbnet *dev, struct usb_interface *intf);
extern struct sk_buff *cdc_ncm_fill_tx_frame(struct cdc_ncm_ctx *ctx, struct sk_buff *skb, __le32 sign);
extern int cdc_ncm_rx_verify_nth16(struct cdc_ncm_ctx *ctx, struct sk_buff *skb_in);
extern int cdc_ncm_rx_verify_ndp16(struct sk_buff *skb_in, int ndpoffset);

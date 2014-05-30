#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Libpcap file format */

#define guint32 unsigned int
#define guint16 unsigned short
#define guint8  unsigned char
#define gint32  int

// Global Header

typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

/*
magic_number:   used to detect the file format itself and the byte ordering. The writing application writes
                0xa1b2c3d4 with it's native byte ordering format into this field. The reading application will
                read either 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application reads
                the swapped 0xd4c3b2a1 value, it knows that all the following fields will have to be swapped too.
version_major,
version_minor:  the version number of this file format (current version is 2.4)
thiszone:       the correction time in seconds between GMT (UTC) and the local timezone of the following packet
                header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0.
                If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00,
                thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
sigfigs:        in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
snaplen:        the "snapshot length" for the capture (typically 65535 or even more, but might be limited by
                the user), see: incl_len vs. orig_len below

network:        data link layer type (e.g. 1 for Ethernet, see wiretap/libpcap.c or libpcap's pcap-bpf.h for details),
                this can be various types like Token Ring, FDDI, etc.
*/

// Record (Packet)

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */

//        guint32 ifindex;        /* index, in *capturing* machine's list of interfaces, of the interface on which this packet came in. */
//        guint16 protocol;       /* Ethernet packet type */
//        guint8  pkt_type;       /* broadcast/multicast/etc. indication */
//        guint8  pad;            /* pad to a 4-byte boundary */
} pcaprec_hdr_t;

/*
ts_sec:         the date and time when this packet was captured. This value is in seconds since January 1, 1970
                00:00:00 GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function from
                time.h to get this value, but you might use a more optimized way to get this timestamp value.
                If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.

ts_usec:        the microseconds when this packet was captured, as an offset to ts_sec.  Beware: this value
                shouldn't reach 1 second (1 000 000), in this case ts_sec must be increased instead!

incl_len:       the number of bytes of packet data actually captured and saved in the file. This value should
                never become larger than orig_len or the snaplen value of the global header.

orig_len:       the length of the packet as it appeared on the network when it was captured. If incl_len and
                orig_len differ, the actually saved packet size was limited by snaplen

*/

// Packet Data

/*
    The actual packet data will immediately follow the packet header as a data blob of incl_len bytes without
    a specific byte alignment.
*/

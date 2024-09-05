#ifndef _802_11RADIOTAP_HDR_H
#define _802_11RADIOTAP_HDR_H

#include <stdlib.h>

/*
    The radiotap header format is a mechanism to supply additional information about frames, 
    from the driver to userspace applications such as libpcap, and from a userspace application 
    to the driver for transmission. Designed initially for NetBSD systems by David Young, the 
    radiotap header format provides more flexibility than the Prism or AVS header formats and 
    allows the driver developer to specify an arbitrary number of fields based on a bitmask 
    presence field in the radiotap header.

    https://www.radiotap.org/

    Radiotap data is specified in little endian byte order (least significant bits ordered first)
*/
struct IEEE_80211_RADIOTAP
{
    // START IEEE_80211_RADIOTAP

    u_int8_t    it_version;     /* set to 0 */
    u_int8_t    it_pad;         /* unused, aligns the fields onto natural word boundaries */
    u_int16_t   it_len;         /* entire length of radiotap data, including the RT header */
    u_int32_t   it_present;     /* bitmask of the radiotap data fields that follow the RT header */

    // END IEEE_80211_RADIOTAP
}__attribute__((__packed__));

#endif
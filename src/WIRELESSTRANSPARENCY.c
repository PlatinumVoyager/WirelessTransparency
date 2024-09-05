#define _DEFAULT_SOURCE

#ifndef __linux__
    fprintf(stderr, "This code requires a Linux based OS (Operating System). Try all you might.\n");
    exit(-1);
#else
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>
    #include <signal.h>
    #include <errno.h>
    #include <stdbool.h>

    #include <time.h>
    #include <sys/time.h>
    #include <endian.h>
    #include <setjmp.h>
    #include <pcap/pcap.h>
#endif

#include "../include/setiface.h"
#include "../include/802_11ieee_hdr.h"
#include "../include/802_11radiotap_hdr.h"

void sig_handler(int signal);
void return_bitmask_listing(u_int32_t bitmask_bit);
char *ieee_80211_mac_translation(const u_int8_t mac_addr[6]);

void pkt_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt);

void parse_ieee_80211_header(struct IEEE_80211_HDR *ieee_80211_hdr, const u_char *pkt, 
    const struct pcap_pkthdr *hdr, u_int16_t radiotap_hdr_len);

jmp_buf break_loop, signal_handler;
sigjmp_buf sigjmp_main;

int PACKET_COUNT = 0;
int SET_GLOBAL_NEWLINE = 0;


/*
    Fret not if the SSID to which your primary wireless network interface is connected to is not showing 802.11 beacon frames
    You simply will not receive them as you are already connected to the DS (Distribution System) through the AP (Access Point) itself.
*/
int main(int argc, char *argv[])
{
    const char msg[] = "\033[0;32mWIRELESSTRANSPARENCY v0.1\033[0;m\n\n";

    // sizeof returns space allocated for the null terminator '\0' as well
    // -1 to negate the length disparity
    const int msg_sz = sizeof(msg) - 1;

    __asm__(
        "movq $1, %%rax\n"      // syscall number for sys_write (1)
        "movq $1, %%rdi\n"      // file descriptor 1 (stdout)
        "movq %0, %%rsi\n"      // pointer to the message
        "movq %1, %%rdx\n"      // message length

        "syscall\n"             // invoke the kernel
        : // "r" means that the compiler can use any general-purpose register for that operand
        : "r"(msg), "r"((long)msg_sz) // msg = %0, msg_sz = %1
        : "rax", "rdi", "rsi", "rdx" // tells the compiler which registers are modified by the asm code
    );

    // set ctrl-c hook
    if (__sigsetjmp(sigjmp_main, 1) == 0x0)
    {
        if (signal(0x2, sig_handler) != 0x0)
        {
            fprintf(stderr, "Failed to set the signal interrupt handler!\n");

            return -1;
        }
    }
    else 
    {
        return -1;
    }

    if (argc < 2)
    {
        fprintf(stderr, "Specify interface!\n");

        return -1;
    }

    char *dev = argv[1];
    char error_buff[PCAP_ERRBUF_SIZE];

    printf("++ Set interface to %s\n++ Bringing interface down...\n", dev);

    pcap_t *handle = pcap_open_live(dev, MAX_SNAP_LEN, 0, 1000, error_buff);

    // 1 = up, 0 = down
    if (set_iface_params(dev, 0) < 0x0)
    {
        return -1;
    }

    printf("\nSet interface %s to status: up\n", dev);

    // system call to "iwconfig <iface> mode monitor"
    size_t cmd_len = snprintf(((void *)0), 0, "iwconfig %s mode monitor\n", dev);

    char cmd_exec[cmd_len + 1];
    cmd_exec[0] = '\0';

    snprintf(cmd_exec, (cmd_len + 1), "iwconfig %s mode monitor\n", dev);
    printf("cmd: %s\n", cmd_exec); system(cmd_exec);

    // bring up the interface
    if (set_iface_params(dev, SET_ACTIVATE) < 0)
    {
        // failed, now die.
        return -1;
    }

    if (_setjmp(break_loop) == 0x0)
    {
        // set ;; because code here will cause an early interrupt, doesn't make sense (check the stack)
        ;;
    }
    else 
    {
        // this will properly close the packet capture loop
        goto break_pcap;
    }

    int rc;

    if ((rc = pcap_loop(handle, 0, pkt_handler, ((void *)0)) != PCAP_ERROR))
    {
        // do nothing
        ;;
    }
    else 
    {
        fprintf(stderr, "Failed to call retreive packets from interface: %s\n", dev);

        return -1;
    }

    break_pcap:
    {
        pcap_breakloop(handle);
        printf("++ 802.11 packet dump to stdout terminated successfully by end user.\n");

        longjmp(signal_handler, 1);
    }

    return 0;
}


void sig_handler(int signal)
{
    printf("\nsig_handler() -> execution phase: active\n");

    goto exit_signal;

    exit_signal:
    {
        if (_setjmp(signal_handler) == 0x0)
        {
            longjmp(break_loop, 1);
        }
        else
        {
            printf("\033[0;32m%d\033[0;m total frames captured!\n", PACKET_COUNT);

            // ret jmp here
            printf("Exiting...\n");
        }

        exit(0);
    }
}


void return_bitmask_listing(u_int32_t bitmask_bit)
{
    printf("## RADIOTAP HEADER BITMASK: ");

    for (int i = 0; i < 32; i++)
    {
        printf("%d", ((bitmask_bit >> i) & 1));
    }

    return;
}


/* basic Media Access Control address translation routine */
char *ieee_80211_mac_translation(const u_int8_t mac_addr[6])
{
    size_t mac_sz = snprintf(NULL, 0, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac_addr[0], mac_addr[1], mac_addr[2],
        mac_addr[3], mac_addr[4], mac_addr[5]    
    );

    char *media_access_control_addr = (char *) malloc(mac_sz + 1);

    if (media_access_control_addr == NULL)
    {
        fprintf(stderr, "Failed to allocated space on the heap for the mac address translation character buffer\n");

        exit(1);
    }

    snprintf(media_access_control_addr, (mac_sz + 1), "%02x:%02x:%02x:%02x:%02x:%02x",
        mac_addr[0], mac_addr[1], mac_addr[2],
        mac_addr[3], mac_addr[4], mac_addr[5]    
    );

    /* sending destination set to broadcast address */
    if (strcmp(media_access_control_addr, "ff:ff:ff:ff:ff:ff") == 0)
    {
        char broadcast_addr[] = " (BROADCAST)\n";
        size_t bcast_len = snprintf(NULL, 0, " (BROADCAST)\n");

        char *ieee_80211_ra_2 = (char *) realloc(media_access_control_addr, mac_sz + bcast_len + 1);

        if (ieee_80211_ra_2 == NULL)
        {
            fprintf(stderr, "Error >> failed to run memory allocation routine against RA address!\n");

            exit(-1);
        }

        media_access_control_addr = ieee_80211_ra_2;
        strncat(media_access_control_addr, broadcast_addr, bcast_len + 1);

        SET_GLOBAL_NEWLINE++; // function was called once

        return media_access_control_addr;
    }

    if (SET_GLOBAL_NEWLINE == 0x0 || SET_GLOBAL_NEWLINE == 0x1)
    {
        // call function to display MAC OUI

        char *newline = "\n";
        char *append_nl_no_bcast = (char *) realloc(media_access_control_addr, mac_sz + 2);

        if (append_nl_no_bcast == NULL)
        {
            fprintf(stderr, "Error >> failed to run memory allocation routine for newline injection!\n");

            exit(-1);
        }

        media_access_control_addr = append_nl_no_bcast;
        SET_GLOBAL_NEWLINE = 0;

        strncat(media_access_control_addr, newline, mac_sz + 2);

        return media_access_control_addr;
    }

    return media_access_control_addr;
}


/* This function is responsible for parsing the IEEE 802.11 header information */
void parse_ieee_80211_header(struct IEEE_80211_HDR *ieee_80211_hdr, const u_char *pkt, const struct pcap_pkthdr *hdr, u_int16_t radiotap_hdr_len)
{
    // 16 bit frame control field
    uint16_t frame_control = ieee_80211_hdr->frame_control;

    /*
        Protocol Version (Bits 0-1):
        ----------------------------
            These 2 bits indicate the version of the 802.11 protocol.
            Typically set to 00, as most networks use version 0.
    
        0000 0000 0000 0011 = 0x03 (bits 0, 1)
    */
    uint8_t frame_protocol = (frame_control & 0x03);

    if (frame_protocol == 0x00)
    {
        printf("\nDefault protocol version indicated by 802.11 frame header in transit.\n");
    }
    else
    {
        printf("** Got different or custom protocol version info via frame_protocol field.\n");
    }

    /*
        Type (Bits 2-3):
        ----------------
            These 2 bits define the general type of the frame.
            
            Possible values:
            ----------------
                00 for Management frames
                01 for Control frames
                10 for Data frames
    
        0000 0000 0000 1100 = 0x0c (bits 2, 3)
    */
    uint8_t frame_type = (frame_control & 0x0C) >> 2;

    /*
        Subtype (Bits 4-7):
        -------------------
            These 4 bits provide more specific information about the frame, depending on the type.
            The interpretation varies with the type (e.g., for Management frames, 1000 indicates a Beacon frame).
    
        0000 0000 1111 0000 = 0xF0 (bits 4, 5, 6, 7)
    */
    uint8_t frame_subtype = (frame_control & 0xF0) >> 4;

    /*
        To DS (Bit 8):
        --------------
            Indicate the frame’s direction.
            To DS (To Distribution System): 1 if the frame is headed towards the DS.

        0000 0001 0000 0000 = 0x100 (9th bit position (8th from 0))
    */

    uint8_t frame_to_ds = (frame_control & 0x100) >> 8;

    if (frame_to_ds == 0x01)
    {
        printf("** 802.11 Frame To DS bit set. STA (station) => DS (AP)\n");
    }

    /*
        From DS (Bit 9)
        ---------------
            From DS: 1 if the frame is coming from the DS.
            For frames within an ad hoc network, both are set to 0.

        0000 0010 0000 0000 = 0x200 (10th bit position (9th from 0))
    */
    uint8_t frame_from_ds = (frame_control & 0x200) >> 9; // response, beacon frame, etc

    if (frame_from_ds == 0x01)
    {
        printf("** 802.11 Frame From DS bit set. DS (AP) => STA (station)\n");
    }

    // check for frames sent within an ad-hoc network (or broadcast?)
    if (frame_to_ds == 0x00 && frame_from_ds == 0x00)
    {
        printf("** 802.11 frame sent within an AD-HOC network.\n");
    }

    /*
        More Fragments (Bit 10):
        ------------------------
            1 if there are more fragments of a divided packet following this frame.
    
        0000 0100 0000 0000 = 0x400 (11th bit position (10th from 0))
    */
    uint8_t frame_more_frags = (frame_control & 0x400) >> 10;

    if (frame_more_frags == 0x01)
    {
        printf("** Frame is fragmented, data stream is not yet complete.\n");
    }

    /*
        Retry (Bit 11):
        ---------------
            1 if this frame is a retransmission of an earlier frame.

        0000 1000 0000 0000 = 0x800 (12th bit position (11th from 0))
    */

    uint8_t frame_retry = (frame_control & 0x800) >> 11;

    if (frame_retry == 0x01)
    {
        printf("** 802.11 frame retransmission in progress\n");
    }

    /*
        Power Management (Bit 12):
        --------------------------
            Indicates the power management state of the sender after the completion of a frame exchange.
            1 if the sender will be in power-save mode.

        bit mask: 0001 0000 0000 0000 = 0x1000 (13th bit position (12th from 0)) 
    */
    uint8_t frame_power_mgmt = (frame_control & 0x1000) >> 12;

    switch (frame_power_mgmt) { case 0x01: { printf("Frame depicts bit set for power management features.\n"); break; } 
        case 0x00: { ;; }}

    /*
        More Data (Bit 13):
        -------------------
            1 if more frames are buffered for the destination address.

        Bitwise & to isolate the bit, right shift result by 13 positions to move the bit to the least significant position:
            0010 0000 0000 0000 = 2000 (14th bit position (13th from 0)) 
    */
    uint8_t frame_more_data = (frame_control & 0x2000) >> 13;

    switch (frame_more_data) { case 0x01: { printf("Detected buffered frame in data stream.\n"); break; }
        case 0x00: { ;; }}

    /*
        Protected frame (Bit 14):
        -------------------------
            1 if frame body is encrypted under WEP or WPA/WPA2.

        0100 0000 0000 0000 = 4000 (15th bit position (14th from 0)) 
    */
    uint8_t frame_protect = (frame_control & 0x4000) >> 14;

    switch (frame_protect)
    {
        case 0x0:
        {
            printf("IEEE 802.11 Frame is not encrypted.\n");

            break;
        }

        case 0x1:
        {
            printf("** IEEE 802.11 encrypted frame in transmission.\n");

            break;
        }
    }

    /*
        Order (Bit 15):
        ---------------
            Used only in data frames where the Strictly Ordered service class is invoked.
            1 if the frames must be processed in strict order.
        
        1000 0000 0000 0000 = 8000 (16th bit position (15th from 0))
    */
    uint8_t frame_order = (frame_control & 0x8000) >> 15;

    switch (frame_order)
    {
        case 0x0:
        {
            printf("Frame order does not matter.\n");

            break;
        }
    
        case 0x1:
        {
            printf("** Frame order enabled strict ordering.\n");

            break;
        }
    }

    switch (frame_type)
    {
        case FRAME_TYPE_MANAGEMENT:
        {
            /* 802.11 management frame type */
            printf("Frame type classified as: MANAGMENT (0x00)\n");

            break;
        }

        case FRAME_TYPE_CONTROL:
        {
            /* 802.11 control frame type */
            printf("Frame type classified as: CONTROL (0x01)\n");

            break;
        }

        case FRAME_TYPE_DATA:
        {
            /* 802.11 data frame type */
            printf("Frame type classified as: data (0x02 - possibly carrying wireless payload)\n");

            break;
        }

        case 0x11:
        {
            // 0x11 = Reserved

            break;
        }

        default:
        {
            /* ??? */
            printf("Frame type unknown: 0x%0x\n", frame_type);

            break;
        }
    }

    // pilfer MAC addresses from 802.11 frames
    // do proper space allocation routines
    char *ieee_80211_ra = ((void *)0);
    size_t ieee_ra_sz = snprintf(((void *)0), 0, "%s", ieee_80211_mac_translation(ieee_80211_hdr->ra));

    ieee_80211_ra = malloc(ieee_ra_sz * sizeof(ieee_80211_ra));

    if (ieee_80211_ra == NULL)
    {
        fprintf(stderr, "Failed to allocate space for RA!\n");

        return;
    }

    snprintf(ieee_80211_ra, ieee_ra_sz, "%s", ieee_80211_mac_translation(ieee_80211_hdr->ra));

    char *ieee_80211_ta = ieee_80211_mac_translation(ieee_80211_hdr->ta);
    char *ieee_80211_sa = ieee_80211_mac_translation(ieee_80211_hdr->sa);

    printf("\nFrame RA (SENDTO): %s\n", ieee_80211_ra);
    printf("Frame TA (RECVFROM): %s\n", ieee_80211_ta);
    printf("Frame SA (SENDFROM): %s\n", ieee_80211_sa);

    free(ieee_80211_ra);
    free(ieee_80211_ta);
    free(ieee_80211_sa);

    /*
        Fragment number: (4 bits, bits 0, 1, 2, 3)
        Sequence number: (12 bits, bits 4 - 15)
    */
    uint8_t ieee_80211_seq_ctrl = ieee_80211_hdr->seq_control;

    // 0000 0000 0000 1111 = 0xF = 0x000F
    // no need to shift since the bit mask already has the desired bits set in the least
    // significant position so no right shift is required
    uint8_t hdr_fragment_num = (ieee_80211_seq_ctrl & 0x000F);

    // 1111 1111 1111 0000 = 0xFFF0 >> 4 = shift all bits to the right 4 times
    uint8_t hdr_sequence_num = (ieee_80211_seq_ctrl & 0xFFF0) >> 4;

    printf("Frame 802.11 header fragment #: %u\nFrame 802.11 header sequence #: %u\n",
        hdr_fragment_num,
        hdr_sequence_num
    );

    // call function from external file to handle different frame types
    // listed within '802_11ieeehdr.h'

    /* 802.11 beacon frame */
    if (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_BEACON_FRAME)
    {
        // 0x00 for management frame, 0x80 for beacon frame
        // now parse the beacon frame

        // obtain the 802.11 beacon header
        struct IEEE_80211_BEACON_HDR *ieee_80211_beacon_hdr = (struct IEEE_80211_BEACON_HDR *)(pkt + radiotap_hdr_len + sizeof(struct IEEE_80211_HDR));

        // parse 802.11 beacon header
        printf("\n** 802.11 Beacon Frame:\n=======================\n\tBeacon frame TS: %lu\n\tBF Transmit Interval: %dms\n", 
            ieee_80211_beacon_hdr->ts,              /* beacon timestamp */
            ieee_80211_beacon_hdr->beacon_interval  /* beacon transmit interval */
        );

        // parse information elements
        struct IEEE_80211_INFO_ELEMENT *ieee_80211_info_element = (struct IEEE_80211_INFO_ELEMENT *)(pkt + radiotap_hdr_len + sizeof(struct IEEE_80211_HDR) + sizeof(struct IEEE_80211_BEACON_HDR));
    
        // loop through elements
        while ((uint8_t *)ieee_80211_info_element < (uint8_t *)(pkt + hdr->caplen))
        {
            printf("\tIE ID: 0x%X, Length: %d\n", ieee_80211_info_element->id, ieee_80211_info_element->len);

            if (ieee_80211_info_element->id == 0x00)
            {
                // Service Set Identifier print operations
                if (ieee_80211_info_element->len > 0)
                {
                    printf("\tSSID: \033[0;32m"); // begin ansi escape
                    fwrite(ieee_80211_info_element->data, 1, ieee_80211_info_element->len, stdout);
                    printf("\033[0;m\n"); // die
                }
                else 
                {
                    printf("\tSSID: \033[90;1mHIDDEN\033[0;m\n\n\t\033[0;31mYou are a target.\033[0;m\n");
                }

                break;
            }

            ieee_80211_info_element = (struct IEEE_80211_INFO_ELEMENT *)((uint8_t *)ieee_80211_info_element + FRAME_ID_LEN_PAD + ieee_80211_info_element->len);

            continue;
        }
    }

    /* 802.11 probe request */
    if (IEEE_80211_MGMT_PROBE_REQUEST)
    {
        printf("** 802.11 Probe Request\n");

        /* function not imported, sequence of code in development */
    }

    return;
}


void pkt_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
    char tv_buff[64];
    char tv_str[1024];

    time_t ntime = hdr->ts.tv_sec;
    struct tm *nowtm = localtime(&ntime);

    // format time
    strftime(tv_buff, sizeof(tv_buff), "%m-%d-%Y %H:%M:%S", nowtm);

    bpf_u_int32 pkt_len = hdr->len;
    char plen_buff[16]; // haha but no (packet length buffer)

    // convert length of the packet into a string
    sprintf(plen_buff, "%u", pkt_len);

    // IEEE 802.11 radiotap compliant header information parsing
    struct IEEE_80211_RADIOTAP *ieee_radiotap_hdr = (struct IEEE_80211_RADIOTAP *)pkt;

    u_int8_t rt_hdr_ver = ieee_radiotap_hdr->it_version;
    u_int16_t rt_hdr_len = ieee_radiotap_hdr->it_len;

    // obtain bitmask value
    u_int32_t rt_hdr_bitmask = ieee_radiotap_hdr->it_present;
    rt_hdr_bitmask = le32toh(rt_hdr_bitmask); // convert to host byte order

    // print bitmask listing
    return_bitmask_listing(rt_hdr_bitmask);

    // got bitmask value? Then assume that it must be a valid frame, increment counter anyways
    PACKET_COUNT++;

    printf(" | Packet # \033[0;34m%d\033[0;m | Packet len: %s | RT len: %d (ver=%d) arrival at \033[0;32m%s\033[0;m\n", 
        PACKET_COUNT,
        plen_buff,
        rt_hdr_len,
        rt_hdr_ver,
        tv_buff
    );

    /*
        0000	0
        0001	1
        0010	2
        0011	3
        0100	4
        0101	5
        0110	6
        0111	7
        1000	8
        1001	9
        1010	A
        1011	B
        1100	C
        1101	D
        1110	E
        1111	F
    */

    // print channel information
    // 0000 0000 0000 0000 0000 0000 0000 1000 
    // shift bits right by 3 to align to the least most significant bit position 
    // (a.k.a - 3 0's shift by 3)
    // u_int32_t ieee_80211_channel = (rt_hdr_bitmask & 0x08) >> 3;
    
    /* 
        Check for additional it_present words indicated via the 31st bit (starting at 0) being set within the 
        radio tap header.
    */
    // u_int32_t radiotap_multiple_present = (rt_hdr_bitmask & (1U << 31));
    u_int32_t rt_present_offset = sizeof(struct IEEE_80211_RADIOTAP);

    int x = 0;

    do
    {
        rt_hdr_bitmask = *(u_int32_t *)(ieee_radiotap_hdr + rt_present_offset);
        rt_hdr_bitmask = le32toh(rt_hdr_bitmask);

        if (x == 0x0)
        {
            return_bitmask_listing(rt_hdr_bitmask); x++;
        }
        else
        {
            rt_present_offset += sizeof(u_int32_t);

            if (rt_present_offset >= pkt_len)
            {
                break;
            }
            else
            {
                continue;
            }
        }

    } while (true);

    // if (rt_hdr_bitmask & (1U << 31)) = check if 31st bit is set to 1 without isolating and 
    // shifting the bits around

    // obtain the 802.11 header
    struct IEEE_80211_HDR *ieee_80211_hdr = (struct IEEE_80211_HDR *)(pkt + rt_hdr_len);

    // parse 802.11 header data
    parse_ieee_80211_header(ieee_80211_hdr, pkt, hdr, rt_hdr_len);

    printf("\n");

    return;
}
#ifndef _802_11IEEE_HDR_H
#define _802_11IEEE_HDR_H

#include <stdlib.h>

#define MAX_SNAP_LEN       262144
#define FRAME_ID_LEN_PAD   0x2
#define SET_ACTIVATE       1

/* 80211 frame types */
#define FRAME_TYPE_MANAGEMENT 0x00
#define FRAME_TYPE_CONTROL    0x01
#define FRAME_TYPE_DATA       0x02

/*
    WARNING: All frame subtypes must be bit shifted by 4, this is to update the currently shifted value already
    stored within the primary source file.

    Example (before bit shifting by 4):
    -----------------------------------
        IEEE_80211_MGMT_BEACON_FRAME  (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == 0x80)

        * Results in switch case handling when filtering through raw packets 

    Example (after bit shifting by 4):
    ----------------------------------
        IEEE_80211_MGMT_BEACON_FRAME  (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == 0x08)

        * Results in the correct SSID, IE, being displayed
*/

/* define 802.11 frame subtypes (bit shifted by 4 to the right) */
#define FRAME_SUBTYPE_ASSOCIATION_REQUEST    0x00
#define FRAME_SUBTYPE_ASSOCIATION_RESPONSE   0x01
#define FRAME_SUBTYPE_REASSOCIATION_REQUEST  0x02
#define FRAME_SUBTYPE_REASSOCIATION_RESPONSE 0x03
#define FRAME_SUBTYPE_PROBE_REQUEST          0x04
#define FRAME_SUBTYPE_PROBE_RESPONSE         0x05
#define FRAME_SUBTYPE_TIMING_ADVERT          0x06
#define FRAME_SUBTYPE_RESERVED               0x07
#define FRAME_SUBTYPE_BEACON_FRAME           0x08
#define FRAME_SUBTYPE_ANNOUNCE_TRAFFIC_IND   0x09
#define FRAME_SUBTYPE_DISASSOCIATION         0x0A
#define FRAME_SUBTYPE_AUTHENTICATION         0x0B
#define FRAME_SUBTYPE_DEAUTHENTICATION       0x0C
#define FRAME_SUBTYPE_ACTION                 0x0D
#define FRAME_SUBTYPE_ACTION_NO_ACK          0x0E
#define FRAME_SUBTYPE_RESERVED_NO_2          0x0F

/* setup 802.11 parameter types: management */
#define IEEE_80211_MGMT_ASSOCIATION_REQUEST    (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_ASSOCIATION_REQUEST)
#define IEEE_80211_MGMT_ASSOCIATION_RESPONSE   (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_ASSOCIATION_RESPONSE)
#define IEEE_80211_MGMT_REASSOCIATION_REQUEST  (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_REASSOCIATION_REQUEST)
#define IEEE_80211_MGMT_REASSOCIATION_RESPONSE (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_REASSOCIATION_REQUEST)
#define IEEE_80211_MGMT_PROBE_REQUEST          (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_PROBE_REQUEST)
#define IEEE_80211_MGMT_PROBE_RESPONSE         (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_PROBE_RESPONSE)
#define IEEE_80211_MGMT_TIMING_ADVERT          (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_TIMING_ADVERT)
#define IEEE_80211_MGMT_RESERVED               (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_RESERVED)
#define IEEE_80211_MGMT_BEACON_FRAME           (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_BEACON_FRAME)
#define IEEE_80211_MGMT_ANNOUNCE_TRAFFIC_IND   (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_ANNOUNCE_TRAFFIC_IND)
#define IEEE_80211_MGMT_DISASSOCIATION         (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_DISASSOCIATION)
#define IEEE_80211_MGMT_AUTHENTICATION         (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_AUTHENTICATION)
#define IEEE_80211_MGMT_DEAUTHENTICATION       (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_DEAUTHENTICATION)
#define IEEE_80211_MGMT_ACTION                 (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_ACTION)
#define IEEE_80211_MGMT_ACTION_NO_ACK          (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_ACTION_NO_ACK)
#define IEEE_80211_MGMT_RESERVED_NO_2          (frame_type == FRAME_TYPE_MANAGEMENT && frame_subtype == FRAME_SUBTYPE_RESERVED_NO_2)

/* setup 802.11 parameter types: control */
#define IEEE_80211_CTRL_RESERVED          (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x01)
#define IEEE_80211_CTRL_RESERVED_NO_2     (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x11)
#define IEEE_80211_CTRL_TRIGGER           (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x21)
#define IEEE_80211_CTRL_TACK              (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x31)
#define IEEE_80211_CTRL_BEAMFORMING_RPOLL (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x41)
#define IEEE_80211_CTRL_VHT_NDP_ANNOUNCE  (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x51)
#define IEEE_80211_CTRL_CTRL_FRAME_EXT    (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x61)
#define IEEE_80211_CTRL_CTRL_WRAPPER      (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x71)
#define IEEE_80211_CTRL_BLOCK_ACK_REQ     (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x81)
#define IEEE_80211_CTRL_BLOCK_ACK         (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0x91)
#define IEEE_80211_CTRL_PS_POLL           (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0xA1)
#define IEEE_80211_CTRL_REQ2SEND          (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0xB1)
#define IEEE_80211_CTRL_CLR2SEND          (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0xC1)
#define IEEE_80211_CTRL_ACK               (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0xD1)
#define IEEE_80211_CTRL_CONT_FREE_END     (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0xE1)
#define IEEE_80211_CTRL_CONT_FREE_END_ACK (frame_type == FRAME_TYPE_CONTROL && frame_subtype == 0xF1)

/* setup 802.11 parameter types: data */
#define IEEE_80211_DATA                      (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x02)
#define IEEE_80211_DATA_CF_ACK               (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x12)
#define IEEE_80211_DATA_CF_POLL              (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x22)
#define IEEE_80211_DATA_CF_ACK_CF_POLL       (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x32)
#define IEEE_80211_DATA_NULL                 (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x42)
#define IEEE_80211_DATA_CF_ACK_NO_DATA       (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x52)
#define IEEE_80211_DATA_CF_POLL_NO_DATA      (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x62)
#define IEEE_80211_DATA_CF_ACK_POLL_NO_DATA  (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x72)
#define IEEE_80211_DATA_QOS_DATA             (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x82)
#define IEEE_80211_DATA_QOS_DATA_CF_ACK      (frame_type == FRAME_TYPE_DATA && frame_subtype == 0x92)
#define IEEE_80211_DATA_QOS_DATA_CF_POLL     (frame_type == FRAME_TYPE_DATA && frame_subtype == 0xA2)
#define IEEE_80211_DATA_QOS_DATA_CF_ACK_POLL (frame_type == FRAME_TYPE_DATA && frame_subtype == 0xB2)
#define IEEE_80211_DATA_QOS_NULL             (frame_type == FRAME_TYPE_DATA && frame_subtype == 0xC2)
#define IEEE_80211_DATA_RESERVED             (frame_type == FRAME_TYPE_DATA && frame_subtype == 0xD2)
#define IEEE_80211_DATA_QOS_CF_POLL          (frame_type == FRAME_TYPE_DATA && frame_subtype == 0xE2)
#define IEEE_80211_QOS_DATA_CF_ACK_POLL_NO_DATA  (frame_type == FRAME_TYPE_DATA && frame_subtype == 0xF2)


struct IEEE_80211_HDR 
{
    u_int16_t frame_control;
    u_int16_t duration_id;
    
    u_int8_t ra[0x6];
    u_int8_t ta[0x6];
    u_int8_t sa[0x6];

    u_int16_t seq_control;

}__attribute__((__packed__));


struct IEEE_80211_BEACON_HDR
{
    u_int64_t ts;
    u_int16_t beacon_interval;
    u_int16_t capability_info;

}__attribute__((__packed__));


struct IEEE_80211_INFO_ELEMENT
{
    u_int8_t id;
    u_int8_t len;
    u_int8_t data[];

}__attribute__((__packed__));

#endif
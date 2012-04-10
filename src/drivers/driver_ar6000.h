

#ifndef __DRIVER_AR6000_H_
#define __DRIVER_AR6000_H_

#ifdef __GNUC__
#define __ATTRIB_PACK           __attribute__ ((packed))
#else /* Not GCC */
#define __ATTRIB_PACK
#endif /* End __GNUC__ */ 

#define ATH_MAC_LEN 6

/*
 * There are two types of ioctl's here: Standard ioctls and
 * eXtended ioctls.  All extended ioctls (XIOCTL) are multiplexed
 * off of the single ioctl command, AR6000_IOCTL_EXTENDED.  The
 * arguments for every XIOCTL starts with a 32-bit command word
 * that is used to select which extended ioctl is in use.  After
 * the command word are command-specific arguments.
 */

/* Linux standard Wireless Extensions, private ioctl interfaces */
#define IEEE80211_IOCTL_SETPARAM             (SIOCIWFIRSTPRIV+0)
#define IEEE80211_IOCTL_SETKEY               (SIOCIWFIRSTPRIV+1)
#define IEEE80211_IOCTL_DELKEY               (SIOCIWFIRSTPRIV+2)
#define IEEE80211_IOCTL_SETMLME              (SIOCIWFIRSTPRIV+3)
#define IEEE80211_IOCTL_ADDPMKID             (SIOCIWFIRSTPRIV+4)
#define IEEE80211_IOCTL_SETOPTIE             (SIOCIWFIRSTPRIV+5)


/*
 * There is a very small space available for driver-private
 * wireless ioctls.  In order to circumvent this limitation,
 * we multiplex a bunch of ioctls (XIOCTLs) on top of a
 * single AR6000_IOCTL_EXTENDED ioctl.
 */
#define AR6000_IOCTL_EXTENDED                (SIOCIWFIRSTPRIV+31)
 

#define IEEE80211_IOCTL_SETAUTHALG              	28
#define AR6000_XIOCTL_WMI_SET_APPIE             	65
#define AR6000_XIOCTL_AP_GET_STA_LIST               99
#define AR6000_XIOCTL_AP_HIDDEN_SSID                100
#define AR6000_XIOCTL_AP_SET_NUM_STA                101
#define AR6000_XIOCTL_AP_SET_ACL_MAC                102
#define AR6000_XIOCTL_AP_GET_ACL_LIST               103
#define AR6000_XIOCTL_AP_COMMIT_CONFIG              104
#define IEEE80211_IOCTL_GETWPAIE                    105
#define AR6000_XIOCTL_AP_CONN_INACT_TIME            106
#define AR6000_XIOCTL_AP_PROT_SCAN_TIME             107
#define AR6000_XIOCTL_SET_COUNTRY                   108
#define AR6000_XIOCTL_AP_SET_DTIM                   109
#define AR6000_XIOCTL_WMI_TARGET_EVENT_REPORT       110
#define AR6000_XIOCTL_SET_IP                        111
#define AR6000_XIOCTL_AP_SET_ACL_POLICY             112
#define AR6000_XIOCTL_AP_INTRA_BSS_COMM             113
#define AR6000_XIOCTL_AP_GET_HIDDEN_SSID            114
#define AR6000_XIOCTL_AP_GET_COUNTRY                115
#define AR6000_XIOCTL_AP_GET_WMODE                  116
#define AR6000_XIOCTL_AP_GET_DTIM                   117
#define AR6000_XIOCTL_AP_GET_BINTVL                 118
#define AR6000_XIOCTL_AP_GET_RTS                    119
#define AR6000_XIOCTL_TCMD_GET_MAC                  120

/*
 * ------- AP Mode definitions --------------
 */

/*
 * !!! Warning !!!
 * -Changing the following values needs compilation of both driver and firmware
 */
#define AP_MAX_NUM_STA          8
#define AP_ACL_SIZE             10
#define IEEE80211_MAX_IE        256
#define MCAST_AID               0xFF /* Spl. AID used to set DTIM flag in the beacons */
#define DEF_AP_COUNTRY_CODE     "US "
#define DEF_AP_WMODE_G          WMI_11G_MODE
#define DEF_AP_WMODE_AG         WMI_11AG_MODE
#define DEF_AP_DTIM             5
#define DEF_BEACON_INTERVAL     100

/* AP mode disconnect reasons */
#define AP_DISCONNECT_STA_LEFT      101
#define AP_DISCONNECT_FROM_HOST     102
#define AP_DISCONNECT_COMM_TIMEOUT  103

/*
 * Used with WMI_AP_HIDDEN_SSID_CMDID
 */
#define HIDDEN_SSID_FALSE   0
#define HIDDEN_SSID_TRUE    1
typedef  struct {
    uint8_t     hidden_ssid;
} __ATTRIB_PACK WMI_AP_HIDDEN_SSID_CMD;

/*
 * Used with WMI_AP_ACL_POLICY_CMDID
 */
#define AP_ACL_DISABLE          0x00
#define AP_ACL_ALLOW_MAC        0x01
#define AP_ACL_DENY_MAC         0x02
#define AP_ACL_RETAIN_LIST_MASK 0x80
typedef  struct {
    uint8_t     policy;
} __ATTRIB_PACK WMI_AP_ACL_POLICY_CMD;

/*
 * Used with WMI_AP_ACL_MAC_LIST_CMDID
 */
#define ADD_MAC_ADDR    1
#define DEL_MAC_ADDR    2
typedef  struct {
    uint8_t     action;
    uint8_t     index;
    uint8_t     mac[ATH_MAC_LEN];
    uint8_t     wildcard;
} __ATTRIB_PACK WMI_AP_ACL_MAC_CMD;

typedef  struct {
    uint16_t    index;
    uint8_t     acl_mac[AP_ACL_SIZE][ATH_MAC_LEN];
    uint8_t     wildcard[AP_ACL_SIZE];
    uint8_t     policy;
} __ATTRIB_PACK WMI_AP_ACL;

/*
 * Used with WMI_AP_SET_NUM_STA_CMDID
 */
typedef  struct {
    uint8_t     num_sta;
} __ATTRIB_PACK WMI_AP_SET_NUM_STA_CMD;

/*
 * Used with WMI_AP_SET_MLME_CMDID
 */
typedef  struct {
    uint8_t    mac[ATH_MAC_LEN];
    uint16_t   reason;              /* 802.11 reason code */
    uint8_t    cmd;                 /* operation to perform */
#define WMI_AP_MLME_ASSOC       1   /* associate station */
#define WMI_AP_DISASSOC         2   /* disassociate station */
#define WMI_AP_DEAUTH           3   /* deauthenticate station */
#define WMI_AP_MLME_AUTHORIZE   4   /* authorize station */
#define WMI_AP_MLME_UNAUTHORIZE 5   /* unauthorize station */
} __ATTRIB_PACK WMI_AP_SET_MLME_CMD;

typedef  struct {
    uint32_t period;
} __ATTRIB_PACK WMI_AP_CONN_INACT_CMD;

typedef  struct {
    uint32_t period_min;
    uint32_t dwell_ms;
} __ATTRIB_PACK WMI_AP_PROT_SCAN_TIME_CMD;


 
/*
 * 802.11 protocol definitions.
 */
#define IEEE80211_WEP_KEYLEN        5   /* 40bit */
#define IEEE80211_WEP104_KEYLEN     13   /* 40bit */
#define IEEE80211_WEP_IVLEN         3   /* 24bit */
#define IEEE80211_WEP_KIDLEN        1   /* 1 octet */
#define IEEE80211_WEP_CRCLEN        4   /* CRC-32 */
#define IEEE80211_WEP_NKID          4   /* number of key ids */

/*
 * 802.11i defines an extended IV for use with non-WEP ciphers.
 * When the EXTIV bit is set in the key id byte an additional
 * 4 bytes immediately follow the IV for TKIP.  For CCMP the
 * EXTIV bit is likewise set but the 8 bytes represent the
 * CCMP header rather than IV+extended-IV.
 */
#define IEEE80211_WEP_EXTIV         0x20
#define IEEE80211_WEP_EXTIVLEN      4   /* extended IV length */
#define IEEE80211_WEP_MICLEN        8   /* trailing MIC */

#define IEEE80211_CRC_LEN           4



#define IEEE80211_ADDR_LEN  6       /* size of 802.11 address */
/* is 802.11 address multicast/broadcast? */
#define IEEE80211_IS_MULTICAST(_a)  (*(_a) & 0x01)
#define IEEE80211_IS_BROADCAST(_a)  (*(_a) == 0xFF)
#define WEP_HEADER (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN)
#define WEP_TRAILER IEEE80211_WEP_CRCLEN
#define CCMP_HEADER (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN + \
                    IEEE80211_WEP_EXTIVLEN)
#define CCMP_TRAILER IEEE80211_WEP_MICLEN
#define TKIP_HEADER (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN + \
                    IEEE80211_WEP_EXTIVLEN)
#define TKIP_TRAILER IEEE80211_WEP_CRCLEN
#define TKIP_MICLEN  IEEE80211_WEP_MICLEN


#define IEEE80211_ADDR_EQ(addr1, addr2)     \
    (A_MEMCMP(addr1, addr2, IEEE80211_ADDR_LEN) == 0)

#define IEEE80211_ADDR_COPY(dst,src)    A_MEMCPY(dst,src,IEEE80211_ADDR_LEN)

#define IEEE80211_KEYBUF_SIZE 16
#define IEEE80211_MICBUF_SIZE (8+8)  /* space for both tx and rx */

/*
 * NB: these values are ordered carefully; there are lots of
 * of implications in any reordering.  In particular beware
 * that 4 is not used to avoid conflicting with IEEE80211_F_PRIVACY.
 */
#define IEEE80211_CIPHER_WEP            0
#define IEEE80211_CIPHER_TKIP           1
#define IEEE80211_CIPHER_AES_OCB        2
#define IEEE80211_CIPHER_AES_CCM        3
#define IEEE80211_CIPHER_CKIP           5
#define IEEE80211_CIPHER_CCKM_KRK       6
#define IEEE80211_CIPHER_NONE           7       /* pseudo value */

#define IEEE80211_CIPHER_MAX            (IEEE80211_CIPHER_NONE+1)

#define IEEE80211_IS_VALID_WEP_CIPHER_LEN(len) \
        (((len) == 5) || ((len) == 13) || ((len) == 16))



/*
 * generic definitions for IEEE 802.11 frames
 */
struct ieee80211_frame {
    uint8_t    i_fc[2];
    uint8_t    i_dur[2];
    uint8_t    i_addr1[IEEE80211_ADDR_LEN];
    uint8_t    i_addr2[IEEE80211_ADDR_LEN];
    uint8_t    i_addr3[IEEE80211_ADDR_LEN];
    uint8_t    i_seq[2];
    /* possibly followed by addr4[IEEE80211_ADDR_LEN]; */
    /* see below */
} __ATTRIB_PACK ;

struct ieee80211_qosframe {
    uint8_t i_fc[2];
    uint8_t i_dur[2];
    uint8_t i_addr1[IEEE80211_ADDR_LEN];
    uint8_t i_addr2[IEEE80211_ADDR_LEN];
    uint8_t i_addr3[IEEE80211_ADDR_LEN];
    uint8_t i_seq[2];
    uint8_t i_qos[2];
} __ATTRIB_PACK ;

#define IEEE80211_FC0_VERSION_MASK          0x03
#define IEEE80211_FC0_VERSION_SHIFT         0
#define IEEE80211_FC0_VERSION_0             0x00
#define IEEE80211_FC0_TYPE_MASK             0x0c
#define IEEE80211_FC0_TYPE_SHIFT            2
#define IEEE80211_FC0_TYPE_MGT              0x00
#define IEEE80211_FC0_TYPE_CTL              0x04
#define IEEE80211_FC0_TYPE_DATA             0x08

#define IEEE80211_FC0_SUBTYPE_MASK          0xf0
#define IEEE80211_FC0_SUBTYPE_SHIFT         4
/* for TYPE_MGT */
#define IEEE80211_FC0_SUBTYPE_ASSOC_REQ     0x00
#define IEEE80211_FC0_SUBTYPE_ASSOC_RESP    0x10
#define IEEE80211_FC0_SUBTYPE_REASSOC_REQ   0x20
#define IEEE80211_FC0_SUBTYPE_REASSOC_RESP  0x30
#define IEEE80211_FC0_SUBTYPE_PROBE_REQ     0x40
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP    0x50
#define IEEE80211_FC0_SUBTYPE_BEACON        0x80
#define IEEE80211_FC0_SUBTYPE_ATIM          0x90
#define IEEE80211_FC0_SUBTYPE_DISASSOC      0xa0
#define IEEE80211_FC0_SUBTYPE_AUTH          0xb0
#define IEEE80211_FC0_SUBTYPE_DEAUTH        0xc0
/* for TYPE_CTL */
#define IEEE80211_FC0_SUBTYPE_PS_POLL       0xa0
#define IEEE80211_FC0_SUBTYPE_RTS           0xb0
#define IEEE80211_FC0_SUBTYPE_CTS           0xc0
#define IEEE80211_FC0_SUBTYPE_ACK           0xd0
#define IEEE80211_FC0_SUBTYPE_CF_END        0xe0
#define IEEE80211_FC0_SUBTYPE_CF_END_ACK    0xf0
/* for TYPE_DATA (bit combination) */
#define IEEE80211_FC0_SUBTYPE_DATA          0x00
#define IEEE80211_FC0_SUBTYPE_CF_ACK        0x10
#define IEEE80211_FC0_SUBTYPE_CF_POLL       0x20
#define IEEE80211_FC0_SUBTYPE_CF_ACPL       0x30
#define IEEE80211_FC0_SUBTYPE_NODATA        0x40
#define IEEE80211_FC0_SUBTYPE_CFACK         0x50
#define IEEE80211_FC0_SUBTYPE_CFPOLL        0x60
#define IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK 0x70
#define IEEE80211_FC0_SUBTYPE_QOS           0x80
#define IEEE80211_FC0_SUBTYPE_QOS_NULL      0xc0

#define IEEE80211_FC1_DIR_MASK              0x03
#define IEEE80211_FC1_DIR_NODS              0x00    /* STA->STA */
#define IEEE80211_FC1_DIR_TODS              0x01    /* STA->AP  */
#define IEEE80211_FC1_DIR_FROMDS            0x02    /* AP ->STA */
#define IEEE80211_FC1_DIR_DSTODS            0x03    /* AP ->AP  */

#define IEEE80211_FC1_MORE_FRAG             0x04
#define IEEE80211_FC1_RETRY                 0x08
#define IEEE80211_FC1_PWR_MGT               0x10
#define IEEE80211_FC1_MORE_DATA             0x20
#define IEEE80211_FC1_WEP                   0x40
#define IEEE80211_FC1_ORDER                 0x80

#define IEEE80211_SEQ_FRAG_MASK             0x000f
#define IEEE80211_SEQ_FRAG_SHIFT            0
#define IEEE80211_SEQ_SEQ_MASK              0xfff0
#define IEEE80211_SEQ_SEQ_SHIFT             4

#define IEEE80211_NWID_LEN                  32

/*
 * 802.11 rate set.
 */
#define IEEE80211_RATE_SIZE     8       /* 802.11 standard */
#define IEEE80211_RATE_MAXSIZE  15      /* max rates we'll handle */

#define WMM_NUM_AC                  4   /* 4 AC categories */

#define WMM_PARAM_ACI_M         0x60    /* Mask for ACI field */
#define WMM_PARAM_ACI_S         5   /* Shift for ACI field */
#define WMM_PARAM_ACM_M         0x10    /* Mask for ACM bit */
#define WMM_PARAM_ACM_S         4       /* Shift for ACM bit */
#define WMM_PARAM_AIFSN_M       0x0f    /* Mask for aifsn field */
#define WMM_PARAM_LOGCWMIN_M    0x0f    /* Mask for CwMin field (in log) */
#define WMM_PARAM_LOGCWMAX_M    0xf0    /* Mask for CwMax field (in log) */
#define WMM_PARAM_LOGCWMAX_S    4   /* Shift for CwMax field */

#define WMM_AC_TO_TID(_ac) (       \
    ((_ac) == WMM_AC_VO) ? 6 : \
    ((_ac) == WMM_AC_VI) ? 5 : \
    ((_ac) == WMM_AC_BK) ? 1 : \
    0)

#define TID_TO_WMM_AC(_tid) (      \
    ((_tid) < 1) ? WMM_AC_BE : \
    ((_tid) < 3) ? WMM_AC_BK : \
    ((_tid) < 6) ? WMM_AC_VI : \
    WMM_AC_VO)
/*
 * Management information element payloads.
 */

enum {
    IEEE80211_ELEMID_SSID       = 0,
    IEEE80211_ELEMID_RATES      = 1,
    IEEE80211_ELEMID_FHPARMS    = 2,
    IEEE80211_ELEMID_DSPARMS    = 3,
    IEEE80211_ELEMID_CFPARMS    = 4,
    IEEE80211_ELEMID_TIM        = 5,
    IEEE80211_ELEMID_IBSSPARMS  = 6,
    IEEE80211_ELEMID_COUNTRY    = 7,
    IEEE80211_ELEMID_CHALLENGE  = 16,
    /* 17-31 reserved for challenge text extension */
    IEEE80211_ELEMID_PWRCNSTR   = 32,
    IEEE80211_ELEMID_PWRCAP     = 33,
    IEEE80211_ELEMID_TPCREQ     = 34,
    IEEE80211_ELEMID_TPCREP     = 35,
    IEEE80211_ELEMID_SUPPCHAN   = 36,
    IEEE80211_ELEMID_CHANSWITCH = 37,
    IEEE80211_ELEMID_MEASREQ    = 38,
    IEEE80211_ELEMID_MEASREP    = 39,
    IEEE80211_ELEMID_QUIET      = 40,
    IEEE80211_ELEMID_IBSSDFS    = 41,
    IEEE80211_ELEMID_ERP        = 42,
    IEEE80211_ELEMID_RSN        = 48,
    IEEE80211_ELEMID_XRATES     = 50,
    IEEE80211_ELEMID_TPC        = 150,
    IEEE80211_ELEMID_CCKM       = 156,
    IEEE80211_ELEMID_VENDOR     = 221,  /* vendor private */
};

#define ATH_OUI             0x7f0300        /* Atheros OUI */
#define ATH_OUI_TYPE        0x01
#define ATH_OUI_SUBTYPE     0x01
#define ATH_OUI_VERSION     0x00

#define WPA_OUI             0xf25000
#define WPA_OUI_TYPE        0x01
#define WPA_VERSION         1          /* current supported version */

#define WPA_CSE_NULL        0x00
#define WPA_CSE_WEP40       0x01
#define WPA_CSE_TKIP        0x02
#define WPA_CSE_CCMP        0x04
#define WPA_CSE_WEP104      0x05

#define WPA_ASE_NONE        0x00
#define WPA_ASE_8021X_UNSPEC    0x01
#define WPA_ASE_8021X_PSK   0x02

#define RSN_OUI         0xac0f00
#define RSN_VERSION     1       /* current supported version */

#define RSN_CSE_NULL        0x00
#define RSN_CSE_WEP40       0x01
#define RSN_CSE_TKIP        0x02
#define RSN_CSE_WRAP        0x03
#define RSN_CSE_CCMP        0x04
#define RSN_CSE_WEP104      0x05

#define RSN_ASE_NONE            0x00
#define RSN_ASE_8021X_UNSPEC    0x01
#define RSN_ASE_8021X_PSK       0x02

#define RSN_CAP_PREAUTH         0x01

#define WMM_OUI                 0xf25000
#define WMM_OUI_TYPE            0x02
#define WMM_INFO_OUI_SUBTYPE    0x00
#define WMM_PARAM_OUI_SUBTYPE   0x01
#define WMM_VERSION             1

#ifdef  PYXIS_ADHOC
#define PYXIS_OUI             0xf25000        /* Pyxis OUI 00-50-F2*/
#define PYXIS_OUI_TYPE        0x06
#endif

/* WMM stream classes */
#define WMM_NUM_AC  4
#define WMM_AC_BE   0       /* best effort */
#define WMM_AC_BK   1       /* background */
#define WMM_AC_VI   2       /* video */
#define WMM_AC_VO   3       /* voice */

/* TSPEC related */
#define ACTION_CATEGORY_CODE_TSPEC                 17
#define ACTION_CODE_TSPEC_ADDTS                    0
#define ACTION_CODE_TSPEC_ADDTS_RESP               1
#define ACTION_CODE_TSPEC_DELTS                    2

typedef enum {
    TSPEC_STATUS_CODE_ADMISSION_ACCEPTED = 0,
    TSPEC_STATUS_CODE_ADDTS_INVALID_PARAMS = 0x1,
    TSPEC_STATUS_CODE_ADDTS_REQUEST_REFUSED = 0x3,
    TSPEC_STATUS_CODE_UNSPECIFIED_QOS_RELATED_FAILURE = 0xC8,
    TSPEC_STATUS_CODE_REQUESTED_REFUSED_POLICY_CONFIGURATION = 0xC9,
    TSPEC_STATUS_CODE_INSUFFCIENT_BANDWIDTH = 0xCA,
    TSPEC_STATUS_CODE_INVALID_PARAMS = 0xCB,
    TSPEC_STATUS_CODE_DELTS_SENT    = 0x30,
    TSPEC_STATUS_CODE_DELTS_RECV    = 0x31,
} TSPEC_STATUS_CODE;

#define TSPEC_TSID_MASK             0xF
#define TSPEC_TSID_S                1

/*
 * WMM/802.11e Tspec Element
 */
typedef struct wmm_tspec_ie_t {
    uint8_t     elementId;
    uint8_t     len;
    uint8_t     oui[3];
    uint8_t     ouiType;
    uint8_t     ouiSubType;
    uint8_t     version;
    uint16_t    tsInfo_info;
    uint8_t     tsInfo_reserved;
    uint16_t    nominalMSDU;
    uint16_t    maxMSDU;
    uint32_t    minServiceInt;
    uint32_t    maxServiceInt;
    uint32_t    inactivityInt;
    uint32_t    suspensionInt;
    uint32_t    serviceStartTime;
    uint32_t    minDataRate;
    uint32_t    meanDataRate;
    uint32_t    peakDataRate;
    uint32_t    maxBurstSize;
    uint32_t    delayBound;
    uint32_t    minPhyRate;
    uint16_t    sba;
    uint16_t    mediumTime;
} __ATTRIB_PACK  WMM_TSPEC_IE;


/*
 * BEACON management packets
 *
 *  octet timestamp[8]
 *  octet beacon interval[2]
 *  octet capability information[2]
 *  information element
 *      octet elemid
 *      octet length
 *      octet information[length]
 */

#define IEEE80211_BEACON_INTERVAL(beacon) \
    ((beacon)[8] | ((beacon)[9] << 8))
#define IEEE80211_BEACON_CAPABILITY(beacon) \
    ((beacon)[10] | ((beacon)[11] << 8))

#define IEEE80211_CAPINFO_ESS               0x0001
#define IEEE80211_CAPINFO_IBSS              0x0002
#define IEEE80211_CAPINFO_CF_POLLABLE       0x0004
#define IEEE80211_CAPINFO_CF_POLLREQ        0x0008
#define IEEE80211_CAPINFO_PRIVACY           0x0010
#define IEEE80211_CAPINFO_SHORT_PREAMBLE    0x0020
#define IEEE80211_CAPINFO_PBCC              0x0040
#define IEEE80211_CAPINFO_CHNL_AGILITY      0x0080
/* bits 8-9 are reserved */
#define IEEE80211_CAPINFO_SHORT_SLOTTIME    0x0400
#define IEEE80211_CAPINFO_APSD              0x0800
/* bit 12 is reserved */
#define IEEE80211_CAPINFO_DSSSOFDM          0x2000
/* bits 14-15 are reserved */

/*
 * Authentication Modes
 */

enum ieee80211_authmode {
    IEEE80211_AUTH_NONE     = 0,
    IEEE80211_AUTH_OPEN     = 1,
    IEEE80211_AUTH_SHARED   = 2,
    IEEE80211_AUTH_8021X    = 3,
    IEEE80211_AUTH_AUTO     = 4,   /* auto-select/accept */
    /* NB: these are used only for ioctls */
    IEEE80211_AUTH_WPA      = 5,  /* WPA/RSN  w/ 802.1x */
    IEEE80211_AUTH_WPA_PSK  = 6,  /* WPA/RSN  w/ PSK */
    IEEE80211_AUTH_WPA_CCKM = 7,  /* WPA/RSN IE  w/ CCKM */
};

#define IEEE80211_PS_MAX_QUEUE    50 /*Maximum no of buffers that can be queues for PS*/
  

/*
 * WPA/RSN get/set key request.  Specify the key/cipher
 * type and whether the key is to be used for sending and/or
 * receiving.  The key index should be set only when working
 * with global keys (use IEEE80211_KEYIX_NONE for ``no index'').
 * Otherwise a unicast/pairwise key is specified by the bssid
 * (on a station) or mac address (on an ap).  They key length
 * must include any MIC key data; otherwise it should be no
 more than IEEE80211_KEYBUF_SIZE.
 */
struct ieee80211req_key {
    u_int8_t    ik_type;    /* key/cipher type */
    u_int8_t    ik_pad;
    u_int16_t   ik_keyix;   /* key index */
    u_int8_t    ik_keylen;  /* key length in bytes */
    u_int8_t    ik_flags;
#define IEEE80211_KEY_XMIT  0x01
#define IEEE80211_KEY_RECV  0x02
#define IEEE80211_KEY_DEFAULT   0x80    /* default xmit key */
    u_int8_t    ik_macaddr[IEEE80211_ADDR_LEN];
    u_int64_t   ik_keyrsc;  /* key receive sequence counter */
    u_int64_t   ik_keytsc;  /* key transmit sequence counter */
    u_int8_t    ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
};
/*
 * Delete a key either by index or address.  Set the index
 * to IEEE80211_KEYIX_NONE when deleting a unicast key.
 */
struct ieee80211req_del_key {
    u_int8_t    idk_keyix;  /* key index */
    u_int8_t    idk_macaddr[IEEE80211_ADDR_LEN];
};
/*
 * MLME state manipulation request.  IEEE80211_MLME_ASSOC
 * only makes sense when operating as a station.  The other
 * requests can be used when operating as a station or an
 * ap (to effect a station).
 */
struct ieee80211req_mlme {
    u_int8_t    im_op;      /* operation to perform */
#define IEEE80211_MLME_ASSOC        1   /* associate station */
#define IEEE80211_MLME_DISASSOC     2   /* disassociate station */
#define IEEE80211_MLME_DEAUTH       3   /* deauthenticate station */
#define IEEE80211_MLME_AUTHORIZE    4   /* authorize station */
#define IEEE80211_MLME_UNAUTHORIZE  5   /* unauthorize station */
    u_int16_t   im_reason;  /* 802.11 reason code */
    u_int8_t    im_macaddr[IEEE80211_ADDR_LEN];
};

struct ieee80211req_addpmkid {
    u_int8_t    pi_bssid[IEEE80211_ADDR_LEN];
    u_int8_t    pi_enable;
    u_int8_t    pi_pmkid[16];
};

#define AUTH_ALG_OPEN_SYSTEM    0x01
#define AUTH_ALG_SHARED_KEY 0x02
#define AUTH_ALG_LEAP       0x04

struct ieee80211req_authalg {
   u_int8_t auth_alg;
};

/*
 * Request to add an IE to a Management Frame
 */
enum{
    IEEE80211_APPIE_FRAME_BEACON     = 0,
    IEEE80211_APPIE_FRAME_PROBE_REQ  = 1,
    IEEE80211_APPIE_FRAME_PROBE_RESP = 2,
    IEEE80211_APPIE_FRAME_ASSOC_REQ  = 3,
    IEEE80211_APPIE_FRAME_ASSOC_RESP = 4,
    IEEE80211_APPIE_NUM_OF_FRAME     = 5
};

/*
 * The Maximum length of the IE that can be added to a Management frame
 */
#define IEEE80211_APPIE_FRAME_MAX_LEN  200

struct ieee80211req_getset_appiebuf {
    u_int32_t app_frmtype; /* management frame type for which buffer is added */
    u_int32_t app_buflen;  /*application supplied buffer length */
    u_int8_t  app_buf[];
};

/*
 * The following definitions are used by an application to set filter
 * for receiving management frames
 */
enum {
     IEEE80211_FILTER_TYPE_BEACON      =   0x1,
     IEEE80211_FILTER_TYPE_PROBE_REQ   =   0x2,
     IEEE80211_FILTER_TYPE_PROBE_RESP  =   0x4,
     IEEE80211_FILTER_TYPE_ASSOC_REQ   =   0x8,
     IEEE80211_FILTER_TYPE_ASSOC_RESP  =   0x10,
     IEEE80211_FILTER_TYPE_AUTH        =   0x20,
     IEEE80211_FILTER_TYPE_DEAUTH      =   0x40,
     IEEE80211_FILTER_TYPE_DISASSOC    =   0x80,
     IEEE80211_FILTER_TYPE_ALL         =   0xFF  /* used to check the valid filter bits */
};

struct ieee80211req_set_filter {
      u_int32_t app_filterype; /* management frame filter type */
};

enum {
    IEEE80211_PARAM_AUTHMODE = 3,   /* Authentication Mode */
    IEEE80211_PARAM_MCASTCIPHER = 5,
    IEEE80211_PARAM_MCASTKEYLEN = 6,    /* multicast key length */
    IEEE80211_PARAM_UCASTCIPHER = 8,
    IEEE80211_PARAM_UCASTKEYLEN = 9,    /* unicast key length */
    IEEE80211_PARAM_WPA     = 10,   /* WPA mode (0,1,2) */
    IEEE80211_PARAM_ROAMING     = 12,   /* roaming mode */
    IEEE80211_PARAM_PRIVACY     = 13,   /* privacy invoked */
    IEEE80211_PARAM_COUNTERMEASURES = 14,   /* WPA/TKIP countermeasures */
    IEEE80211_PARAM_DROPUNENCRYPTED = 15,   /* discard unencrypted frames */
};

/*
 * Values for IEEE80211_PARAM_WPA
 */
#define WPA_MODE_WPA1   1
#define WPA_MODE_WPA2   2
#define WPA_MODE_AUTO   3
#define WPA_MODE_NONE   4

struct ieee80211req_wpaie {
    u_int8_t    wpa_macaddr[IEEE80211_ADDR_LEN];
    u_int8_t    wpa_ie[IEEE80211_MAX_IE];
    u_int8_t    rsn_ie[IEEE80211_MAX_IE];
};
 

#define IEEE80211_REASON_AUTH_LEAVE 0 /* TODO: CHECK value! */
#endif
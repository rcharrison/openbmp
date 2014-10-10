/*
 * Copyright (c) 2013-2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include <arpa/inet.h>
#include <cmath>

#include "MPReachAttr.h"
#include "UpdateMsg.h"


namespace bgp_msg {

/**
 * Constructor for class
 *
 * \details Handles BGP MP Reach NLRI
 *
 * \param [in]     logPtr       Pointer to existing Logger for app logging
 * \param [in]     pperAddr     Printed form of peer address used for logging
 * \param [in]     enable_debug Debug true to enable, false to disable
 */
MPReachAttr::MPReachAttr(Logger *logPtr, std::string peerAddr, bool enable_debug) {
    logger = logPtr;
    debug = enable_debug;

    peer_addr = peerAddr;
}

MPReachAttr::~MPReachAttr() {
}

/**
 * Parse the MP_REACH NLRI attribute data
 *
 * \details
 *      Will parse the MP_REACH_NLRI data passed.  Parsed data will be stored
 *      in parsed_data.
 *
 *      \see RFC4760 for format details.
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void MPReachAttr::parseReachNlriAttr(int attr_len, u_char *data, bgp_msg::UpdateMsg::parsed_update_data &parsed_data) {
    mp_reach_nlri nlri;
    char buf[INET6_ADDRSTRLEN];
    uint8_t prefix_len;
    uint8_t prefix_bytes;
  
    struct nexthop {
        int        af;
        union {
            struct in_addr v4;
            struct in6_addr v6;
        } na;
    } nh;
   

    /*
     * Set the MP NLRI struct
     */
    // Read address family
    memcpy(&nlri.afi, data, 2); data += 2; attr_len -= 2;
    bgp::SWAP_BYTES(&nlri.afi);                     // change to host order

    nlri.safi = *data++; attr_len--;                 // Set the SAFI - 1 octet

    /*
     * The type of next hop is better determined by the length than via the AFI/SAFI types
     * of the MP_REACH_NLRI path attribute. See RFC 4684, 5549, and 6074.
     *
     * Next Hop Length			Type
     * 4				IPv4
     * 12				RD, IPv4 (RD always 0)
     * 16				IPv6
     * 24				RD, IPv6 (RD always 0)
     * 32				IPv6 gaddr,lladdr
     */
    nlri.nh_len = *data++; attr_len--;              // Set the next-hop length - 1 octet
    
    switch (nlri.nh_len) {
        case 12:
            data += 8;  /* Skip RD, FALLTHROUGH */
        case 4:	
            nh.af = AF_INET;
            memcpy(&nh.na.v4, data, 4); // Does not need to be byte-swapped
            data += 4;
            inet_ntop(AF_INET, &nh.na.v4.s_addr, buf, sizeof(buf));
            parsed_data.attrs[ATTR_TYPE_NEXT_HOP] = std::string(buf);
            break;
        case 32:
            nh.af = AF_INET6;
            memcpy(&nh.na.v6, data, 16);
            data += 32; // Skip over link local address
            inet_ntop(AF_INET6, &nh.na.v6.s6_addr, buf, sizeof(buf));
            parsed_data.attrs[ATTR_TYPE_NEXT_HOP] = std::string(buf);
            break;
        case 24:
            data += 8; /* Skip RD, FALLTHROUGH */
        case 16:
            nh.af = AF_INET6;
            memcpy(&nh.na.v6, data, 16);
            inet_ntop(AF_INET6, &nh.na.v6.s6_addr, buf, sizeof(buf));
            parsed_data.attrs[ATTR_TYPE_NEXT_HOP] = std::string(buf);
            data += 16;
            break;
        default:
            LOG_INFO("Unexpected next hop length: %d, skipping.", nlri.nh_len);
            break;
    }
    LOG_INFO("%s", parsed_data.attrs[ATTR_TYPE_NEXT_HOP].c_str());

    attr_len -= nlri.nh_len;
      
    //nlri.next_hop = data;  data += nlri.nh_len; attr_len -= nlri.nh_len;    // Set pointer position for nh data
    nlri.reserved = *data++; attr_len--;             // Set the reserve octet
    nlri.nlri_data = data;                          // Set pointer position for nlri data
    nlri.nlri_len = attr_len;                       // Remaining attribute length is for NLRI data

    /*
     * Make sure the parsing doesn't exceed buffer
     */
    if (attr_len < 0) {
        LOG_NOTICE("%s: MP_REACH NLRI data length is larger than attribute data length, skipping parse", peer_addr.c_str());
        return;
    }

    SELF_DEBUG("%s: afi=%d safi=%d nh_len=%d reserved=%d", peer_addr.c_str(),
                nlri.afi, nlri.safi, nlri.nh_len, nlri.reserved);

    /*
     * Next-hop and NLRI data depends on the AFI & SAFI
     *  Parse data based on AFI + SAFI
     */
    //parseAfi(nlri, parsed_data);
    while (attr_len > 0) {
        prefix_len = *(data++); attr_len -= 1;
        prefix_bytes = prefix_len / 8;
        if (prefix_len % 8) ++prefix_bytes;
        parsePrefix(nlri.afi, nlri.safi, data, prefix_len, prefix_bytes, parsed_data);
        data += prefix_bytes; attr_len -= prefix_bytes;
    }
}

void MPReachAttr::formatRD(unsigned char *data, char *buf, size_t len) {
    uint16_t rd_type;
    char ip_buf[INET6_ADDRSTRLEN];
    union {
        struct in_addr ip;
        uint16_t       as; 
        uint32_t       as4;
    } ga;
    union {
        uint16_t       val16;
        uint32_t       val32;
    } la;

    memcpy(&rd_type, data, 2); data += 2;
    rd_type = ntohs(rd_type);

    switch (rd_type) {
        case 0:
            memcpy(&ga.as, data, 2); data += 2;
            ga.as = ntohs(ga.as);
            memcpy(&la.val32, data, 4); data += 4;
            la.val32 = ntohl(la.val32);
            snprintf(buf, len-1, "%" PRIu16 ":%" PRIu32, ga.as, la.val32);
            break;
        case 1:
            memcpy(&ga.ip, data, 4); data += 4;
            ga.ip.s_addr = ntohl(ga.ip.s_addr);
            memcpy(&la.val16, data, 2); data += 2;
            la.val16 = ntohs(la.val16);
            inet_ntop(AF_INET, &ga.ip.s_addr, ip_buf, sizeof(ip_buf));
            snprintf(buf, len-1, "%s:%" PRIu16, ip_buf, la.val16);
            break;
        case 2:     
            memcpy(&ga.as4, data, 4); data += 4;
            ga.as4 = ntohl(ga.as4);
            memcpy(&la.val16, data, 2); data += 2;
            snprintf(buf, len-1, "%" PRIu32 ":%" PRIu16, ga.as4, la.val16);
            break;
        default:
            LOG_INFO("Unkown RD Type %d", rd_type);
            break;
    }
}

void MPReachAttr::parsePrefix(uint16_t afi, uint8_t safi, unsigned char *data, uint8_t prefix_len, uint8_t prefix_bytes, UpdateMsg::parsed_update_data &parsed_data) {

    bgp::prefix_tuple prefix;
    char rd_buf[256];
    char addr_buf[INET6_ADDRSTRLEN];
    char prefix_buf[256];
    uint8_t label_stack_length;
    struct in_addr v4;
    struct in6_addr v6;

    LOG_INFO("%s: afi=%" PRIu16 ",safi=%" PRIu8 ",prefix_len=%" PRIu8 ",prefix_bytes=%" PRIu8,
        peer_addr.c_str(), afi, safi, prefix_len, prefix_bytes);

    switch (afi) {
        case 1:
            switch (safi) {
                //case 1:
                //case 2:
                //case 4:
                case 128: // L3VPN
                    // Assume a single label for now - not safe but usually works, don't store it yet
                    prefix.type = bgp::PREFIX_VPN_V4;
                    data += 3; prefix_bytes -= 3; prefix_len -= 24;
                    formatRD(data, rd_buf, sizeof(rd_buf)); // formatRD advances data pointer!
                    data += 8; prefix_bytes -= 8; prefix_len -= 64;
                    bzero(&v4.s_addr, sizeof(v4.s_addr));
                    memcpy(&v4.s_addr, data, prefix_bytes); data += prefix_bytes;
                    inet_ntop(AF_INET, &v4.s_addr, addr_buf, sizeof(addr_buf));
                    snprintf(prefix_buf, sizeof(prefix_buf) - 1, "%s:%s/%" PRIu8, rd_buf, addr_buf, prefix_len); 
                    prefix.len = prefix_len;
                    prefix.prefix.assign(prefix_buf);
                    parsed_data.advertised.push_back(prefix); 
                    //LOG_INFO("%s", prefix_buf);
                    break;
                //case 129:
                default:
                    LOG_INFO("%s: AFI=%d, SAFI=%d not implemented yet, skipping", peer_addr.c_str(), afi, safi);
                    break;
            }
            break;
        case 2:
            switch (safi) {
                case 4: // skip label, fallthrough (for now ... need to actually check label stack)
                    data += 3;
                case 1:
                    prefix.type = bgp::PREFIX_UNICAST_V6;
                    bzero(&v6.s6_addr, sizeof(v6.s6_addr));
                    memcpy(&v6.s6_addr, data, prefix_bytes);
                    inet_ntop(AF_INET6, &v6.s6_addr, addr_buf, sizeof(addr_buf));
                    prefix.len  = prefix_len;
                    prefix.prefix.assign(addr_buf);
                    parsed_data.advertised.push_back(prefix);
                    break;
                case 2:
                case 128:
                case 129:
                default:
                    LOG_INFO("%s: AFI=%d, SAFI=%d not implemented yet, skipping", peer_addr.c_str(), afi, safi);
                    break;
            }
            break;
        case 25:
            switch (safi) {
                case 65:
                default:
                    LOG_INFO("%s: AFI=%d, SAFI=%d not implemented yet, skipping", peer_addr.c_str(), afi, safi);
                    break;
            }
            break;   
        default:
            LOG_INFO("%s: MP_REACH AFI=%d is not implemented yet, skipping", peer_addr.c_str(), afi);
            break;
    }
    //LOG_INFO("AFI/SAFI %d/%d", afi, safi);
}

/**
 * MP Reach NLRI parse based on AFI
 *
 * \details Will parse the next-hop and nlri data based on AFI.  A call to
 *          the specific SAFI method will be performed to further parse the message.
 *
 * \param [in]   nlri           Reference to parsed NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void MPReachAttr::parseAfi(mp_reach_nlri &nlri, UpdateMsg::parsed_update_data &parsed_data) {

    switch (nlri.afi) {
        case bgp::BGP_AFI_IPV6 :  // IPv6
            parseAfiUnicstIPv6(nlri, parsed_data);
            break;

        // TODO: Add other AFI parsing

        default : // Unknown
            LOG_INFO("%s: MP_REACH AFI=%d is not implemented yet, skipping", peer_addr.c_str(), nlri.afi);
            return;
    }
}

/**
 * MP Reach NLRI parse for BGP_AFI_IPV6
 *
 * \details Will handle parsing the SAFI's for address family ipv6
 *
 * \param [in]   nlri           Reference to parsed NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void MPReachAttr::parseAfiUnicstIPv6(mp_reach_nlri &nlri, UpdateMsg::parsed_update_data &parsed_data) {
    u_char      ipv6_raw[16];
    char        ipv6_char[40];

    bzero(ipv6_raw, sizeof(ipv6_raw));

    /*
     * Decode based on SAFI
     */
    switch (nlri.safi) {
        case bgp::BGP_SAFI_UNICAST: // Unicast IPv6 address prefix

            // Next-hop is an IPv6 address - Change/set the next-hop attribute in parsed data to use this next-hop
            memcpy(ipv6_raw, nlri.nlri_data, nlri.nh_len);
            inet_ntop(AF_INET6, ipv6_raw, ipv6_char, sizeof(ipv6_char));
            parsed_data.attrs[ATTR_TYPE_NEXT_HOP] = std::string(ipv6_char);

            // Data is an IPv6 address - parse the address and save it
            parseNlriData_v6(nlri.nlri_data, nlri.nlri_len, parsed_data.advertised);
            break;

        default :
            LOG_INFO("%s: MP_REACH AFI=ipv6 SAFI=%d is not implemented yet, skipping for now",
                     peer_addr.c_str(), nlri.afi, nlri.safi);
            return;
    }
}

/**
 * Parses mp_reach_nlri and mp_unreach_nlri
 *
 * \details
 *      Will parse the NLRI encoding as defined in RFC4760 Section 5 (NLRI Encoding).
 *
 * \param [in]   data       Pointer to the start of the prefixes to be parsed
 * \param [in]   len        Length of the data in bytes to be read
 * \param [out]  prefixes   Reference to a list<prefix_tuple> to be updated with entries
 */
void MPReachAttr::parseNlriData_v6(u_char *data, uint16_t len, std::list<bgp::prefix_tuple> &prefixes) {
    u_char            ipv6_raw[16];
    char              ipv6_char[40];
    u_char            addr_bytes;
    bgp::prefix_tuple tuple;

    if (len <= 0 or data == NULL)
        return;

    // TODO: Can extend this to support multicast, but right now we set it to unicast v6
    // Set the type for all to be unicast V6
    tuple.type = bgp::PREFIX_UNICAST_V6;

    // Loop through all prefixes
    for (size_t read_size=0; read_size < len; read_size++) {
        bzero(ipv6_raw, sizeof(ipv6_raw));

        // set the address in bits length
        tuple.len = *data++;

        // Figure out how many bytes the bits requires
        addr_bytes = tuple.len / 8;
        if (tuple.len % 8)
           ++addr_bytes;

        // if the route isn't a default route
        if (addr_bytes > 0) {
            memcpy(ipv6_raw, data, addr_bytes);
            data += addr_bytes;
            read_size += addr_bytes;

            // Convert the IP to string printed format
            inet_ntop(AF_INET6, ipv6_raw, ipv6_char, sizeof(ipv6_char));
            tuple.prefix.assign(ipv6_char);

            // Add tuple to prefix list
            prefixes.push_back(tuple);
        }
    }
}


} /* namespace bgp_msg */

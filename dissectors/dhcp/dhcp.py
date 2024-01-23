from chunk import HeterogeneousList, EnumPackChunk, ValuePackChunk, ListChunk, BinaryDataChunk
from dissectors.inet.inet import IPPackChunk

BOOTP_OP_ENUM = {
    1: "BOOTREQUEST",
    2: "BOOTREPLY"
}

DHCPTypes = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
    9: "force_renew",
    10: "lease_query",
    11: "lease_unassigned",
    12: "lease_unknown",
    13: "lease_active",
}

BOOTP_OPTIONS_ENUM = {
    0: "pad",
    1: "subnet_mask",
    2: "time_zone",
    3: "router",
    4: "time_server",
    5: "IEN_name_server",
    6: "name_server",
    7: "log_server",
    8: "cookie_server",
    9: "lpr_server",
    12:  "(12) Host Name",
    14: "dump_path",
    15: "domain",
    17: "root_disk_path",
    22: "max_dgram_reass_size",
    23: "default_ttl",
    24: "pmtu_timeout",
    28: "broadcast_address",
    35: "arp_cache_timeout",
    36: "ether_or_dot3",
    37: "tcp_ttl",
    38: "tcp_keepalive_interval",
    39: "tcp_keepalive_garbage",
    40: "NIS_domain",
    41: "NIS_server",
    42: "NTP_server",
    43: "vendor_specific",
    44: "NetBIOS_server",
    45: "NetBIOS_dist_server",
    50: "requested_addr",
    51: "lease_time",
    53: "(53) DHCP Message Type (Discover)",
    54: "server_id",
    55: "param_req_list",
    56: "error_message",
    57: "max_dhcp_size",
    58: "renewal_time",
    59: "rebinding_time",
    60: "vendor_class_id",
    61:  "(61) Client Identifier",
    64: "NISplus_domain",
    65: "NISplus_server",
    69: "SMTP_server",
    70: "POP3_server",
    71: "NNTP_server",
    72: "WWW_server",
    73: "Finger_server",
    74: "IRC_server",
    75: "StreetTalk_server",
    76: "StreetTalk_Dir_Assistance",
    82: "relay_agent_Information",
    #53: ByteEnumField("message-type", 1, DHCPTypes),
    #             55: DHCPRequestListField("request-list"),
    255: "(255) End"
}


class BOOTP_Option(HeterogeneousList):
    name = "BOOTP Option"
    template = [(EnumPackChunk, {"name": "option_type", "enum": BOOTP_OPTIONS_ENUM, "fmt": "B"}),
                (ValuePackChunk, {"name": "option_length",
                                  "fmt": "B",
                                  "conditional_fn": lambda x: x.parent.option_type.value != 0xff}),
                (BinaryDataChunk, {"name": "option_data",
                                   "length_from": lambda x: x.parent.option_length.value,
                                   "conditional_fn": lambda x: x.parent.option_type.value != 0xff})]


class BOOTP_OptionList(ListChunk):
    name = "BOOTP OptionList"

    def __init__(self, *args, **kwargs):
        super(BOOTP_OptionList, self).__init__(element_type=(BOOTP_Option, {}), *args, **kwargs)

    def read_from_stream(self, streamdata):
        print("just going to read options till I get to an end option")
        self.value = []
        chunk_type, chunk_args = self.element_type
        remaining_data = streamdata[:]
        while True:
            new_chunk = chunk_type(**chunk_args)
            remaining_data = new_chunk.read_from_stream(remaining_data)
            self.value.append(new_chunk)
            if new_chunk.option_type == 0xff:
                return remaining_data


class BOOTP(HeterogeneousList):
    name = "BOOTP"
    template = [(EnumPackChunk, {"name": "op", "default": 1, "enum": BOOTP_OP_ENUM, "fmt": "B"}),
                (ValuePackChunk, {"name": "htype", "default": 1, "fmt": "B"}),
                (ValuePackChunk, {"name": "hlen", "default": 6, "fmt": "B"}),
                (ValuePackChunk, {"name": "hops", "default": 0, "fmt": "B"}),
                (ValuePackChunk, {"name": "xid", "default": 0, "fmt": "i"}),
                (ValuePackChunk, {"name": "secs", "default": 0, "fmt": "h"}),
                (ValuePackChunk, {"name": "flags", "default": 0, "fmt": "2B"}),
                (IPPackChunk, {"name": "ciaddr", "default": "0.0.0.0"}),
                (IPPackChunk, {"name": "yiaddr", "default": "0.0.0.0"}),
                (IPPackChunk, {"name": "siaddr", "default": "0.0.0.0"}),
                (IPPackChunk, {"name": "giaddr", "default": "0.0.0.0"}),
                (BinaryDataChunk, {"name": "chaddr", "default": "", "length": 6}),
                (BinaryDataChunk, {"name": "chpad", "default": "", "length": 10}),
                (BinaryDataChunk, {"name": "sname", "default": "", "length": 64}),
                (BinaryDataChunk, {"name": "file", "default": "", "length": 128}),
                (BinaryDataChunk, {"name": "magic_cookie", "default": "", "length": 4}),
                (BOOTP_OptionList, {"name": "options",
                             "length_from": lambda x: 48})]  # TODO: How to calculate this?



import re


class Rule:

    def __init__(self):
        self.header =  {
            "action": None,
            "protocol": None,
            "src_ip": None,
            "src_port": None,
            "direction": None,
            "dst_ip": None,
            "dst_port": None
        }

        self.general_options = {
            "msg": None,
            # the message to print with the packet dump or alert.

            "reference": None,
            # references to external attack identification systems.

            "gid": None,
            # identify  what part of Snort generates the event
            # when a particular rule fires.

            "sid": None,
            # uniquely identify Snort rules.

            "rev": None,
            # identify revisions of Snort rules.

            "classtype": None,
            # categorize a rule as detecting  an attack that is part
            # of a more general type of attack class.

            "metadata": None
            # embed additional information about the rule,
            # typically in a key-value format.  Keys: engine
            # ( Indicate a Shared Library Rule ) ex: "shared",
            # soid ( Shared Library Rule Generator and
            # SID ) ex: "gid|sid", service ( Target-Based
            # Service Identifier ) ex: "http"
    }
        self.payload_options = {
            "content": None,
            # search for specific content in the packet payload

            "protected_content": None,
            # look at the raw packet data, ignoring any decoding
            # that was done by preprocessors

            "hash": None,
            # specify the hashing  algorithm to use when matching a
            # protected_content rule

            "length": None,
            # original length of the content specified
            # in a protected_content rule digest (0-65536)

            "nocase": None,
            # Snort should look for the specific pattern, ignoring case

            "rawbytes": None,
            # look at the raw packet data, ignoring any decoding
            # that was done by preprocessors

            "depth": None,
            # how far into a packet Snort should search for the specified pattern

            "offset": None,
            # where to start searching for a pattern within a packet

            "distance": None,
            # how far into a packet Snort should ignore before starting to search
            # for the specified pattern relative to the end of the previous pattern match

            "within": None,
            # at most N bytes are between pattern matches

            "http_client_body": None,
            # restrict the search to the body of an HTTP client request

            "http_cookie": None,
            # restrict the search to the extracted Cookie Header field

            "http_raw_cookie": None,
            # restrict the search to the extracted UNNORMALIZED Cookie Header field

            "http_header": None,
            # restrict the search to the extracted Header fields

            "http_raw_header": None,
            # restrict the search to the extracted UNNORMALIZED Header fields

            "http_method": None,
            # restrict the search to the extracted Method from a HTTP client request

            "http_uri": None,
            # restrict the search to the UNNORMALIZED request URI field

            "http_raw_uri": None,
            # restrict the search to the NORMALIZED request URI field

            "http_stat_code": None,
            # restrict the search to the extracted Status code field
            # from a HTTP server response

            "http_stat_msg": None,
            # restrict the search to the extracted Status Message field
            # from a HTTP server response

            "http_encode": None,
            # enable alerting based on encoding type present in a HTTP client
            # request or a HTTP server response

            "fast_pattern": None,
            # sets the content within a rule to be used
            # with the fast pattern matcher

            "uricontent": None,
            # searche the normalized request URI field

            "urilen": None,
            # specify the exact length, the minimum length,
            # the maximum length, or range of URI lengths to match

            "isdataat": None,
            # verify that the payload has data at a specified location

            "pcre": None,
            # allow rules to be written using perl compatible regular expressions

            "pkt_data": None,
            # set the cursor used for detection to the raw transport payload

            "file_data": None,
            # This option sets the cursor used for detection
            # to one of the following buffers:
            # 1. HTTP response body
            # 2. HTTP de-chunked response body
            # 3. HTTP decompressed response
            # 4. HTTP normalized response body
            # 5. HTTP UTF normalized response body
            # 6. All of the above
            # 7. SMTP/POP/IMAP data body
            # 8. Base64 decoded MIME attachment
            # 9. Non-Encoded MIME attachment
            # 10. Quoted-Printable decoded MIME attachment
            # 11. Unix-to-Unix decoded attachment

            "base64_decode": None,
            # decode the base64 encoded data

            "base64_data": None,
            # set the cursor used for detection to the beginning
            # of the base64 decoded buffer if present

            "byte_test": None,
            # test a byte field against a specific value (with operator)

            "byte_jump": None,
            # allow rules to read the length of a portion of data, then skip that
            # far forward in the packet.

            "byte_extract": None,
            # It reads in some number of bytes from the
            # packet payload and saves it to a variable.

            "byte_math": None,
            # Perform a mathematical operation on an extracted
            # value and a specified value or existing variable,
            # and store the outcome in a new resulting variable

            "ftpbounce": None,
            # detects FTP bounce attacks.

            "asn1": None,
            # decode a packet or a portion of a packet, and looks for various
            # malicious encodings.

            "cvs": None,
            # detect invalid entry strings

            "dce_iface": None,
            # For DCE/RPC based rules it has been necessary
            # to set flow-bits based on a client bind to a
            # service to avoid false positives.

            "dce_opnum": None,
            # represents a specific function call to an interface.

            "dce_stub_data": None,
            # This option is used to place the cursor at the beginning of the DCE/RPC
            # stub data SIP Preprocessor provides ways to  tackle Common Vulnerabilities
            # and Exposures(CVEs) related with SIP found over the past few years.

            "sip_method": None,
            # check for specific SIP request methods.

            "sip_stat_code": None,
            # check the SIP response status code. This option matches if
            # any one of the state codes specified matches the status
            # codes of the SIP response.

            "sip_header": None,
            # restrict the search to the extracted Header fields of a
            # SIP message request or a response. This works similar to
            # file_data.

            "sip_body": None,
            # The sip_body keyword places the cursor at the
            # beginning of the Body fields of a SIP message.
            # This works similar to file_data and
            # dce_stub_data. The message body includes
            # channel information using SDP protocol.

            "gtp_type": None,
            # check for specific GTP types. User can input message type
            # value, an integer in [0, 255], or a string.

            "gtp_info": None,
            # check for specific GTP information element.
            # This keyword restricts the search to the
            # information element field.(0, 255)

            "gtp_version": None,
            # check for specific GTP version.

            "ssl_version": None,
            # track the version negotiated between the endpoints of the SSL encryption.

            "ssl_state": None,
            # track the state of the SSL encryption during the process of hello and key exchange.
        }

        self.non_payload_options = {
            "fragoffset": None,
            # allow one to compare the IP fragment offset field against a
            # decimal value.

            "ttl": None,
            # check the IP time-to-live value

            "tos": None,
            # check the IP TOS field for a specific value

            "id": None,
            # check the IP ID field for a specific value

            "ipopts": None,
            # check if a specific IP option is present

            "fragbits": None,
            # check if fragmentation and reserved bits are set
            # in the IP header.

            "dsize": None,
            # test the packet payload size

            "flags": None,
            # check if specific TCP flag bits are present.

            "flow": None,
            # allow rules to only apply to certain directions of the traffic

            "flowbits": None,
            # allow rules to track states during a transport protocol session.

            "seq": None,
            # check for a specific TCP sequence number

            "ack": None,
            # check for a specific TCP acknowledge number

            "window": None,
            # check for a specific TCP window size

            "itype": None,
            # check for a specific ICMP type value

            "icode": None,
            # check for a specific ICMP code value

            "icmp_id": None,
            # check for a specific ICMP ID value

            "icmp_seq": None,
            # check for a specific ICMP sequence value

            "rpc": None,
            # check for a RPC application, version, and
            # procedure numbers in SUNRPC CALL requests

            "ip_proto": None,
            # allow checks against the IP protocol header

            "sameip": None,
            # check if the source ip is the same as the destination IP.

            "stream_reassemble": None,
            # allows a rule to enable or disable TCP stream
            # reassembly on matching traffic.

            "stream_size": None
            # allows a rule to match traffic
            # according to the number of bytes observed,
            # as determined by the TCP sequence numbers.
        }
        self.post_detection_options = {
            "logto": None,
            # log all packets that trigger this rule to a special output log file

            "session":  None,
            # extract user data from TCP Sessions

            "resp": None,
            # enable an active response that kills the offending session

            "tag": None,
            #  log more than just the single packet that triggered the rule.
            #  Format: tag:host, <count>, <metric>, <direction>;
            #          tag:session[, <count>, <metric>][, exclusive];

            "replace": None,
            # replace the prior matching content with the given string (only inline mode)

            "detection_filter": None,
            # defines a rate which must be exceeded by a source or destination host before a rule can generate an event.
        }

    def string_matching_checked(self):
        if self.payload_options["content"] or self.payload_options["content-list"]\
                or self.payload_options['uricontent'] or self.payload_options['pcre']:
            return True
        return False

    def flow_checked(self):
        """  To detect if rule applies on a flow  """
        if self.non_payload_options["flow"]:
            return True
        return False

    def payload_options_checked(self):
        for item in self.payload_options.values():
            if item:
                return True
        return False

    def packet_counter_checked(self):
        """ To check if the rule applies only on k-packets among the all matched ones """
        packet_checker = False
        counter_checker = False
        if self.post_detection_options["tag"]:
            for item in self.post_detection_options["tag"]:
                if re.match(r'^[0-9]+$', item):
                    counter_checker = True
                if item == "packets":
                    packet_checker = True
        return packet_checker and counter_checker




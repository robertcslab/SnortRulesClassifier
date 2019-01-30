import re
from SnortRulesClassifier.SnortRule import Rule


class RuleParser:
    """"  This Class should parse a Snort rule from a string   """
    '''
    sample rule:
    alert tcp $HOME_NET 2589 -> $EXTERNAL_NET any (msg:"MALWARE-BACKDOOR - Dagger_1.4.0"; flow:to_client,established;
    content:"2|00 00 00 06 00 00 00|Drives|24 00|"; depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)

    sample preprocessor rule:
    alert ( msg: "BO_TRAFFIC_DETECT"; sid: 1; gid: 105; rev: 1; metadata: rule-type preproc, policy balanced-ips drop,\
    policy security-ips drop ; classtype:trojan-activity; reference:cve,1999-0660; )
    '''
    @staticmethod
    def extract_header_values(rule_string):
        snort_header_dict = Rule().header

        if re.match(r"(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))", rule_string):
            header = rule_string.split('(', 1)
            header_values = ''.join(header[0]).split(' ')
            snort_header_dict["action"] = header_values[0]
            snort_header_dict["protocol"] = header_values[1]
            snort_header_dict["src_ip"] = header_values[2]
            snort_header_dict["src_port"] = header_values[3]
            snort_header_dict["direction"] = header_values[4]
            snort_header_dict["dst_ip"] = header_values[5]
            snort_header_dict["dst_port"] = header_values[6]
            return snort_header_dict

        else:
            msg = 'Syntax Error, Please check if rule has been closed properly %s ' % rule_string
            raise SyntaxError(msg)

    @staticmethod
    def extract_option_values(rule_string):
        snort_general_options_dict = Rule().general_options
        snort_payload_options_dict = Rule().payload_options
        snort_non_payload_options_dict = Rule().non_payload_options
        snort_post_detection_options_dict = Rule().post_detection_options

        if re.match(r"(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))", rule_string):
            options = rule_string.split('(', 1)[1]  # options will be started after '('
            options = options.split(';')  # to separate each option
            for item in options:
                option_argument = []
                sub_options = item.split(':')
                if len(sub_options) > 1:
                    option_key = sub_options[0].lstrip()
                    sub_options = sub_options[1].split(',')
                    for sub_item in sub_options:
                        option_argument.append(sub_item.lstrip())

                    if option_key in snort_general_options_dict.keys():
                        snort_general_options_dict[option_key] = option_argument

                    elif option_key in snort_payload_options_dict.keys():
                        snort_payload_options_dict[option_key] = option_argument

                    elif option_key in snort_non_payload_options_dict.keys():
                        snort_non_payload_options_dict[option_key] = option_argument

                    elif option_key in snort_post_detection_options_dict.keys():
                        snort_post_detection_options_dict[option_key] = option_argument

                    else:
                        pass
                        # raise appropriate Error
            return snort_general_options_dict, snort_payload_options_dict, snort_non_payload_options_dict, snort_post_detection_options_dict

        else:
            msg = 'Syntax Error, Please check if rule has been closed properly %s ' % rule_string
            raise SyntaxError(msg)

    def rule_parser(self, rule_string):
        new_rule = Rule()
        new_rule.header = self.extract_header_values(rule_string)
        options = self.extract_option_values(rule_string)
        new_rule.general_options = options[0]
        new_rule.payload_options = options[1]
        new_rule.non_payload_options = options[2]
        new_rule.post_detection_options = options[3]

        return new_rule

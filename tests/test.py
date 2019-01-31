import unittest

from SnortRulesClassifier.SnortRule import Rule
from SnortRulesClassifier.SnortRulesParser import RuleParser


class TestSnortRulesParser(unittest.TestCase):
    def setUp(self):
        self.test_rule = 'alert tcp $HOME_NET 2589 -> $EXTERNAL_NET any ' \
                    '(msg:"MALWARE-BACKDOOR - Dagger_1.4.0"; flow:to_' \
                    'client,established; content:"2|00 00 00 06 00 00 00|Drives|24 00|";' \
                    ' depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)'

    def test_extract_header_values(self):
        # TODO: Write another test for a preprocessor rule(with no header)
        header = RuleParser.extract_header_values(self.test_rule)
        self.assertEqual(header['action'], 'alert')
        self.assertEqual(header['protocol'], 'tcp')
        self.assertEqual(header['src_ip'],'$HOME_NET')
        self.assertEqual(header['src_port'],'2589')
        self.assertEqual(header['direction'],'->')
        self.assertEqual(header['dst_ip'],'$EXTERNAL_NET')
        self.assertEqual(header['dst_port'],'any')

    def test_extract_option_values(self):
        # TODO: Write a full-option test case
        general_options, payload_options, non_payload_options = RuleParser.extract_option_values(self.test_rule)

        self.assertEqual(general_options['msg'][0], '"MALWARE-BACKDOOR - Dagger_1.4.0"')
        self.assertEqual(general_options['metadata'][0], 'ruleset community')
        self.assertEqual(general_options['classtype'][0], 'misc-activity')
        self.assertEqual(general_options['sid'][0], '105')
        self.assertEqual(general_options['rev'][0], '14')

        self.assertEqual(payload_options['content'][0],'"2|00 00 00 06 00 00 00|Drives|24 00|"')
        self.assertEqual(payload_options['depth'][0],'16')

        self.assertEqual(non_payload_options['flow'][0],'to_client')
        self.assertEqual(non_payload_options['flow'][1],'established')

    def test_classify_rules(self):
        # ToDo: Write required test cases after finishing snort-classifier
        pass


class TestSnortRule(unittest.TestCase):
    def setUp(self):
        self.test_snort_rule = Rule()
        self.test_snort_rule.payload_options = {
            'content': 'test content',
        }
        self.test_snort_rule.non_payload_options = {
            'flow': 'to_client'
        }

    def test_sting_matching_checked(self):
        res = Rule.string_matching_checked(self.test_snort_rule)
        self.assertEqual(res, True)

    def test_flow_checked(self):
        res = Rule.flow_checked(self.test_snort_rule)
        self.assertEqual(res, True)

    def test_payload_options_checked(self):
        res = Rule.payload_options_checked(self.test_snort_rule)
        self.assertEqual(res, True)


if __name__ == '__main__':
    unittest.main()

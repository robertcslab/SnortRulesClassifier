import itertools

from SnortRulesClassifier.SnortRulesParser import RuleParser

input_file_name = "rules.txt"
output_file_name = "classifiedrules.txt"


class SnortRulesManager:

    snort_rules_classes = {
        1: "Header Filters on a Single Packet",
        2: "String Matching on a Single Packet",
        3: "String Matching to a Bounded Depth in a Flow",
        4: "String Matching Across an Entire Flow, Delivered in-order",
        5: "String Matching Across an Entire Flow, Delivered out-of-order",
        6: "No Type Detected"
    }

    @staticmethod
    def parse_rules_from_file():
        rule_files = open(input_file_name, "r")
        for line in rule_files:
            parser = RuleParser()
            yield RuleParser.rule_parser(parser, line)

    @staticmethod
    def classify_rule(snort_rule):
        class_id = 6
        if not snort_rule.payload_options_checked():
            class_id = 1
        elif snort_rule.string_matching_checked() and not snort_rule.flow_checked():
            class_id = 2
        elif snort_rule.string_matching_checked() and snort_rule.flow_checked() and snort_rule.packet_counter_checked():
            class_id = 3
        # TODO: Parse pcre (Perl regex) to check order of string matching
        return class_id

    @staticmethod
    def write_classified_rules_to_file(class_list):
        output_file = open(output_file_name, "w")
        input_rules = open(input_file_name, "r")
        for item in itertools.zip_longest(class_list, input_rules):
            output_file.write(SnortRulesManager.snort_rules_classes[item[0]] + "\t" + item[1] + "\n")

    def get_class_type(self, class_id):
        pass

    def get_rule(self, rule_id):
        pass


if __name__ == "__main__":
    classified_rules = []
    mngr = SnortRulesManager()
    for rule in SnortRulesManager.parse_rules_from_file():
        classified_rules.append(mngr.classify_rule(rule))

    print(classified_rules)  # for test
    mngr.write_classified_rules_to_file(classified_rules)



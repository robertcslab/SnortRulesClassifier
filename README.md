# SnortRulesClassifier
To classify Snort rules regarding their level of granularity


**Requirements**: Python 3.7+

**Install**: 
-   Go to the SnortRulesClassifier directory
-   Type python SnortRuleClassifier.py

**Project Description**:

SnortRulesClassifier is a tool to parse Snort rules and classify them into the following categories:

-   Header filters on a single packet (Rules with no payload option)

-   String matching on a single packet (Rules with 'content' related options)

-   String matching to a bounded depth in a flow (Content-related rules which log more than just the single packet that triggered the rule.')

-   String matching across an entire flow (this class is temporary)






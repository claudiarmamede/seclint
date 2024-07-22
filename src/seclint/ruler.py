from seclint.rule import Rule
from seclint.config import Config
from seclint.section import *

class Ruler:
    def __init__(self, config : Config) -> None:
        self.rules = []
        for rule in config.default_rules:
            section_name = rule.split('_')[0]
            section = globals()[section_name.capitalize()] # Header, Summary, Explanation, Reporter
            default_rule = config.default_rules[rule]
            self.rules.append(Rule(rule,
                                   default_rule['active'],
                                   default_rule['type'],
                                   default_rule['value'] if 'value' in default_rule.keys() else None,
                                   section()
                                   ))

    def get_section_rules(self, section : Section) -> list:

        return [rule for rule in self.rules
                if type(rule.section) == type(section)]




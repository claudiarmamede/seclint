import click
from seclint.rule import Rule
from seclint.config import Config
from seclint.ruler import Ruler
from seclint.report import Report
from seclint.section import Section


class Compliance:
    def __init__(self, path_config : str = "config/rules.yml") -> None:
        self.ruler = Ruler(Config(path=path_config))
        self.results = []
        self.score = 0
        self.warnings = 0
        self.errors = 0

    def check(self, report : Report, section : Section = None):
        """ Check report compliance against the interpretability standard. """
        """ TODO: check section only """
        sections = [section] if section else report.sections
        mid = 0
        for section in sections:
            section_rules = self.ruler.get_section_rules(
                section
            )

            for rule in section_rules:
                if rule.active:
                    func_rule = getattr(Rule, rule.name)
                    result = func_rule(rule, section)
                    # ordering warnings
                    if not result.is_compliant and result.type == 1:
                        self.results = [result] + self.results
                        mid += 1
                        self.errors += 1
                    if not result.is_compliant and result.type == 0:
                        self.results = self.results[0:mid] + \
                            [result] + self.results[mid::]
                        self.warnings += 1
                    if result.is_compliant:
                        self.results = self.results + [result]

    def calculate_score(self):
        no_rules = len(self.ruler.rules)
        rules_in_compliance = sum(
            [result.is_compliant for result in self.results])
        self.score = (rules_in_compliance / no_rules)

    def report(self, quiet, score, out):
        def get_symbol(is_compliant, warning_type):
            if is_compliant:
                return "✅"
            return "❌" if warning_type == 1 else "🟡"

        for result in self.results:
            symbol = get_symbol(result.is_compliant, result.type)
            doc_link = click.style(result.link, fg="blue")
            if result.is_compliant and quiet:
                return
            click.echo(f"{symbol}  {result.message} {doc_link}")

        color = 'green' if self.errors == 0 and self.warnings == 0 else 'yellow'
        summary = f"\nfound {self.errors} error(s), {self.warnings} warning(s);"

        if score:
            secom_link = f"[\u001b]8;;https://tqrg.github.io/secom\u001b\\SECOM\u001b]8;;\u001b\\]"
            click.echo(
                click.style(
                    (f"{summary} 🎯 Commit message is {self.score*100:.2f}% in compliance with interpretability convention."),
                    fg=color,
                    bold=True))
        else:
            click.echo(click.style(summary, fg=color, bold=True))

    def get_results(self):
        return self.results

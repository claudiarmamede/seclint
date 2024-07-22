import re

from seclint.section import Header, Summary, Explanation, Fix, Reporter
from seclint.extractor import Extractor
from seclint.tags import HEADER, SUMMARY, EXPLANATION, FIX, REPORTER

import re

class Report:
    def __init__(self, lines) -> None:
        self.raw_text = lines
        self.sections = []

    def parse(self):        
        # Parse report
        pattern = re.compile(
            r'(?P<tag>' + '|'.join(HEADER + SUMMARY + EXPLANATION + FIX + REPORTER) + r'):\s*(?P<content>.*?)(?=\n\w|$)',
            re.DOTALL
        )

        # Finding all matches
        matches = pattern.finditer(self.raw_text)

        # Extracting the data into a dictionary
        parsed_data = {match.group('tag'): match.group('content').strip() for match in matches}
        
        sections = {'Header':[],
                    'Summary': [],
                    'Explanation': [],
                    'Fix': [],
                    'Reporter': []}
        
        # Setup NER extractor
        extractor = Extractor()

        # Group tags per sections
        for tag, content in parsed_data.items():
            if tag in HEADER:
                sections['Header'].append((tag, content))

            if tag in SUMMARY:
                sections['Summary'].append((tag, content))

            if tag in EXPLANATION:
                sections['Explanation'].append((tag, content))

            if tag in FIX:
                sections['Fix'].append((tag, content))

            if tag in REPORTER:
                sections['Reporter'].append((tag, content))

        self.sections = [
            Header(lines = sections['Header'], entities=extractor.entities(sections['Header'])),
            Summary(lines = sections['Summary'], entities=extractor.entities(sections['Summary'])),
            Explanation(lines = sections['Explanation'], entities=extractor.entities(sections['Explanation'])),
            Fix(lines = sections['Fix'], entities=extractor.entities(sections['Fix'])),
            Reporter(lines = sections['Reporter'], entities=extractor.entities(sections['Reporter']))   
        ]

    def get_sections(self):
        return self.sections

    def get_text(self):
        return self.raw_text

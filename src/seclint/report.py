import re

from seclint.section import Header, Summary, Explanation, Fix, Reporter
from seclint.extractor import Extractor
from seclint.tags import HEADER, SUMMARY, EXPLANATION, FIX, REPORTER


class Report:
    def __init__(self, lines) -> None:
        self.raw_text = lines
        self.sections = []

    def parse(self):
        def is_header(block):
            return re.search(rf"({'|'.join(HEADER)}):", block, re.IGNORECASE)

        def is_summary(block): 
            return re.search(rf"({'|'.join(SUMMARY)}):", block, re.IGNORECASE)

        def is_explanation(block): 
            return re.search(rf"({'|'.join(EXPLANATION)}):", block, re.IGNORECASE)

        def is_fix(block):
            return re.search(rf"({'|'.join(FIX)}):", block, re.IGNORECASE)

        def is_reporter(block):
            return re.search(rf"({'|'.join(REPORTER)}):", block, re.IGNORECASE)

        # Split into sections based on new lines
        blocks = re.split(r'\n{3,}', self.raw_text.strip())
        
        # Setup NER extractor
        extractor = Extractor()

        # Parse report into sections and assign a type to each section
        for block in blocks:
                if is_header(block):
                    self.sections.append(
                        Header(text = block, entities=extractor.entities(block))
                    )
                elif is_summary(block):
                    self.sections.append(
                        Summary(text = block, entities=extractor.entities(block))
                    )
                elif is_explanation(block):
                    self.sections.append(
                        Explanation(text = block, entities=extractor.entities(block))
                    )
                elif is_fix(block):
                    self.sections.append(
                        Fix(text = block, entities=extractor.entities(block))
                    )
                elif is_reporter(block):
                    self.sections.append(
                        Reporter(text = block, entities=extractor.entities(block))
                    )
                else:
                    print(f"Idk what this is {block}")

    def get_sections(self):
        return self.sections

    def get_text(self):
        return self.raw_text

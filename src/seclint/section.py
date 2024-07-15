import re
from seclint.tags import HEADER, SUMMARY, EXPLANATION, FIX, REPORTER
"""This module abstracts the different sections of a report."""


class Section:
    def __init__(self, text : str = None, entities : dict = None) -> None:
        self.text : str = text
        self.entities : dict = entities if entities is not None else {}
        self.lines : list = text.splitlines() if text is not None else []
        self.tags : dict = {}


    def set_entities(self, entities : dict) -> None:
        self.entities = entities


    def get_all_entities(self) -> list:
        return [item for sublist in list(self.entities.values()) for item in sublist]


class Header(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)
        self.set_tags()
    
    def set_tags(self):
        def match_header_tags(line):
            return re.findall(rf"^({'|'.join(HEADER)})", line, re.IGNORECASE | re.MULTILINE )
        
        for line in self.lines:
            self.tags[line] = [match.lower() for match in match_header_tags(line)]
    
class Summary(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)
        self.set_tags()

    def set_tags(self):
        def match_summary_tags(lines): 
            return re.findall(rf"^({'|'.join(SUMMARY)})", lines, re.IGNORECASE | re.MULTILINE )
        
        for line in self.lines:
            self.tags[line] = [match.lower() for match in match_summary_tags(line)]

class Explanation(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)
        self.set_tags()
        
    def set_tags(self):
        def match_explanation_tags(lines): 
            return re.findall(rf"^({'|'.join(EXPLANATION)})", lines, re.IGNORECASE | re.MULTILINE )
        
        for line in self.lines:
            self.tags[line] = [match.lower() for match in match_explanation_tags(line)]

class Fix(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)
        self.set_tags()
        
    def set_tags(self):
        def match_explanation_tags(lines): 
            return re.findall(rf"^({'|'.join(FIX)})", lines, re.IGNORECASE | re.MULTILINE )
        
        for line in self.lines:
            self.tags[line] = [match.lower() for match in match_explanation_tags(line)]


class Reporter(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)
        self.set_tags()

    def set_tags(self):
        def match_reporter_tags(lines):
            return re.findall(rf"^({'|'.join(REPORTER)})", lines, re.IGNORECASE | re.MULTILINE )

        for line in self.lines:
            self.tags[line] = [match.lower() for match in match_reporter_tags(line)]

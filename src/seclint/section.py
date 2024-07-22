from seclint.tags import HEADER, SUMMARY, EXPLANATION, FIX, REPORTER
"""This module abstracts the different sections of a report."""


class Section:
    def __init__(self, lines : list = [], entities : dict = {}) -> None:
        self.lines : list = lines
        self.text : str = '\n'.join([f'{tag} : {content}' for (tag, content) in lines])
        self.entities : dict = entities # if entities is not None else {}
        self.tags : list = [tag for tag, content in lines]

    def get_all_entities(self) -> list:
        return [item for sublist in list(self.entities.values()) for item in sublist]


class Header(Section):
    def __init__(self, lines:list=[], entities:dict={}) -> None:
        super().__init__(lines, entities)

class Summary(Section):
    def __init__(self, lines:list=[], entities:dict={}) -> None:
        super().__init__(lines, entities)

class Explanation(Section):
    def __init__(self, lines:list=[], entities:dict={}) -> None:
        super().__init__(lines, entities)

class Fix(Section):
    def __init__(self, lines:list=[], entities:dict={}) -> None:
        super().__init__(lines, entities)

class Reporter(Section):
    def __init__(self, lines:list=[], entities:dict={}) -> None:
        super().__init__(lines, entities)

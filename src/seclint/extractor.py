import spacy
import os


class Extractor:
    def __init__(self) -> None:
        self.engine = spacy.load("en_core_web_lg")
        self.engine.remove_pipe("ner")
        self.engine.add_pipe("entity_ruler").from_disk(
            f"{os.path.dirname(os.path.abspath(__file__))}/entities/patterns.jsonl")
        
    def entities(self, block : str) -> dict:
        """Extract entities per line in block"""
        entities = {}
        lines = block.splitlines()

        for line in lines:
            entities[line] = [(ent.text, ent.label_) for ent in self.engine(line).ents]

        return entities
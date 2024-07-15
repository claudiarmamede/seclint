import os
import yaml


class Config:
    def __init__(self, path : str, openai_key=None) -> None:

        def read_config(file):
                with open(file, "r") as fin:
                    return yaml.load(fin, Loader=yaml.FullLoader)

        self.rules_config_path = f"{os.path.dirname(os.path.abspath(__file__))}/{path}"
        self.default_rules = read_config(self.rules_config_path)
        
        # if openai_key:
        #     self.openai_key = openai_key

    # def save_key(self):
    #     with open(self.openai_key_config_path, 'w') as f:
    #         f.write(f"OPENAI_KEY={self.openai_key}")
            
    # def read_key(self):
    #     with open(self.openai_key_config_path) as f:
    #         self.openai_key = f.readlines()[0].split('=')[1]

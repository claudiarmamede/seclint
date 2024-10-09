# import re
from seclint.tags import HEADER, SUMMARY, EXPLANATION, FIX, REPORTER

class Result:
    def __init__(self, rule_name, result, wtype, wmessage) -> None:
        self.rule_name = rule_name
        self.is_compliant = result
        self.type = wtype
        self.message = wmessage
        self.link = f"[\u001b]8;;https://tqrg.github.io/secomlint/#/secomlint-rules?id={self.rule_name.replace('_', '-')}\u001b\\{self.rule_name}\u001b]8;;\u001b\\]"


class Rule:
    def __init__(self, name, active, wtype, value, section) -> None:
        self.name = name
        self.active = active
        self.wtype = wtype
        self.value = value
        self.section = section

    def header_max_length(self, section):
        """rule: header_max_length"""
        section_text = section.text
        if len(section_text) <= self.value:
            return Result('header_max_length', True, self.wtype,
                           f'Header size is within the max length ({self.value} chars).')
        return Result('header_max_length', False, self.wtype,
                       f'Header has more than {self.value} chars.')

    def header_is_not_empty(self, section):
        """rule: header_is_not_empty"""
        section_text = section.text
        if len(section_text) > 0:
            return Result('header_is_not_empty', True, self.wtype,
                           'Header is not empty.')
        return Result('header_is_not_empty', False, self.wtype,
                       'Header is empty.')

    def header_has_tag(self, section):
        """rule: header_has_tag"""  
        section_tags = section.tags[0]
        if section_tags in HEADER:
            return Result('header_has_tag', True, self.wtype,
                           f'Header starts with {section_tags} type')
        return Result('header_has_tag', False, self.wtype,
                       f'Header is missing the {HEADER} type at the start.')

    def header_has_weakness(self, section):
        """rule: header_has_weakness
           condition: header contains entity = {CWEID, BUGSFRAMEWORK}
           
           NOTE: we dropped CVEs because this will be used before the cve is assigned"""
        entities = section.get_all_entities()

        if len(entities) > 0:
            # print(entities)
            weakness = [list(entity)[0] 
                        for entity in entities 
                            if list(entity)[1] == 'CWEID'
                            or list(entity)[1] == 'VULNID'
                            or list(entity)[1] == 'FLAW']
                
            if len(weakness) > 0:
                return Result('header_has_weakness', True, self.wtype,
                            'Header mentions a weakness (CWE/BF) id.')
            return Result('header_has_weakness', False, self.wtype,
                        'Header has tag weakness but a weakness (CWE/BF) id/name was not mentioned.')
        return Result('header_has_weakness', False, self.wtype,
                'Header section is missing weakness tag/mention.')

    def header_has_severity(self, section):
        """ rule: header_has_severity
            condition: header contains entity = {SEVERITY} 

            TODO: make something similar to cWE-id here. take into account numbers and the string "severity:" 
            """
        entities = section.get_all_entities()
        
        if len(entities) > 0:
            severity = [list(entity)[0]
                        for entity in entities 
                            if list(entity)[1] == 'SEVERITY']
             
            if len(severity) > 0:
                return Result('header_has_severity', True, self.wtype, 'Header has SEVERITY.')
        return Result('header_has_severity', False, self.wtype, 'Header is missing SEVERITY at the end.')


    def summary_has_what(self, section):
        """rule: summary_has_what 
            condition: summary section contains tag <what> and something useful after it
        """
        entities = section.entities
        tags = section.tags 

        if 'what' not in tags: 
            return Result('summary_has_what', False, self.wtype, 'Summary is missing the <what> tag.')

        line_entities = entities['what']
        description = [list(line_entities)[0] 
                        for entity in line_entities 
                            if list(entity)[1] == 'SECWORD' 
                            or list(entity)[1] == 'FLAW' 
                            or list(entity)[1] == 'CWEID' 
                            or list(entity)[1] == 'VULNID']
        
        if len(description) > 0:
            return Result('summary_has_what', True, self.wtype, 'Summary has the <what> tag.')
        else:
            return Result('summary_has_what', False, self.wtype, 'Summary has the <what> tag but is missing a description of the problem.')


    def summary_has_why(self, section):
        """rule: summary_has_why 
            condition: summary section contains tag <why> and something useful after it
        """
        entities = section.entities
        tags = section.tags 

        if 'why' not in tags: 
            return Result('summary_has_why', False, self.wtype, 'Summary is missing the <why> tag.')

        line_entities = entities['why']
        description = [list(line_entities)[0] 
                            for entity in line_entities 
                                if list(entity)[1] == 'SECWORD' 
                                    or list(entity)[1] == 'FLAW' 
                                    or list(entity)[1] == 'SEVERITY']
        if len(description) > 0:
            return Result('summary_has_why', True, self.wtype, 'Summary has the <why> tag.')
        else:
            return Result('summary_has_why', False, self.wtype, 'Summary has the <why> tag but does not explain why the issue is relevant.')


    def summary_has_how(self, section):
        """rule: summary_has_how 
            condition: summary section contains tag <how> and something useful after it
        """
        entities = section.entities
        tags = section.tags 

        if 'how' not in tags:
            return Result('summary_has_how', False, self.wtype, 'Summary is missing the <how> tag.') 
        
        line_entities = entities['how']
        description = [list(line_entities)[0] 
                            for entity in line_entities 
                                if list(entity)[1] == 'SECWORD' 
                                or list(entity)[1] == 'FLAW' ]
        
        if len(description) > 0:
            return Result('summary_has_how', True, self.wtype, 'Summary has the <how> tag.')
        else:
            return Result('summary_has_how', False, self.wtype, 'Summary has the <how> tag but does not explain how to trigger the problem.')



    def summary_has_when(self,section):
        """rule: summary_has_when
            condition: summary section contains tag <when> and something useful after it
        """      
        entities = section.entities
        tags = section.tags 

        if 'when' not in tags:
            return Result('summary_has_when', False, self.wtype, 'Summary is missing the <when> tag.') 
                
        line_entities = entities['when']
        date = [list(line_entities)[0] 
                    for entity in line_entities 
                        if list(entity)[1] == 'DATE' ]
                
        if len(date) > 0:
            return Result('summary_has_when', True, self.wtype, 'Summary has the <when> tag.')
        else:
            return Result('summary_has_when', False, self.wtype, 'Summary has the <when> tag but does not say when the problem was found.')


    def summary_has_where(self, section):
        """rule: summary_has_where
            condition: summary section contains tag <where> and something useful after it
        """
        entities = section.entities
        tags = section.tags

        if 'where' not in tags:
            return Result('summary_has_where', False, self.wtype, 'Summary is missing the <where> tag.')

        line_entities = entities['where']
        location = [list(line_entities)[0]
                        for entity in line_entities
                            if list(entity)[1] == 'LOCATION']

        if len(location) > 0:
            return Result('summary_has_where', True, self.wtype, 'Summary has the <where> tag.')
        else:
            return Result('summary_has_where', False, self.wtype, 'Summary has the <where> tag but does not say where the problem is')
                          

    def summary_max_length(self, section):
        """rule: summary_max_length 
            condition: summary section contains tag <how> and something useful after it
        """    
        section_text = section.text

        if section.text and len(section_text) <= self.value:
            return Result('summary_max_length', True, self.wtype,
                           f'Summary size is within the max length ({self.value} chars).')
        return Result('summary_max_length', False, self.wtype,
                       f'Summary has more than {self.value} chars.')
    

    # TODO: add taint information here to confirm the variables
    def explanation_has_unchecked_vars(self, section):
        """rule:explanation_has_unchecked_vars"""
        tags = section.tags 

        if 'unchecked-vars' in tags:
            return Result('explanation_has_unchecked_vars', True, self.wtype, 'Explanation has the <unchecked-vars> tag.')
                
        return Result('explanation_has_unchecked_vars', False, self.wtype, 'Explanation is missing information about <unchecked-vars>.')
    

    def explanation_has_checked_vars(self, section):
        """rule:explanation_has_checked_vars"""
        tags = section.tags 

        if 'checked-vars' in tags:
                return Result('explanation_has_checked_vars', True, self.wtype, 'Explanation gives information regarding checked variables.')
                
        return Result('explanation_has_checked_vars', False, self.wtype, 'Explanation is missing information about <checked-vars>.')
    

    def explanation_has_sources(self, section):
        """rule:explanation_has_sources"""
        tags = section.tags 

        if 'code-sources' in tags or 'sources' in tags:
            return Result('explanation_has_sources', True, self.wtype, 'Explanation gives information regarding sources.')
                
        return Result('explanation_has_sources', False, self.wtype, 'Explanation is missing information about <sources>.')
    
    def explanation_has_sinks(self, section):
        """rule:explanation_has_sinks"""
        tags = section.tags 

        if 'sinks' in tags or 'code-sinks' in tags:
            return Result('explanation_has_sinks', True, self.wtype, 'Explanation gives information regarding sinks.')
                
        return Result('explanation_has_sinks', False, self.wtype, 'Explanation is missing information about <sinks>.')
    

    def fix_is_not_empty(self, section):
        """rule: fix_is_not_empty"""
        section_text = section.text
        if len(section_text) > self.value:
            return Result('fix_is_not_empty', True, self.wtype, 'There is a suggested fix.')
        return Result('fix_is_not_empty', False, self.wtype, 'There are no fix suggestions.')


    def fix_has_action(self, section):
        """rule: fix_has_action
            condition: fix """
        entities = section.get_all_entities()
    
        if len(entities) > 0:
            severity = [list(entity)[0]
                        for entity in entities 
                            if list(entity)[1] == 'ACTION']
            
            if len(severity) > 0:
                return Result('fix_has_action', True, self.wtype, 'Suggested fix has actionable items.')
        return Result('fix_has_action', False, self.wtype, 'Suggested fix does not provide actionable items')


    def reporter_has_reported_by(self, section):
        """rule: reporter_has_reported_by
            condition: has the <reported-by> tag and identifies a person """
        entities = section.entities
        tags = section.tags 

        if 'reported-by' not in tags:
            return Result('reporter_has_reported_by', False, self.wtype, 'Report is missing the <reported-by> tag.')

        line_entities = (entities['reported-by']) 
        contacts = [list(line_entities)[0] 
                                   for entity in line_entities 
                                        if list(entity)[1] == 'EMAIL' ]
                
        if len(contacts) > 0:
            return Result('reporter_has_reported_by', True, self.wtype, 'Report has <reported-by> tag.')
        else:
            return Result('reporter_has_reported_by', False, self.wtype, 'Report has the <reported-by> tag but does not identify a person.')

    def reporter_has_co_reported_by(self, section):
        """rule: reporter_has_co_reported_by
            condition: has the <co-reported-by> tag and identifies a person """
        entities = section.entities
        tags = section.tags

        if 'co-reported-by' not in tags:
            return Result('reporter_has_co_reported_by', False, self.wtype, 'Report is missing the <co-reported-by> tag.')

        line_entities = (entities['co-reported-by'])
        contacts = [list(line_entities)[0]
                                   for entity in line_entities
                                        if list(entity)[1] == 'EMAIL' ]

        if len(contacts) > 0:
            return Result('reporter_has_co_reported_by', True, self.wtype, 'Report has <co-reported-by> tag.')
        else:
            return Result('reporter_has_co_reported_by', False, self.wtype, 'Report has the <co-reported-by> tag but does not identify a person.')
        
    def reporter_has_method(self, section):
        """rule: reporter_has_method
            condition: has the <method> tag and identifies a person """
        entities = section.entities
        tags = section.tags

        if 'method' not in tags:
            return Result('reporter_has_method', False, self.wtype, 'Report is missing the <method> tag.')

        line_entities = (entities['method'])
        methods = [list(line_entities)[0]
                                   for entity in line_entities
                                        if list(entity)[1] == 'DETECTION' ]

        if len(methods) > 0:
            return Result('reporter_has_method', True, self.wtype, 'Report has <method> tag.')
        else:
            return Result('reporter_has_method', False, self.wtype, 'Report has the <method> tag but does not specify the adopted strategy.')   

    
    def reporter_has_reference(self, section):
        """rule: reporter_has_reference
            condition: has the <reference> tag and identifies a person """
        entities = section.entities
        tags = section.tags

        if 'reference' not in tags:
            return Result('reporter_has_reference', False, self.wtype, 'Report is missing the <reference> tag.')

        line_entities = (entities['reference'])
        methods = [list(line_entities)[0]
                                   for entity in line_entities
                                        if list(entity)[1] == 'URL' ]

        if len(methods) > 0:
            return Result('reporter_has_reference', True, self.wtype, 'Report has <reference> tag.')
        else:
            return Result('reporter_has_reference', False, self.wtype, 'Report has the <reference> tag but does not provide a URL to the tool.')

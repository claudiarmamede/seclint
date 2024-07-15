### Check report compliance against the interpretability standard
This moduled is based on [SECOMLINT](https://github.com/TQRG/secomlint). 

#### Installation
1. Run ```pip install .```


#### Usage
If you are running this module by itself, use the following command:
``` $ python main.py [arguments]``` , where [arguments] are:

- `--report` (str): Path to the security report\*.
- `--show-score` (bool): If TRUE, output compliance score.
- `--quiet` (bool): If TRUE, show only compliance errors and warnings.
- `--out` (str): Path to the output folder.

\* The taint analysis report does not have a strict structure. You can use any text document containing additional/helpful about the vulnerability.


#### Examples
```$ python main.py --report=PATH/TO/REPORT.txt --compliance=True```


## Rule Configuration

The linter has a default configuration (located at ```seclint/src/config```) that can be overridden with a `.yml` file using the following syntax: 

```
rule_name:
    active: {true | false}
    type: {0 - warning | 1 - error}
    value: {string | regex}
```

An example would be:

```
header_starts_with:
  active: true
  type: 0
  value: 'vuln-detect'
header_has_weakness:
  active: false
```
(The rule `header_starts_with` is active, outputs warnings and checks if header starts with type fix. The rule `header_has_weakness` was deactivated.)


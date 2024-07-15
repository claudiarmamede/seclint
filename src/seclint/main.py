import click
from seclint.report import Report
from seclint.compliance import Compliance


def read_report(fpath:str) -> str: 
    """Read and parse report"""
    try:
        with open(fpath, 'r') as f:
            raw_report = f.read()
            report = Report(raw_report)
            report.parse()
            return report
    except Exception as exc:
        print (f"An error occurred: {exc}")
        return None


@click.command()
@click.option("--report", default="reports/bad_report.txt", help="Report file path")
@click.option("--show-score", is_flag=True, default=False, help="Show compliance score.")
@click.option("--quiet", is_flag=True, default=False, help="If true, display only compliance errors and warnings.")
@click.option("--out", help="Output report to file name.")
@click.option("--rules-config", default="config/rules.yml", help="Rule configuration file path name.")
def main(report:str, show_score:bool, quiet:bool, out:str, rules_config:str):
    
    report = read_report(report)
    
    if not report: 
        print(f"❌ Can't read report at {report}") 
        return
   
    compliance = Compliance(path_config=rules_config)
    compliance.check(report)
    compliance.calculate_score()
    compliance.report(quiet, show_score, out)
    
    if(show_score):
        print(f"[ Compliance score: {compliance.score} ]")
    
    return


if __name__ == '__main__':
    main()

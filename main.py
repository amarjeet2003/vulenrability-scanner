import pandas as pd

from scripts.report_to_csv import (
    parse_horusec_report,
    parse_semgrep_report, 
    parse_vcg_report, 
    parse_snyk_report,
    parse_bearer_report, 
    parse_bandit_report,
    parse_pyt_report,
    normalize_vulnerability, 
    output_to_csv,
    map_cwe_ids
)
from scripts.common_parsing import find_common_entries, find_unique_entries

def main():
    # Paths to the reports
    horusec_report_path = 'data/horusecresult-11224.txt'
    # vcg_report_path = 'data/VCG-260924.txt'
    snyk_report_path = 'data/snykresult11224.txt'
    excel_cwe_path = 'data/snyk_code_security_rules.xlsx'
    semgrep_report_path = 'data/sempython11224.txt'
    # bearer_report_path = 'data/Bearer-260924.txt'
    bandit_report_path='data/bandit11224.txt'
    pyreport_report_path = 'data/pyt11224.txt'
    # Parse and normalize the reports
    horusec_vulnerabilities = parse_horusec_report(horusec_report_path)
    
    # vcg_vulnerabilities = parse_vcg_report(vcg_report_path)
    snyk_vulnerabilities = parse_snyk_report(snyk_report_path)
    semgrep_vulnerabilities = parse_semgrep_report(semgrep_report_path)
    # bearer_vulnerabilities = parse_bearer_report(bearer_report_path)
    bandit_vulnerabilities = parse_bandit_report(bandit_report_path)
    pyreport_vulnerabilities = parse_pyt_report(pyreport_report_path)

    cwe_map = map_cwe_ids(excel_cwe_path)

    normalized_horusec_vulns = [normalize_vulnerability(vuln) for vuln in horusec_vulnerabilities]
    # normalized_vcg_vulns = [normalize_vulnerability(vuln) for vuln in vcg_vulnerabilities]
    normalized_snyk_vulns = [normalize_vulnerability(vuln) for vuln in snyk_vulnerabilities]
    normalized_semgrep_vulns = [normalize_vulnerability(vuln) for vuln in semgrep_vulnerabilities]
    # normalized_bearer_vulns = [normalize_vulnerability(vuln) for vuln in bearer_vulnerabilities]
    normalized_bandit_vulnerabilities = [normalize_vulnerability(vuln) for vuln in bandit_vulnerabilities]
    normalized_pyreport_vulns = [normalize_vulnerability(vuln) for vuln in pyreport_vulnerabilities]


    output_to_csv(normalized_horusec_vulns, 'results/normalized_horusec_vulnerabilities.csv', cwe_map)
    # output_to_csv(normalized_vcg_vulns, 'results/normalized_vcg_vulnerabilities.csv', cwe_map)
    output_to_csv(normalized_snyk_vulns, 'results/normalized_snyk_vulnerabilities.csv', cwe_map)
    output_to_csv(normalized_semgrep_vulns, 'results/normalized_semgrep_vulnerabilities.csv', cwe_map)
    # output_to_csv(normalized_bearer_vulns, 'results/normalized_bearer_vulnerabilities.csv', cwe_map)
    output_to_csv(normalized_bandit_vulnerabilities, 'results/bandit_report_output.csv', cwe_map)
    output_to_csv(normalized_pyreport_vulns, 'results/normalized_pyreport_vulnerabilities.csv', cwe_map)
    # Load the CSVs back into DataFrames
    sources = {
        'Horusec': pd.read_csv('results/normalized_horusec_vulnerabilities.csv'),
        # 'VCG': pd.read_csv('results/normalized_vcg_vulnerabilities.csv'),
        'Snyk': pd.read_csv('results/normalized_snyk_vulnerabilities.csv'),
        'Semgrep': pd.read_csv('results/normalized_semgrep_vulnerabilities.csv'),
        # 'Bearer': pd.read_csv('results/normalized_bearer_vulnerabilities.csv'),
        'Bandit':pd.read_csv('results/bandit_report_output.csv'),
        'Pyreport': pd.read_csv('results/normalized_pyreport_vulnerabilities.csv'),
    }

    # Find common entries across all sources
    common_df = find_common_entries(sources)

    if not common_df.empty:
        common_df.to_csv('results/final_common_vulnerabilities_v2.csv', index=False)
        print(f"Found {len(common_df)} common entries. Stored in 'results/final_common_vulnerabilities_v2.csv'.")
    else:
        print("No common entries found.")

    # Find unique entries across all sources
    unique_df = find_unique_entries(sources, common_df)

    if not unique_df.empty:
        unique_df.to_csv('results/final_unique_vulnerabilities_v2.csv', index=False)
        print(f"Found {len(unique_df)} unique entries. Stored in 'results/final_unique_vulnerabilities_v2.csv'.")
    else:
        print("No unique entries found.")

if __name__ == '__main__':
    main()

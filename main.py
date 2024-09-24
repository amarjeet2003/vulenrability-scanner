import pandas as pd

from scripts.report_to_csv import (
    parse_horusec_report,
    parse_semgrep_report, 
    parse_vcg_report, 
    parse_snyk_report,
    parse_bearer_report, 
    normalize_vulnerability, 
    output_to_csv,
    map_cwe_ids
)
from scripts.common_parsing import find_common_entries, find_unique_entries

def main():
    # Paths to the reports
    horusec_report_path = 'data/Horusec_new.txt'
    vcg_report_path = 'data/VCG_new.txt'
    snyk_report_path = 'data/snyk_new.txt'
    excel_cwe_path = 'data/snyk_code_security_rules.xlsx'
    semgrep_report_path = 'data/Semgrep_output.txt'
    bearer_report_path = 'data/Bearer_result.txt'

    # Parse and normalize the reports
    horusec_vulnerabilities = parse_horusec_report(horusec_report_path)
    vcg_vulnerabilities = parse_vcg_report(vcg_report_path)
    snyk_vulnerabilities = parse_snyk_report(snyk_report_path)
    semgrep_vulnerabilities = parse_semgrep_report(semgrep_report_path)
    bearer_vulnerabilities = parse_bearer_report(bearer_report_path)

    cwe_map = map_cwe_ids(excel_cwe_path)

    normalized_horusec_vulns = [normalize_vulnerability(vuln) for vuln in horusec_vulnerabilities]
    normalized_vcg_vulns = [normalize_vulnerability(vuln) for vuln in vcg_vulnerabilities]
    normalized_snyk_vulns = [normalize_vulnerability(vuln) for vuln in snyk_vulnerabilities]
    normalized_semgrep_vulns = [normalize_vulnerability(vuln) for vuln in semgrep_vulnerabilities]
    normalized_bearer_vulns = [normalize_vulnerability(vuln) for vuln in bearer_vulnerabilities]

    output_to_csv(normalized_horusec_vulns, 'results/normalized_horusec_vulnerabilities.csv', cwe_map)
    output_to_csv(normalized_vcg_vulns, 'results/normalized_vcg_vulnerabilities.csv', cwe_map)
    output_to_csv(normalized_snyk_vulns, 'results/normalized_snyk_vulnerabilities.csv', cwe_map)
    output_to_csv(normalized_semgrep_vulns, 'results/normalized_semgrep_vulnerabilities.csv', cwe_map)
    output_to_csv(normalized_bearer_vulns, 'results/normalized_bearer_vulnerabilities.csv', cwe_map)


    # Load the CSVs back into DataFrames
    sources = {
        'Horusec': pd.read_csv('results/normalized_horusec_vulnerabilities.csv'),
        'VCG': pd.read_csv('results/normalized_vcg_vulnerabilities.csv'),
        'Snyk': pd.read_csv('results/normalized_snyk_vulnerabilities.csv'),
        'Semgrep': pd.read_csv('results/normalized_semgrep_vulnerabilities.csv'),
        'Bearer': pd.read_csv('results/normalized_bearer_vulnerabilities.csv')
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

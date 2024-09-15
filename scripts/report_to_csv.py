import csv
import re
import os
import openpyxl

# Function to parse the VCG report
def parse_vcg_report(report_path):
    vulnerabilities = []
    vulnerability = {}

    with open(report_path, 'r') as file:
        for line in file:
            line = line.strip()

            # Match and extract severity, type, and details
            issue_match = re.match(r'^(LOW|MEDIUM|HIGH|CRITICAL|STANDARD|POTENTIAL ISSUE|SUSPICIOUS COMMENT): (.+)', line)
            if issue_match:
                if vulnerability:
                    # Add the previous vulnerability to the list if it's not empty
                    vulnerabilities.append(vulnerability)
                
                # Start a new vulnerability entry
                vulnerability = {
                    'severity': issue_match.group(1),
                    'type': issue_match.group(2),
                    'details': None,
                    "title": None,
                    'line': None,
                    'file': None,
                    'code': None
                }
                title = line.split('-')[1:]
                vulnerability['title'] = " ".join(title).strip()
                continue

            # Extract line and file information
            line_file_match = re.match(r'Line: (\d+) - (.+)', line)
            if line_file_match:
                if vulnerability:
                    
                    vulnerability['line'] = int(line_file_match.group(1))
                    vulnerability['file'] = line_file_match.group(2).strip().lower()
                continue

            # Extract code snippet
            if vulnerability and not vulnerability.get('details') and not line.startswith('Line:'):
                # Assuming code snippets can span multiple lines
                if not vulnerability.get('details'):
                    vulnerability['details'] = line
                else:
                    vulnerability['details'] += "\n" + line
                continue

            # Extract details
            if vulnerability and not vulnerability.get('code') and not line.startswith('Line:'):
                if vulnerability.get('code') is None:
                    vulnerability['code'] = line
                else:
                    vulnerability['code'] += "\n" + line
                continue
                
        # Append the last vulnerability if it exists
        if vulnerability:
            vulnerabilities.append(vulnerability)

    return vulnerabilities

def parse_horusec_report(report_path):
    vulnerabilities = []
    
    with open(report_path, 'r') as file:
        vulnerability = {}
        for line in file:
            line = line.strip()

            # Stop capturing if delimiter "===" is found
            if line.startswith("==="):
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                    vulnerability = {}
                continue

            if line.startswith("Language:"):
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                vulnerability = {'language': line.split(": ")[1]}
            elif line.startswith("Severity:"):
                vulnerability['severity'] = line.split(": ")[1]
            elif line.startswith("Line:"):
                vulnerability['line'] = int(line.split(": ")[1])
            elif line.startswith("File:"):
                vulnerability['file'] = line.split(": ")[1]
            elif line.startswith("Code:"):
                vulnerability['code'] = line.split(": ", 1)[1]
            elif line.startswith("Details:"):
                vulnerability['title'] = line.split(":", 2)[2].strip()
                vulnerability['details'] = vulnerability['title']
            else:
                if 'details' in vulnerability:
                    vulnerability['details'] += " " + line

        # Append the last vulnerability after the loop
        if vulnerability:
            vulnerabilities.append(vulnerability)

    return vulnerabilities



# Function to parse the Snyk report
def parse_snyk_report(report_path):
    vulnerabilities = []
    vulnerability = {}
    
    with open(report_path, 'r') as file:
        lines = file.readlines()
        
        for line in lines:
            line = line.strip()

            if line.startswith("âœ—"):
                severity_type = re.match(r"âœ— \[(\w+)\] (.+)", line)
                if severity_type:
                    vulnerability['severity'] = severity_type.group(1)
                    vulnerability['title'] = severity_type.group(2)
            
            elif line.startswith("Path:"):
                path_info = re.match(r"Path: (.+), line (\d+)", line)
                if path_info:
                    vulnerability['file'] = path_info.group(1)
                    vulnerability['line'] = int(path_info.group(2))
            
            elif line.startswith("Info:"):
                vulnerability['details'] = line.split(": ", 1)[1]
                vulnerabilities.append(vulnerability)
                vulnerability = {}

    return vulnerabilities

def parse_semgrep_report(report_path):
    vulnerabilities = []
    vulnerability = {}

    with open(report_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()

            # Check for file path
            file_match = re.match(r'^\s*(.*\.(java|py|js|rb|go))', line)
            if file_match:
                # Save previous vulnerability if one exists
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                    vulnerability = {}
                    
                vulnerability['file'] = file_match.group(1).split('/')[-1]

            # Check for vulnerability type
            # type_match = re.match(r'^\s*(\w+\.\w+\.\w+.*)', line)
            # if type_match:
            #     vulnerability['title'] = type_match.group(1)

            # Check for details
            if line.startswith('Detected') or line.startswith('A'):
                vulnerability['details'] = line

            # Check for line number and code snippet
            code_match = re.match(r'^\s*(\d+)\s*┆\s*(.*)', line)
            if code_match:
                vulnerability['line'] = code_match.group(1)
                vulnerability['code'] = code_match.group(2)

    # Append the last vulnerability
    if vulnerability:
        vulnerabilities.append(vulnerability)

    return vulnerabilities


def parse_bearer_report(report_path):
    vulnerabilities = []
    vulnerability = {}

    with open(report_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()

            # Check for severity level (e.g., CRITICAL, MEDIUM, LOW)
            severity_match = re.match(r'^(CRITICAL|HIGH|MEDIUM|LOW):\s*(.*)\s*\[CWE-\d+\]', line)
            if severity_match:
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                    vulnerability = {}

                vulnerability['severity'] = severity_match.group(1)
                vulnerability['title'] = severity_match.group(2)

            # Extract file path and line number (e.g., File: /path/to/file.java:49)
            file_match = re.match(r'^File:\s*(.*):(\d+)', line)
            if file_match:
                vulnerability['file'] = file_match.group(1).split("/")[-1]  # Extract just the filename
                vulnerability['line'] = file_match.group(2)

            # Extract the code that follows the line number
            code_match = re.match(r'^(\d+)\s*(.*)', line)
            if code_match and 'line' in vulnerability and code_match.group(1) == vulnerability['line']:
                vulnerability['code'] = code_match.group(2)

        if vulnerability:
            vulnerabilities.append(vulnerability)  # Append the last vulnerability if it exists

    return vulnerabilities


# Function to normalize the vulnerability data
def normalize_vulnerability(vuln):
    return {
        'Severity': vuln.get('severity', '').upper(),
        'Title': vuln.get('title', '').strip(),
        'File': os.path.basename(vuln.get('file', '').lower()),
        'Line': int(vuln.get('line', 0)),
        'Code': vuln.get('code', '').strip(),
        'Details': vuln.get('details', '').strip()
    }

# Function to map CWE IDs from an Excel file based on the Name column
def map_cwe_ids(excel_path):
    cwe_map = {}
    wb = openpyxl.load_workbook(excel_path)
    sheet = wb.active

    for row in sheet.iter_rows(min_row=2, values_only=True):
        cwe_id, name, description = row
        cwe_map[name.strip().lower()] = cwe_id  # Store as lowercase for easier matching

    return cwe_map

# Function to output the normalized data to a CSV file
def output_to_csv(vulnerabilities, output_file, cwe_map=None):
    keys = ['Severity', 'Title', 'File', 'Line', 'Code', 'Details', 'CWE ID']
    with open(output_file, 'w', newline='') as csv_file:
        dict_writer = csv.DictWriter(csv_file, keys)
        dict_writer.writeheader()

        for vuln in vulnerabilities:
            title_normalized = vuln['Title'].strip().lower()

            # Add the CWE ID if mapping exists
            cwe_id = cwe_map.get(title_normalized, 'N/A') if cwe_map else 'N/A'
            vuln['CWE ID'] = cwe_id
            dict_writer.writerow(vuln)

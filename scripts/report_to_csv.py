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

    try:
        with open(report_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

            for line in lines:
                line = line.strip()

                # Extract severity and title
                if line.startswith("âœ—"):
                    match = re.match(r"âœ— \[(\w+)\] (.+)", line)
                    if match:
                        vulnerability['severity'] = match.group(1)
                        vulnerability['title'] = match.group(2)

                # Extract file path and line number
                elif line.startswith("Path:"):
                    match = re.match(r"Path: (.+), line (\d+)", line)
                    if match:
                        vulnerability['file'] = match.group(1)
                        vulnerability['line'] = int(match.group(2))

                # Extract additional details
                elif line.startswith("Info:"):
                    details = line.split(": ", 1)[1] if ": " in line else ""
                    vulnerability['details'] = details.strip()

                    # Add the fully populated vulnerability to the list
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        vulnerability = {}

        # print("Parsed Snyk vulnerabilities:", vulnerabilities)
        return vulnerabilities

    except FileNotFoundError:
        print(f"Error: The file '{report_path}' was not found.")
        return []

    except Exception as e:
        print(f"An unexpected error occurred while parsing the report: {e}")
        return []
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
    # print("Bearer Report:", vulnerabilities)
    return vulnerabilities

def parse_bandit_report(report_path):
    vulnerabilities = []

    with open(report_path, 'r') as file:
        vulnerability = {}
        for line in file:
            line = line.strip()

            # Start of a new issue
            if line.startswith(">> Issue:"):
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                
                issue_data = line.split(": ", 1)[1]
                
                # Extract the content after the first parentheses (CWE part)
                details_content = re.sub(r'.*\)', '', issue_data).strip()  # Removes everything before and including ')'
                
                # Both title and details should contain the content after the bracket
                vulnerability['title'] = details_content
                vulnerability['details'] = details_content
            
            elif line.startswith("Severity:"):
                vulnerability['severity'] = line.split(": ", 1)[1].split()[0]
            
            elif line.startswith("Confidence:"):
                vulnerability['confidence'] = line.split(": ", 1)[1].split()[0]

            elif line.startswith("CWE:"):
                cwe_info = line.split(": ", 1)[1]
                vulnerability['cwe'] = re.search(r'CWE-\d+', cwe_info).group(0)
                vulnerability['cwe_link'] = cwe_info.split('(')[1][:-1] if '(' in cwe_info else None
            
            elif line.startswith("More Info:"):
                vulnerability['more_info'] = line.split(": ", 1)[1]

            elif line.startswith("Location:"):
                location_parts = line.split(": ", 1)[1].rsplit(":", 2)
                vulnerability['file'] = location_parts[0]
                vulnerability['line'] = int(location_parts[1])
                vulnerability['column'] = int(location_parts[2])

            elif re.match(r'^\d+', line) and 'file' in vulnerability:
                # Capture code lines if they're indented and directly follow a location
                vulnerability['code'] = vulnerability.get('code', '') + line + '\n'
            
            elif line.startswith("--------------------------------------------------"):
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                    vulnerability = {}

        # Append the last vulnerability after the loop
        if vulnerability:
            vulnerabilities.append(vulnerability)
    # print("bandit report:-",vulnerabilities)
    return vulnerabilities
def parse_pyt_report(pyreport_report_path):
    """Parse the Pytest report and extract vulnerabilities."""
    vulnerabilities = []  # List to hold all vulnerabilities
    vulnerability = {}  # Dictionary to store individual vulnerability details

    try:
        with open(pyreport_report_path, 'r') as file:
            lines = file.readlines()

        for i, line in enumerate(lines):
            line = line.strip()  # Clean up the line

            # Start of a new vulnerability issue (looking for title or pattern)
            if line.startswith("Vulnerability"):
                if vulnerability:  # If we already have a vulnerability, save it
                    vulnerabilities.append(vulnerability)
                # Start new vulnerability and add relevant details
                vulnerability = {'title': line, 'line': i + 1}  # Store the line number

            # Extract file and line location (if present)
            elif line.startswith("File:"):
                parts = line.split(":")
                if len(parts) > 1:
                    vulnerability['file'] = os.path.basename(parts[1].strip())

            # Extract source (user input) and capture the line number
            elif line.startswith("User input at"):
                parts = line.split(",")
                if len(parts) > 0:
                    vulnerability['user_input'] = parts[0].split("at", 1)[1].strip()
                    # Store the line number for "User input"
                    vulnerability['line'] = i + 1  # Line number where user input is found

            # Extract reassignment details
            elif line.startswith("Reassigned in:"):
                parts = line.split(":")
                if len(parts) > 1:
                    reassigned_info = parts[1].strip()
                    vulnerability['reassigned'] = reassigned_info

            # Extract the sink location (e.g., render_template)
            elif "render_template" in line:
                parts = line.split("sink", 1)
                if len(parts) > 1:
                    vulnerability['sink'] = parts[1].strip()

            # Capture unknown vulnerability details if available
            elif line.startswith("This vulnerability is unknown due to:"):
                parts = line.split("due to:")
                if len(parts) > 1:
                    vulnerability['unknown_cause'] = parts[1].strip()

            # End of vulnerability block (using separator or end of report)
            elif line.startswith("--------------------------------------------------"):
                if vulnerability:  # If we have a full vulnerability, save it
                    vulnerabilities.append(vulnerability)
                    vulnerability = {}  # Reset for the next vulnerability

        # Append the last vulnerability after the loop
        if vulnerability:
            vulnerabilities.append(vulnerability)

    except Exception as e:
        print(f"Error processing the report: {e}")
    
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
        rule_name, cwe_id = row
        cwe_map[rule_name.strip().lower()] = cwe_id  # Store as lowercase for easier matching

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

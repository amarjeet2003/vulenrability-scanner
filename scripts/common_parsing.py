import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
import re

# Load stopwords and initialize stemmer
nltk.download('stopwords', quiet=True)
stop_words = set(stopwords.words('english'))
stemmer = PorterStemmer()

def clean_text(text):
    if pd.isnull(text):
        return ""
    text = re.sub(r"[^\w\s]", "", text.lower()).split()
    text = [word for word in text if word not in stop_words]
    text = [stemmer.stem(word) for word in text]
    return ' '.join(text)


# Function to check if two details are similar
def is_similar(detail1, detail2):
    # Check if either of the details is NaN(Not available)
    if pd.isna(detail1) or pd.isna(detail2):
        return False 
    detail1 = clean_text(detail1)
    detail2 = clean_text(detail2)
    # Check if either detail is a substring of the other
    if detail1 in detail2 or detail2 in detail1:
        return True
    keywords = ["hash", "md5", "message digest", "weak cryptographic hash function", "sql", "password", "comment", "crypto", "ldap", "tcp","cipher", "ssl", "hardcoded"]
    return any(keyword in detail1 and keyword in detail2 for keyword in keywords)

def find_common_entries(sources):
    common_entries = []
    source_lookups = {source_name: {} for source_name in sources.keys()}

    # Create lookup dictionaries for each source based on 'File'
    for source_name, df in sources.items():
        for _, row in df.iterrows():
            if row['File'] not in source_lookups[source_name]:
                source_lookups[source_name][row['File']] = []
            source_lookups[source_name][row['File']].append(row)

    # Iterating through the first source to find common entries
    primary_source_name = list(sources.keys())[0]
    primary_df = sources[primary_source_name]

    for _, row in primary_df.iterrows():
        file_name = row['File']
        matched_entry = {
            'File': file_name, 
            f'Severity_{primary_source_name}': row['Severity'],
            f'Line_{primary_source_name}': row['Line'], 
            f'Code_{primary_source_name}': row['Code'],
            f'Title_{primary_source_name}': row['Title'],
            f'Details_{primary_source_name}': row['Details'],
            f'CWE ID_{primary_source_name}': row['CWE ID']
        }

        is_common = False
        for other_source_name in sources.keys():
            if other_source_name == primary_source_name:
                continue
            if file_name in source_lookups[other_source_name]:
                for other_row in source_lookups[other_source_name][file_name]:
                    # Check if the details are similar
                    if is_similar(row['Details'], other_row['Details']) or is_similar(row['Title'], other_row['Title']) or is_similar(row['Code'], other_row['Code']):
                        matched_entry[f'Severity_{other_source_name}'] = other_row['Severity']
                        matched_entry[f'Line_{other_source_name}'] = other_row['Line']
                        matched_entry[f'Code_{other_source_name}'] = other_row['Code']
                        matched_entry[f'Title_{other_source_name}'] = other_row['Title']
                        matched_entry[f'Details_{other_source_name}'] = other_row['Details']
                        matched_entry[f'CWE ID_{other_source_name}'] = other_row['CWE ID']
                        is_common = True
                        break
            else:
                matched_entry[f'Severity_{other_source_name}'] = None
                matched_entry[f'Line_{other_source_name}'] = None
                matched_entry[f'Code_{other_source_name}'] = None
                matched_entry[f'Title_{other_source_name}'] = None
                matched_entry[f'Details_{other_source_name}'] = None
                matched_entry[f'CWE ID_{other_source_name}'] = None

        if is_common:
            common_entries.append(matched_entry)

    return pd.DataFrame(common_entries)


# Function to find unique entries across all sources
def find_unique_entries(sources, common_entries):
    unique_entries = []

    # Iterate through each source to find unique entries
    for source_name, df in sources.items():
        for _, row in df.iterrows():
            file_name = row['File']
            is_common = False
            # Check if the entry is common
            for _, common_row in common_entries.iterrows():
                if (file_name == common_row['File']) and is_similar(row['Details'], common_row[f'Details_{source_name}']):
                    is_common = True
                    break
            if not is_common:
                row['Source'] = source_name
                unique_entries.append(row)

    return pd.DataFrame(unique_entries)

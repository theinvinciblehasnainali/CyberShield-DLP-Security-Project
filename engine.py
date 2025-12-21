import re
import openpyxl
import os

# Master list of all possible patterns the engine can detect
REGEX_PATTERNS = {
    'CNIC': r'\d{5}-\d{7}-\d',
    'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'Phone': r'(\+92|0)3\d{2}-\d{7}',
    'CreditCard': r'\b(?:\d[ -]*?){13,16}\b', # Matches the 'pattern' key in JSON
    "Sensitive_Keyword": r"\b(password|confidential|salary|secret|private)\b"
}

def find_leaks_in_text(text, active_policies):
    findings = []
    for policy in active_policies:
        if policy.get('status') == 'active':
            pattern = policy.get('pattern')
            policy_name = policy.get('name', 'Unknown Policy')
            
            if not pattern: continue
                
            try:
                # Add re.IGNORECASE to catch 'Password', 'PASSWORD', etc.
                matches = re.findall(pattern, text, re.IGNORECASE) 
                for match in matches:
                    findings.append({
                        "type": policy_name, 
                        "value": str(match)
                    })
            except re.error as e:
                print(f"⚠️ Regex Error: {e}")
                
    return findings

def scan_file_content(file_path, active_policies):
    ext = os.path.splitext(file_path)[1].lower()
    text_content = ""

    try:
        if ext == '.xlsx':
            wb = openpyxl.load_workbook(file_path, data_only=True)
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    text_content += " " + " ".join([str(cell) for cell in row if cell is not None])
        
        elif ext in ['.txt', '.log', '.csv']:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text_content = f.read()

        if text_content:
            # Pass policies down to the regex function
            return find_leaks_in_text(text_content, active_policies)
        
        return []
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
        return []

def perform_real_scan(directory_to_scan, active_policies):
    """Now accepts active_policies as an argument"""
    scan_results = {
        "files_scanned": 0,
        "threats_found": 0,
        "details": []
    }

    for root, dirs, files in os.walk(directory_to_scan):
        for file in files:
            scan_results["files_scanned"] += 1
            file_path = os.path.join(root, file)
            
            # Pass policies into the content scanner
            leaks = scan_file_content(file_path, active_policies)
            
            if leaks:
                scan_results["threats_found"] += 1
                scan_results["details"].append({
                    "file_name": file,
                    "file_path": file_path,
                    "leaks": leaks,
                    "severity": "high" if len(leaks) > 2 else "medium"
                })
                
    return scan_results
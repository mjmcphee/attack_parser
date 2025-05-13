import re
import json
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time

def get_mitre_attack_data(version=17):
    """
    Fetch the MITRE ATT&CK Enterprise matrix data for a specific version
    """
    # The correct URL format for the GitHub repository
    url = f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}.0/enterprise-attack/enterprise-attack.json"
    
    response = requests.get(url)
    
    # Check if the response is successful
    if response.status_code != 200:
        print(f"Error: Failed to fetch ATT&CK data. Status code: {response.status_code}")
        print(f"URL attempted: {url}")
        raise Exception(f"Failed to fetch ATT&CK data from {url}")
    
    try:
        data = response.json()
        return parse_attack_data(data)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        print(f"Response content (first 100 chars): {response.text[:100]}")
        raise

def parse_attack_data(data):
    """
    Parse the MITRE ATT&CK data to extract techniques and tactics
    """
    techniques = {}
    tactics = {}
    
    for obj in data.get("objects", []):
        # Extract techniques (attack-patterns)
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    if technique_id:
                        techniques[technique_id] = {
                            "name": obj.get("name", "Unknown"),
                            "tactic_refs": obj.get("kill_chain_phases", [])
                        }
        
        # Extract tactics (x-mitre-tactic)
        elif obj.get("type") == "x-mitre-tactic":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id")
                    if tactic_id:
                        tactics[tactic_id] = {
                            "name": obj.get("name", "Unknown")
                        }
    
    return {"techniques": techniques, "tactics": tactics}

def fetch_url_content_and_detect_mode(url, attack_data):
    """
    Fetch content from a URL, determine the best parsing mode, and extract content
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    try:
        print(f"Fetching content from {url}...")
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            print(f"Error: Failed to fetch URL. Status code: {response.status_code}")
            return None
    except requests.exceptions.Timeout:
        print(f"Error: Request timed out when trying to fetch {url}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None
    
    # Parse the HTML with BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extract title
    title = "Threat Intelligence Report"  # Default title
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    
    # Auto-detect if HTML mode is needed
    html_mode_needed = False
    
    # Check if this is a known site that needs HTML mode
    known_html_mode_sites = ['cisa.gov', 'ncsc.gov.uk', 'microsoft.com/security']
    for site in known_html_mode_sites:
        if site in url:
            html_mode_needed = True
            break
    
    # Check for MITRE ATT&CK links in HTML
    if not html_mode_needed:
        attack_links = soup.find_all('a', href=lambda href: href and 'attack.mitre.org' in href)
        if len(attack_links) > 0:
            # If there are links to MITRE ATT&CK, we should use HTML mode
            html_mode_needed = True
    
    # Check for technique IDs in text mode as a preliminary test
    if not html_mode_needed:
        # Get plain text for initial scanning
        text_content = soup.get_text()
        technique_pattern = r'T\d{4}(?:\.\d{3})?'
        technique_matches = re.findall(technique_pattern, text_content)
        
        # Count valid techniques in plain text
        plain_text_techniques = 0
        for match in technique_matches:
            if match in attack_data["techniques"]:
                plain_text_techniques += 1
        
        # Now check for technique IDs in href attributes
        href_techniques = set()
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            if 'mitre.org' in href and '/techniques/' in href:
                match = re.search(r'techniques/(T\d{4}(?:\.\d{3})?)', href)
                if match and match.group(1) in attack_data["techniques"]:
                    href_techniques.add(match.group(1))
        
        # If we find more techniques in hrefs than in plain text, use HTML mode
        if len(href_techniques) > plain_text_techniques:
            html_mode_needed = True
    
    # Process based on the detected mode
    if html_mode_needed:
        print("Detected MITRE ATT&CK references in hyperlinks, using HTML parsing mode...")
        # Process with HTML-specific mode
        found_techniques = set()
        found_tactics = set()
        
        # Extract from hyperlinks
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            
            # Check if the link is to attack.mitre.org
            if 'attack.mitre.org' in href:
                # Extract technique ID from URL
                if '/techniques/' in href:
                    match = re.search(r'techniques/(T\d{4}(?:\.\d{3})?)', href)
                    if match:
                        technique_id = match.group(1)
                        if technique_id in attack_data["techniques"]:
                            found_techniques.add(technique_id)
                    else:
                        # Try to extract from link text
                        text = link.get_text().strip()
                        match = re.search(r'(T\d{4}(?:\.\d{3})?)', text)
                        if match:
                            technique_id = match.group(1)
                            if technique_id in attack_data["techniques"]:
                                found_techniques.add(technique_id)
                
                # Check for tactic IDs
                if '/tactics/' in href:
                    match = re.search(r'tactics/(TA\d{4})', href)
                    if match:
                        tactic_id = match.group(1)
                        if tactic_id in attack_data["tactics"]:
                            found_tactics.add(tactic_id)
                    else:
                        # Try to extract from link text
                        text = link.get_text().strip()
                        match = re.search(r'(TA\d{4})', text)
                        if match:
                            tactic_id = match.group(1)
                            if tactic_id in attack_data["tactics"]:
                                found_tactics.add(tactic_id)
        
        # Also extract from plain text as backup
        text_content = soup.get_text()
        
        # Look for technique IDs in plain text
        for match in re.finditer(r'T\d{4}(?:\.\d{3})?', text_content):
            technique_id = match.group(0)
            if technique_id in attack_data["techniques"]:
                found_techniques.add(technique_id)
        
        # Look for tactic IDs in plain text
        for match in re.finditer(r'TA\d{4}', text_content):
            tactic_id = match.group(0)
            if tactic_id in attack_data["tactics"]:
                found_tactics.add(tactic_id)
                
        found_items = {
            "techniques": found_techniques,
            "tactics": found_tactics
        }
    else:
        print("Using standard text parsing mode...")
        # Process with standard text mode
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.extract()
        
        # Get text
        text_content = soup.get_text(separator=' ')
        # Clean text
        lines = (line.strip() for line in text_content.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text_content = ' '.join(chunk for chunk in chunks if chunk)
        
        # Parse for techniques and tactics
        found_items = parse_text_for_identifiers(text_content, attack_data)
    
    return {
        "text": text_content,
        "title": title,
        "url": url,
        "found_items": found_items,
        "html_mode_used": html_mode_needed
    }

def parse_text_for_identifiers(text, attack_data):
    """
    Parse text for MITRE ATT&CK technique IDs (T####, T####.###) and tactic IDs (TA####)
    """
    found_techniques = set()
    found_tactics = set()
    
    # Look for technique IDs (e.g., T1566, T1566.001)
    technique_pattern = r'T\d{4}(?:\.\d{3})?'
    for match in re.finditer(technique_pattern, text):
        technique_id = match.group(0)
        if technique_id in attack_data["techniques"]:
            found_techniques.add(technique_id)
    
    # Look for tactic IDs (e.g., TA0001)
    tactic_pattern = r'TA\d{4}'
    for match in re.finditer(tactic_pattern, text):
        tactic_id = match.group(0)
        if tactic_id in attack_data["tactics"]:
            found_tactics.add(tactic_id)
    
    return {"techniques": found_techniques, "tactics": found_tactics}

def create_navigator_json(found_items, score, source_info=None):
    """
    Create the ATT&CK Navigator JSON with the found techniques for ATT&CK v17
    """
    # Set the title - use source title if available, otherwise default
    title = "TTP Analysis"
    if source_info and source_info.get("title"):
        title = source_info["title"]
    
    navigator_json = {
        "name": title,
        "versions": {
            "attack": "17",
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "TTPs extracted from threat intelligence",
        "filters": {
            "platforms": [
                "Linux",
                "macOS",
                "Windows",
                "Azure AD",
                "Office 365",
                "SaaS",
                "IaaS",
                "Google Workspace",
                "PRE",
                "Network",
                "Containers",
                "Cloud"
            ]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": [
                "#ffffff",
                "#ff6666"
            ],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }
    
    # Add source URL to metadata if available
    if source_info and source_info.get("url"):
        navigator_json["metadata"].append({
            "name": "Source",
            "value": source_info["url"]
        })
        
    # Add parsing mode to metadata if available
    if source_info and source_info.get("html_mode_used") is not None:
        mode_used = "HTML parsing" if source_info["html_mode_used"] else "Text parsing"
        navigator_json["metadata"].append({
            "name": "Parsing Mode",
            "value": mode_used
        })
    
    # Add source URL to the layer's links section if available
    if source_info and source_info.get("url"):
        navigator_json["links"] = [{
            "label": "Source Report",
            "url": source_info["url"]
        }]
    
    # Add found techniques with their score
    for technique_id in found_items["techniques"]:
        technique_obj = {
            "techniqueID": technique_id,
            "score": score,
            "color": "",
            "comment": "",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": True
        }
        navigator_json["techniques"].append(technique_obj)
    
    # Tactics are not directly included in the Navigator layer as scored items
    # but we can include them in the metadata for reference
    if found_items["tactics"]:
        navigator_json["metadata"].append({
            "name": "Related Tactics",
            "value": ", ".join(sorted(found_items["tactics"]))
        })
    
    return navigator_json

def main():
    parser = argparse.ArgumentParser(description="Extract MITRE ATT&CK TTPs from threat intelligence and create ATT&CK Navigator layer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="URL of the threat intelligence blog/post")
    group.add_argument("--file", help="Local file containing threat intelligence")
    group.add_argument("--text", help="Direct text input containing threat intelligence")
    parser.add_argument("--score", type=int, default=100, help="Score to assign to found techniques (default: 100)")
    parser.add_argument("--title", help="Custom title for the Navigator layer (overrides automatic title)")
    parser.add_argument("--output", default="attack_navigator_layer.json", help="Output file name (default: attack_navigator_layer.json)")
    parser.add_argument("--attack-version", type=int, default=17, help="MITRE ATT&CK version to use (default: 17)")
    parser.add_argument("--force-html-mode", action="store_true", help="Force HTML parsing mode (override auto-detection)")
    parser.add_argument("--force-text-mode", action="store_true", help="Force text parsing mode (override auto-detection)")
    
    args = parser.parse_args()
    
    # Check for conflicting arguments
    if args.force_html_mode and args.force_text_mode:
        print("Error: Cannot specify both --force-html-mode and --force-text-mode")
        return
    
    # Get MITRE ATT&CK data
    print(f"Fetching MITRE ATT&CK v{args.attack_version} data...")
    try:
        attack_data = get_mitre_attack_data(version=args.attack_version)
        print(f"Successfully fetched ATT&CK data, found {len(attack_data['techniques'])} techniques and {len(attack_data['tactics'])} tactics")
    except Exception as e:
        print(f"Error fetching ATT&CK data: {e}")
        return
    
    # Information about the source
    source_info = {}
    found_items = {"techniques": set(), "tactics": set()}
    
    # Get the text to analyze
    if args.url:
        # Use the new auto-detecting function
        if args.force_html_mode:
            print("HTML parsing mode forced by user...")
            # Use a simplified version of HTML parsing directly
            html_result = fetch_url_content_and_detect_mode(args.url, attack_data)
            if not html_result:
                print(f"Error: Could not parse content from {args.url}")
                return
            
            # Force HTML mode in the result
            html_result["html_mode_used"] = True
            result = html_result
        elif args.force_text_mode:
            print("Text parsing mode forced by user...")
            # Use standard text extraction
            response = requests.get(args.url, headers={"User-Agent": "Mozilla/5.0"})
            if response.status_code != 200:
                print(f"Error: Could not fetch content from {args.url}")
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string.strip() if soup.title else "Threat Intelligence Report"
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.extract()
            
            # Get text
            text = soup.get_text(separator=' ')
            # Clean text
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = ' '.join(chunk for chunk in chunks if chunk)
            
            # Parse for techniques and tactics
            found_items = parse_text_for_identifiers(text, attack_data)
            
            result = {
                "text": text,
                "title": title,
                "url": args.url,
                "found_items": found_items,
                "html_mode_used": False
            }
        else:
            # Use auto-detection
            result = fetch_url_content_and_detect_mode(args.url, attack_data)
            if not result:
                print(f"Error: Could not parse content from {args.url}")
                return
        
        text = result["text"]
        found_items = result["found_items"]
        source_info = {
            "url": args.url,
            "title": result["title"],
            "html_mode_used": result["html_mode_used"]
        }
        print(f"Title detected: {result['title']}")
        print(f"Parsing mode used: {'HTML' if result['html_mode_used'] else 'Text'}")
            
    elif args.file:
        print(f"Reading content from {args.file}...")
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                text = f.read()
            
            # Parse for techniques and tactics
            print("Parsing for MITRE ATT&CK identifiers...")
            found_items = parse_text_for_identifiers(text, attack_data)
            
            source_info = {
                "title": args.file  # Use filename as title
            }
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    
    else:  # args.text
        text = args.text
        
        # Parse for techniques and tactics
        print("Parsing for MITRE ATT&CK identifiers...")
        found_items = parse_text_for_identifiers(text, attack_data)
        
        source_info = {
            "title": "Direct Text Input"
        }
    
    # Override title if provided
    if args.title:
        source_info["title"] = args.title
    
    # Create Navigator JSON
    print(f"Found {len(found_items['techniques'])} techniques and {len(found_items['tactics'])} tactics. Creating Navigator layer...")
    navigator_json = create_navigator_json(found_items, args.score, source_info)
    
    # Write to file
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(navigator_json, f, indent=2)
    
    print(f"Navigator layer saved to {args.output}")
    
    # Output found techniques
    if found_items["techniques"]:
        print("\nTechniques found:")
        for technique_id in sorted(found_items["techniques"]):
            print(f"- {technique_id}: {attack_data['techniques'][technique_id]['name']}")
    else:
        print("\nNo techniques were found in the provided content.")
    
    # Output found tactics
    if found_items["tactics"]:
        print("\nTactics found:")
        for tactic_id in sorted(found_items["tactics"]):
            print(f"- {tactic_id}: {attack_data['tactics'][tactic_id]['name']}")
    else:
        print("\nNo tactics were found in the provided content.")

if __name__ == "__main__":
    main()
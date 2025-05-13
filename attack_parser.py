import re
import json
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

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

def fetch_url_content(url):
    """
    Fetch content from a URL and extract both text and title
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract title
        title = "Threat Intelligence Report"  # Default title
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.extract()
        
        # Get text
        text = soup.get_text(separator=' ')
        # Clean text
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return {"text": text, "title": title}
    else:
        return None

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
    
    args = parser.parse_args()
    
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
    
    # Get the text to analyze
    if args.url:
        print(f"Fetching content from {args.url}...")
        result = fetch_url_content(args.url)
        if not result:
            print(f"Error: Could not fetch content from {args.url}")
            return
        text = result["text"]
        source_info = {
            "url": args.url,
            "title": result["title"]
        }
        print(f"Title detected: {result['title']}")
    elif args.file:
        print(f"Reading content from {args.file}...")
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                text = f.read()
            source_info = {
                "title": args.file  # Use filename as title
            }
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    else:  # args.text
        text = args.text
        source_info = {
            "title": "Direct Text Input"
        }
    
    # Override title if provided
    if args.title:
        source_info["title"] = args.title
    
    # Parse for techniques and tactics
    print("Parsing for MITRE ATT&CK identifiers...")
    found_items = parse_text_for_identifiers(text, attack_data)
    
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
# Guide: ATT&CK Parser - Extract and Visualize TTPs from Threat Intelligence

## Overview

ATT&CK Parser is a Python tool that automatically extracts MITRE ATT&CK techniques and tactics from threat intelligence reports and generates ATT&CK Navigator layers for visualization. This tool streamlines threat intelligence analysis by eliminating the need to manually identify and input TTPs into the Navigator.

## Key Features

- Extracts ATT&CK technique IDs (T####, T####.###) and tactic IDs (TA####) from text
- Creates properly formatted ATT&CK Navigator JSON layers
- Supports multiple input types: URLs, files, or direct text input
- Automatically captures blog/report titles and includes source URLs
- Works with ATT&CK v17 (customizable to other versions)

## Installation

1. **Requirements**:
   - Python 3.6+ (tested with Python 3.13)
   - Internet connection (to fetch MITRE ATT&CK data)

2. **Setup**:
   ```bash
   # 1. Create a virtual environment (recommended)
   python -m venv venv
   
   # 2. Activate the virtual environment
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   
   # 3. Install required packages
   pip install requests beautifulsoup4
   
   # 4. Download the script
   # Save it as attack_parser.py
   ```

## Usage

### Basic Usage

```bash
# Parse a URL
python attack_parser.py --url https://example.com/threat-report --score 75

# Parse a local file
python attack_parser.py --file threat_intel.txt --score 50

# Parse direct text
python attack_parser.py --text "The threat actor leveraged T1566.001 and TA0001 in their campaign" --score 100
```

### Command Line Arguments

```
--url URL                URL of the threat intelligence blog/post
--file FILE              Local file containing threat intelligence
--text TEXT              Direct text input containing threat intelligence
--score SCORE            Score to assign to found techniques (default: 100)
--title TITLE            Custom title for the Navigator layer
--output OUTPUT          Output file name (default: attack_navigator_layer.json)
--attack-version VERSION MITRE ATT&CK version to use (default: 17)
```

### Example Workflow

1. Find an interesting threat intelligence report online
2. Run the script with the URL:
   ```bash
   python attack_parser.py --url https://example.com/threat-report --score 50 --attack-version 17
   ```
3. Upload the generated `attack_navigator_layer.json` file to [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
4. Analyze the visualized techniques and tactics

## Tips for Best Results

- Run the script on reports that explicitly mention technique IDs (T####) or tactic IDs (TA####)
- Add a descriptive custom title with the `--title` argument for better organization
- Adjust the score value based on your confidence in the source
- For multiple related reports, generate separate layers and then compare them in the Navigator

## Troubleshooting

- **Error fetching ATT&CK data**: Check your internet connection and confirm the ATT&CK version is valid
- **No techniques found**: Verify the report actually contains explicit T#### or TA#### codes
- **JSON decode error**: This may indicate an issue with the ATT&CK API - try a different version
- **Title extraction fails**: Use the `--title` parameter to manually set a title

## Further Development

This tool focuses on extracting explicit ATT&CK identifiers. Future enhancements could include:
- Natural language processing to detect techniques without explicit IDs
- Confidence scoring based on context
- Batch processing for multiple sources



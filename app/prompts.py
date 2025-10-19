# app/prompts.py
"""
LLM Prompt Templates for Threat Analysis
"""


def build_threat_prompt(context):
    """
    Build comprehensive prompt for LLM analysis
    """
    ioc_value = context.get('ioc_value', '')
    ioc_type = context.get('ioc_type', '')
    classification = context.get('classification', 'Unknown')
    vt_summary = context.get('vt_summary', '')
    shodan_summary = context.get('shodan_summary', '')
    otx_summary = context.get('otx_summary', '')
    whois_summary = context.get('whois_summary', '')
    
    prompt = f"""Analyze this security threat and provide a clear explanation for a cybersecurity analyst.

INDICATOR OF COMPROMISE (IOC):
- Value: {ioc_value}
- Type: {ioc_type}
- Classification: {classification}

DATA SOURCES:

VirusTotal Analysis:
{vt_summary}

Network Exposure (Shodan):
{shodan_summary}

Threat Intelligence (AlienVault OTX):
{otx_summary}

Registration Information (WHOIS):
{whois_summary}

TASK:
Provide a structured analysis in the following JSON format:

{{
  "summary": "One-sentence summary of the threat",
  "explanation": "2-3 paragraph explanation of why this is {classification.lower()} and what makes it dangerous (or safe)",
  "indicators": [
    "Key finding 1",
    "Key finding 2",
    "Key finding 3"
  ],
  "recommendation": "Specific action to take (block, monitor, allow, investigate)",
  "confidence": "High/Medium/Low based on data quality"
}}

Focus on:
1. Being concise but informative
2. Explaining technical findings in clear language
3. Providing actionable recommendations
4. Only stating facts supported by the data provided

Respond ONLY with the JSON object, no additional text."""
    
    return prompt


def build_ip_specific_prompt(context):
    """
    Specialized prompt for IP address analysis
    """
    ioc_value = context.get('ioc_value', '')
    classification = context.get('classification', 'Unknown')
    
    raw_data = context.get('raw_data', {})
    shodan_data = raw_data.get('shodan', {})
    otx_data = raw_data.get('otx', {})
    
    # Extract detailed info
    ports = shodan_data.get('ports', [])
    vulns = shodan_data.get('vulns', [])
    country = shodan_data.get('details', {}).get('country', 'Unknown')
    org = shodan_data.get('details', {}).get('org', 'Unknown')
    
    otx_details = otx_data.get('details', {})
    threat_tags = otx_details.get('top_tags', [])
    
    prompt = f"""Analyze this IP address for security threats:

IP ADDRESS: {ioc_value}
CLASSIFICATION: {classification}

NETWORK ANALYSIS:
- Open Ports: {', '.join(map(str, ports[:10])) if ports else 'None detected'}
- Known Vulnerabilities: {len(vulns)} CVEs detected
- Location: {country}
- Organization: {org}

THREAT INTELLIGENCE:
- Threat Tags: {', '.join(threat_tags[:5]) if threat_tags else 'None'}
- OTX Threat Score: {otx_data.get('threat_score', 0)}/100

CONTEXT:
This IP was submitted for threat analysis. Provide insights on:
1. Why this IP is classified as {classification}
2. What specific threats it poses (if any)
3. Whether the open ports and services are suspicious
4. Recommended actions

Respond in JSON format:
{{
  "summary": "Brief threat summary",
  "explanation": "Detailed explanation",
  "indicators": ["key finding 1", "key finding 2", "key finding 3"],
  "recommendation": "Action to take",
  "confidence": "High/Medium/Low"
}}"""
    
    return prompt


def build_domain_specific_prompt(context):
    """
    Specialized prompt for domain/URL analysis
    """
    ioc_value = context.get('ioc_value', '')
    ioc_type = context.get('ioc_type', '')
    classification = context.get('classification', 'Unknown')
    whois_summary = context.get('whois_summary', '')
    
    raw_data = context.get('raw_data', {})
    otx_data = raw_data.get('otx', {})
    otx_details = otx_data.get('details', {})
    
    malware_families = otx_details.get('malware_families', [])
    threat_tags = otx_details.get('top_tags', [])
    
    prompt = f"""Analyze this {'domain' if ioc_type == 'domain' else 'URL'} for security threats:

{ioc_type.upper()}: {ioc_value}
CLASSIFICATION: {classification}

REGISTRATION INFO:
{whois_summary}

THREAT INTELLIGENCE:
- Malware Families: {', '.join(malware_families[:3]) if malware_families else 'None detected'}
- Threat Tags: {', '.join(threat_tags[:5]) if threat_tags else 'None'}
- OTX Pulses: {otx_data.get('source_count', 0)}

ANALYSIS REQUESTED:
1. Is this domain/URL associated with malicious activity?
2. What type of threat does it pose (phishing, malware distribution, C2, etc.)?
3. Is the domain registration suspicious (newly registered, privacy protection, etc.)?
4. What should users/organizations do about it?

Respond in JSON format:
{{
  "summary": "One-line threat assessment",
  "explanation": "Why this is {classification.lower()} - what activities is it known for?",
  "indicators": ["specific indicator 1", "specific indicator 2", "specific indicator 3"],
  "recommendation": "Block/Monitor/Allow with justification",
  "confidence": "High/Medium/Low"
}}"""
    
    return prompt
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
    vt_summary = context.get('vt_summary', 'No data available')
    shodan_summary = context.get('shodan_summary', 'No data available')
    otx_summary = context.get('otx_summary', 'No data available')
    whois_summary = context.get('whois_summary', 'No data available')
    
    prompt = f"""You are a cybersecurity threat analyst. Analyze this indicator of compromise.

**CRITICAL: Your response MUST be ONLY valid JSON. Do NOT use markdown code blocks. Do NOT add any text before or after the JSON.**

INDICATOR DETAILS:
- Value: {ioc_value}
- Type: {ioc_type}
- Classification: {classification}

THREAT INTELLIGENCE DATA:

VirusTotal: {vt_summary}

Shodan: {shodan_summary}

AlienVault OTX: {otx_summary}

WHOIS: {whois_summary}

Return your analysis in this EXACT JSON structure (no markdown, no code blocks):

{{
  "summary": "Brief one-sentence assessment",
  "explanation": "Detailed 2-3 paragraph explanation of why this is classified as {classification} based on the intelligence data. Include specific findings and technical details.",
  "indicators": [
    "Specific finding from the data",
    "Another concrete indicator",
    "Third relevant finding"
  ],
  "recommendation": "Specific actionable security recommendation (BLOCK/MONITOR/ALLOW with reasoning)",
  "confidence": "High"
}}

Requirements:
- Base analysis ONLY on the provided data
- Use "High", "Medium", or "Low" for confidence
- Include 3-5 specific indicators
- Escape any quotes in strings with backslash
- Return pure JSON only - NO markdown, NO ```json blocks, NO extra text

Your JSON response:"""
    
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
    
    prompt = f"""Analyze this IP address for cybersecurity threats.

**CRITICAL: Return ONLY valid JSON. NO markdown code blocks (```json). NO extra text.**

IP ADDRESS: {ioc_value}
Classification: {classification}

NETWORK INTELLIGENCE:
- Open Ports: {', '.join(map(str, ports[:10])) if ports else 'None'}
- CVE Vulnerabilities: {len(vulns)} detected
- Location: {country}
- Organization: {org}

THREAT INTELLIGENCE:
- Tags: {', '.join(threat_tags[:5]) if threat_tags else 'None'}
- OTX Score: {otx_data.get('threat_score', 0)}/100

Analyze:
1. Why this IP is {classification}
2. Threat level from open ports/services
3. CVE risk assessment
4. Recommended action

Return ONLY this JSON structure (no code blocks):

{{
  "summary": "One sentence threat assessment for {ioc_value}",
  "explanation": "Detailed analysis explaining the {classification} classification. Discuss the open ports, vulnerabilities, threat intelligence, and geographic/organizational context. Be specific and technical.",
  "indicators": [
    "Port/service finding",
    "Vulnerability or threat intel finding",
    "Geographic/reputation finding"
  ],
  "recommendation": "BLOCK/MONITOR/ALLOW with specific reasoning based on findings",
  "confidence": "High"
}}

Pure JSON only:"""
    
    return prompt


def build_domain_specific_prompt(context):
    """
    Specialized prompt for domain/URL analysis
    """
    ioc_value = context.get('ioc_value', '')
    ioc_type = context.get('ioc_type', '')
    classification = context.get('classification', 'Unknown')
    whois_summary = context.get('whois_summary', 'No WHOIS data')
    
    raw_data = context.get('raw_data', {})
    otx_data = raw_data.get('otx', {})
    otx_details = otx_data.get('details', {})
    
    malware_families = otx_details.get('malware_families', [])
    threat_tags = otx_details.get('top_tags', [])
    pulse_count = otx_data.get('source_count', 0)
    
    prompt = f"""Analyze this {'domain' if ioc_type == 'domain' else 'URL'} for cybersecurity threats.

**CRITICAL: Return ONLY pure JSON. NO markdown. NO ```json blocks. NO additional text.**

{ioc_type.upper()}: {ioc_value}
Classification: {classification}

WHOIS REGISTRATION:
{whois_summary}

THREAT INTELLIGENCE:
- Malware Families: {', '.join(malware_families[:3]) if malware_families else 'None'}
- Threat Tags: {', '.join(threat_tags[:5]) if threat_tags else 'None'}
- OTX Pulses: {pulse_count}

Determine:
1. Malicious activity association (phishing, malware, C2, etc.)
2. Registration suspicion (age, privacy protection, registrar)
3. Known threat campaigns
4. Security action required

Return this exact JSON (no markdown):

{{
  "summary": "One-line assessment of {ioc_value}",
  "explanation": "Why this is {classification}. Discuss any malware associations, threat campaigns, registration anomalies, and specific threat activities. Reference the OTX pulses and WHOIS data.",
  "indicators": [
    "Malware/campaign association",
    "Registration or WHOIS finding",
    "Threat intelligence finding"
  ],
  "recommendation": "BLOCK/MONITOR/ALLOW - explain why based on threat type and severity",
  "confidence": "High"
}}

JSON response:"""
    
    return prompt
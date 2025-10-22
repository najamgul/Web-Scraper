# app/llm_service.py
"""
LLM Service for generating threat explanations
Supports Google Gemini Pro and local models (Ollama)
"""
import os
import logging
import json
from app.prompts import build_threat_prompt

logger = logging.getLogger(__name__)

# Configuration
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
LLM_PROVIDER = os.getenv('LLM_PROVIDER', 'gemini')  # 'gemini' or 'ollama'
LLM_MODEL = os.getenv('LLM_MODEL', 'gemini-pro')  # or 'gemini-1.5-pro'
ENABLE_ENRICHMENT = os.getenv('ENABLE_ENRICHMENT', 'true').lower() == 'true'


def generate_threat_explanation(context):
    """
    Generate AI-powered explanation of threat
    
    Args:
        context (dict): Aggregated threat context from all sources
    
    Returns:
        dict: Structured explanation
    """
    if not ENABLE_ENRICHMENT:
        logger.info("Enrichment disabled via config")
        return get_fallback_explanation(context)
    
    try:
        if LLM_PROVIDER == 'gemini' and GEMINI_API_KEY:
            return generate_with_gemini(context)
        elif LLM_PROVIDER == 'ollama':
            return generate_with_ollama(context)
        else:
            logger.warning("No LLM provider configured, using fallback")
            return get_fallback_explanation(context)
    
    except Exception as e:
        logger.error(f"LLM generation error: {e}")
        return get_fallback_explanation(context)

def extract_json_from_response(content):
    """
    Robustly extract JSON from LLM response
    Handles markdown code blocks, extra whitespace, and common issues
    """
    try:
        content = content.strip()
        
        # Remove markdown code blocks
        if '```json' in content:
            # Extract content between ```json and ```
            start = content.find('```json') + 7
            end = content.find('```', start)
            if end != -1:
                content = content[start:end].strip()
        elif content.startswith('```') and content.endswith('```'):
            # Generic code block
            content = content[3:-3].strip()
        
        # Try parsing
        return json.loads(content)
        
    except json.JSONDecodeError as e:
        logger.warning(f"JSON parsing failed: {e}")
        
        # Try to fix common issues
        try:
            # Attempt 1: Find first { and last }
            start = content.find('{')
            end = content.rfind('}')
            if start != -1 and end != -1 and end > start:
                json_str = content[start:end+1]
                return json.loads(json_str)
        except:
            pass
        
        # If all else fails, return None
        return None


def validate_response_structure(parsed):
    """
    Validate that parsed JSON has required fields
    """
    if not isinstance(parsed, dict):
        return False
    
    required_fields = ['summary', 'explanation', 'indicators', 'recommendation']
    
    # Check all required fields exist
    if not all(key in parsed for key in required_fields):
        missing = [k for k in required_fields if k not in parsed]
        logger.warning(f"Response missing fields: {missing}")
        return False
    
    # Validate field types
    if not isinstance(parsed.get('indicators'), list):
        logger.warning("'indicators' field is not a list")
        return False
    
    # Check for empty critical fields
    if not parsed.get('summary') or not parsed.get('explanation'):
        logger.warning("Critical fields are empty")
        return False
    
    return True

def generate_with_gemini(context):
    """
    ✅ OPTIMIZED: Reduced max_tokens and faster config
    """
    try:
        import google.generativeai as genai
        
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(LLM_MODEL)
        prompt = build_threat_prompt(context)
        
        logger.info(f"Calling Gemini API with model: {LLM_MODEL}")
        
        # ✅ FASTER configuration
        generation_config = {
            'temperature': 0.2,  # ← Lower for faster, more focused responses
            'top_p': 0.7,        # ← Reduced
            'top_k': 30,         # ← Reduced
            'max_output_tokens': 1024,  # ← Reduced from 2048
        }
        
        safety_settings = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH"},
        ]
        
        # ✅ Add timeout wrapper
        import concurrent.futures
        
        def call_gemini():
            return model.generate_content(
                prompt,
                generation_config=generation_config,
                safety_settings=safety_settings
            )
        
        # ✅ 8-second timeout for Gemini
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(call_gemini)
            try:
                response = future.result(timeout=8)  # ← 8 second max
            except concurrent.futures.TimeoutError:
                logger.warning("Gemini API timeout - using fallback")
                return get_fallback_explanation(context)
        
        if not response.text:
            logger.warning("Gemini returned empty response")
            return get_fallback_explanation(context)
        
        content = response.text.strip()
        logger.info(f"Gemini response received ({len(content)} chars)")
        
        parsed = extract_json_from_response(content)
        
        if parsed and validate_response_structure(parsed):
            if 'confidence' not in parsed:
                parsed['confidence'] = 'Medium'
            return parsed
        else:
            logger.warning("Invalid response structure, parsing as text")
            return parse_text_response(content, context)
    
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return get_fallback_explanation(context)


def generate_with_ollama(context):
    """
    Generate explanation using local Ollama model
    """
    try:
        import requests
        
        prompt = build_threat_prompt(context)
        
        logger.info(f"Calling Ollama API with model: {LLM_MODEL}")
        
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': LLM_MODEL,
                'prompt': prompt,
                'stream': False
            },
            timeout=30
        )
        
        if response.status_code == 200:
            content = response.json().get('response', '')
            logger.info(f"Ollama response received ({len(content)} chars)")
            
            try:
                parsed = json.loads(content)
                return parsed
            except:
                return parse_text_response(content, context)
        else:
            logger.error(f"Ollama API error: {response.status_code}")
            return get_fallback_explanation(context)
    
    except Exception as e:
        logger.error(f"Ollama error: {e}")
        return get_fallback_explanation(context)


def parse_text_response(text, context):
    """
    Parse plain text LLM response into structured format
    """
    try:
        lines = text.strip().split('\n')
        
        summary = ""
        explanation = ""
        indicators = []
        recommendation = ""
        confidence = "Medium"
        
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Detect sections
            line_lower = line.lower()
            if 'summary' in line_lower and ':' in line:
                current_section = 'summary'
                # Extract content after colon
                if ':' in line:
                    summary = line.split(':', 1)[1].strip()
                continue
            elif 'explanation' in line_lower or 'why' in line_lower or 'dangerous' in line_lower or 'safe' in line_lower:
                if ':' in line:
                    current_section = 'explanation'
                    explanation = line.split(':', 1)[1].strip() + ' '
                    continue
                current_section = 'explanation'
            elif 'indicator' in line_lower or 'finding' in line_lower or 'key' in line_lower:
                current_section = 'indicators'
                continue
            elif 'recommendation' in line_lower or 'action' in line_lower:
                if ':' in line:
                    current_section = 'recommendation'
                    recommendation = line.split(':', 1)[1].strip() + ' '
                    continue
                current_section = 'recommendation'
            elif 'confidence' in line_lower:
                if 'high' in line_lower:
                    confidence = 'High'
                elif 'low' in line_lower:
                    confidence = 'Low'
                continue
            
            # Append to current section
            if current_section == 'summary':
                summary += line + ' '
            elif current_section == 'explanation':
                explanation += line + ' '
            elif current_section == 'indicators':
                # Clean up list markers
                cleaned = line.lstrip('-•*123456789.').strip()
                if cleaned and len(cleaned) > 5:  # Avoid adding section headers
                    indicators.append(cleaned)
            elif current_section == 'recommendation':
                recommendation += line + ' '
        
        # Fallbacks
        if not summary:
            summary = text[:200] + '...' if len(text) > 200 else text
        
        if not explanation:
            explanation = text
        
        if not indicators:
            indicators = ['Analysis based on multiple threat intelligence sources']
        
        if not recommendation:
            recommendation = get_default_recommendation(context.get('classification', 'Unknown'))
        
        return {
            'summary': summary.strip(),
            'explanation': explanation.strip(),
            'indicators': indicators[:5],  # Limit to 5 indicators
            'recommendation': recommendation.strip(),
            'confidence': confidence
        }
    
    except Exception as e:
        logger.error(f"Error parsing text response: {e}")
        return get_fallback_explanation(context)


def get_fallback_explanation(context):
    """
    Generate rule-based explanation when LLM is unavailable
    """
    classification = context.get('classification', 'Unknown')
    ioc_value = context.get('ioc_value', '')
    ioc_type = context.get('ioc_type', '')
    
    vt_summary = context.get('vt_summary', '')
    shodan_summary = context.get('shodan_summary', '')
    otx_summary = context.get('otx_summary', '')
    
    # Build summary
    summary = f"This {ioc_type} ({ioc_value}) has been classified as {classification} based on multi-source threat intelligence analysis."
    
    # Build explanation
    explanation_parts = []
    
    if vt_summary and 'no data' not in vt_summary.lower() and 'not available' not in vt_summary.lower():
        explanation_parts.append(f"VirusTotal Analysis: {vt_summary}")
    
    if shodan_summary and 'no data' not in shodan_summary.lower() and 'not available' not in shodan_summary.lower():
        explanation_parts.append(f"Network Exposure: {shodan_summary}")
    
    if otx_summary and 'no data' not in otx_summary.lower() and 'not available' not in otx_summary.lower():
        explanation_parts.append(f"Threat Intelligence: {otx_summary}")
    
    explanation = '\n\n'.join(explanation_parts) if explanation_parts else "Limited threat data available for comprehensive analysis. This assessment is based on available threat intelligence sources."
    
    # Build indicators
    indicators = []
    
    if classification == 'Malicious':
        indicators = [
            f"Multiple security vendors flagged this {ioc_type} as malicious",
            "Detected in active threat intelligence feeds",
            "Associated with known malicious activity",
            "High-confidence malicious classification"
        ]
    elif classification == 'Benign':
        indicators = [
            "No malicious indicators detected across security vendors",
            "Clean reputation in threat intelligence databases",
            "No suspicious network activity detected",
            "Safe to allow in most security contexts"
        ]
    elif classification == 'Suspicious':
        indicators = [
            "Some suspicious indicators detected",
            "Limited threat intelligence available",
            "Warrants further investigation",
            "Consider monitoring or temporary blocking"
        ]
    else:
        indicators = [
            f"Classification: {classification}",
            "Insufficient threat intelligence data",
            "Manual review recommended",
            "Gather additional context before taking action"
        ]
    
    # Recommendation
    recommendation = get_default_recommendation(classification)
    
    # Confidence
    confidence = 'Medium'
    sources_count = sum([
        1 for s in [vt_summary, shodan_summary, otx_summary] 
        if s and 'no data' not in s.lower() and 'not available' not in s.lower()
    ])
    
    if sources_count >= 2:
        confidence = 'High'
    elif sources_count == 0:
        confidence = 'Low'
    
    return {
        'summary': summary,
        'explanation': explanation,
        'indicators': indicators,
        'recommendation': recommendation,
        'confidence': confidence
    }


def get_default_recommendation(classification):
    """Get default recommendation based on classification"""
    recommendations = {
        'Malicious': 'BLOCK IMMEDIATELY. Add to firewall deny list and EDR block rules. Investigate all systems that have communicated with this indicator. Review logs for signs of compromise and lateral movement.',
        'Suspicious': 'MONITOR CLOSELY. Implement heightened logging and alerting. Consider temporary blocking based on risk tolerance. Investigate source and context. Track for additional malicious indicators.',
        'Benign': 'ALLOW. No immediate action required. Continue standard security monitoring. Maintain awareness as part of normal security operations.',
        'Informational': 'REVIEW CONTEXT. Evaluate against security policies and risk framework. May be legitimate but warrants analyst review. Consider adding to watch list.',
        'Unknown': 'INSUFFICIENT DATA. Gather additional threat intelligence before making security decisions. Consider sandboxing or temporary monitoring. Escalate to security analyst for manual review.'
    }
    
    return recommendations.get(classification, 'Manual security review and threat analysis recommended before taking action.')
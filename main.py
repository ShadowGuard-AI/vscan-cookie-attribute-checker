import argparse
import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Timeout in seconds for the scan request
REQUEST_TIMEOUT = 10

# Fixed marker shown wherever a report shape has a value slot. Cookie
# values themselves are never printed or saved.
MASKED_VALUE = "***"

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description="Checks cookies for security-related attributes (HttpOnly, Secure, SameSite).")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Output file for the results (optional).", default=None)
    return parser

def validate_url(url):
    """
    Validates that the input URL is well-formed.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def parse_set_cookie_header(header):
    """
    Parses one Set-Cookie header value into a cookie record.

    The name and the three attributes (Secure, HttpOnly, SameSite) are
    read from the header itself, where they actually live. The cookie
    value is dropped and replaced with the fixed masked marker, so it
    never reaches a report or a file.
    """
    parts = [part.strip() for part in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    cookie_info = {
        "name": name,
        "value": MASKED_VALUE,
        "Secure": "absent",
        "HttpOnly": "absent",
        "SameSite": "absent",
    }
    for attribute in parts[1:]:
        if not attribute:
            continue
        if "=" in attribute:
            attr_name, attr_value = attribute.split("=", 1)
            if attr_name.strip().lower() == "samesite":
                cookie_info["SameSite"] = attr_value.strip()
        else:
            attr_name = attribute.strip().lower()
            if attr_name == "secure":
                cookie_info["Secure"] = "present"
            elif attr_name == "httponly":
                cookie_info["HttpOnly"] = "present"
    return cookie_info


def check_cookie_attributes(url, set_cookie_headers):
    """
    Checks cookie attributes (HttpOnly, Secure, SameSite) for a given URL.

    Args:
        url (str): The URL where the cookies were obtained.
        set_cookie_headers (list): The raw Set-Cookie header values, one
            entry per cookie, so separate cookies stay separate.

    Returns:
        list: A list of dictionaries, where each dictionary contains information about
              a cookie and its security attributes.
    """
    results = []
    for header in set_cookie_headers:
        try:
            cookie_info = parse_set_cookie_header(header)
            if cookie_info is None:
                continue
            results.append(cookie_info)
            logging.debug(f"Processed cookie: {cookie_info['name']}")

        except Exception as e:
            logging.error(f"Error processing Set-Cookie header: {e}")

    return results
    
def scan_url(url):
    """
    Scans a given URL for cookies and checks their security attributes.

    Args:
        url (str): The URL to scan.

    Returns:
        list: A list of dictionaries, where each dictionary contains information about
              a cookie and its security attributes.  Returns None on error.
    """
    try:
        # Redirects are followed before I ever look at headers, and stream leaves the body unread.
        # Cookies set by an earlier response in the chain are gone by the time I check, because
        # only the final response's raw headers are in front of me.
        response = requests.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, stream=True)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        # The attributes live in the Set-Cookie headers. Read them from
        # the raw response headers so each cookie keeps its own header.
        set_cookie_headers = []
        raw_headers = getattr(response.raw, "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "getlist"):
            set_cookie_headers = raw_headers.getlist("Set-Cookie")
        if not set_cookie_headers:
            # This fallback treats one combined header string as one cookie. Several cookies joined
            # by the client library collapse into a single record here, and the rest go unreported.
            combined = response.headers.get("Set-Cookie")
            if combined:
                set_cookie_headers = [combined]

        if not set_cookie_headers:
            logging.warning(f"No cookies found for URL: {url}")
            return []

        logging.info(f"Found cookies for URL: {url}")
        results = check_cookie_attributes(url, set_cookie_headers)
        return results

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error for URL {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def output_results(results, output_file=None):
    """
    Outputs the results to the console or a file.

    Args:
        results (list): A list of dictionaries containing cookie information.
        output_file (str, optional): The path to the output file. Defaults to None (console output).
    """
    if results:
        output = "Cookie Security Scan Results:\n"
        for cookie in results:
            output += f"  Cookie Name: {cookie['name']}\n"
            output += f"    Value: {cookie['value']}\n"
            output += f"    HttpOnly: {cookie['HttpOnly']}\n"
            output += f"    Secure: {cookie['Secure']}\n"
            # Domain, Path, and expiry never reach this report. A cookie scoped to a broad parent
            # domain and one locked to this host look identical in my output.
            output += f"    SameSite: {cookie['SameSite']}\n"
            output += "---\n"

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(output)
                logging.info(f"Results written to file: {output_file}")
            except IOError as e:
                logging.error(f"Error writing to file {output_file}: {e}")
        else:
            print(output)
    else:
        print("No results to display.")

def main():
    """
    Main function to run the cookie attribute checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    url = args.url

    if not validate_url(url):
        logging.error(f"Invalid URL: {url}")
        # Returning here ends the process with a success code. An invalid URL and a failed scan
        # both exit 0, which a wrapping script will read as a completed check.
        print("Error: Invalid URL. Please provide a valid URL (e.g., https://example.com).")
        return

    logging.info(f"Starting scan for URL: {url}")
    results = scan_url(url)

    if results is not None:  # Avoid errors if scan_url returned None
        output_results(results, args.output)
        logging.info("Scan completed.")
    else:
        logging.error("Scan failed.")

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Basic scan: python main.py https://example.com
# 2. Verbose scan: python main.py -v https://example.com
# 3. Output to file: python main.py https://example.com -o results.txt
# 4. Verbose output to file: python main.py -v https://example.com -o results.txt

# Offensive Tools Considerations:
# 1. This tool primarily focuses on information gathering and checking for misconfigurations.
# 2. It does not directly exploit vulnerabilities but can help identify areas for further investigation using offensive tools.
# 3. The output provides insights into potential cookie-related weaknesses that could be exploited with tools like Burp Suite or OWASP ZAP.
# 4. The tool can be integrated into a larger vulnerability scanning pipeline.
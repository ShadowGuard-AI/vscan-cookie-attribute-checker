import argparse
import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

def check_cookie_attributes(url, cookies):
    """
    Checks cookie attributes (HttpOnly, Secure, SameSite) for a given URL.

    Args:
        url (str): The URL where the cookies were obtained.
        cookies (dict): A dictionary of cookies.

    Returns:
        list: A list of dictionaries, where each dictionary contains information about
              a cookie and its security attributes.
    """
    results = []
    for name, value in cookies.items():
        try:
            cookie_info = {"name": name, "value": value}
            
            # Check for HttpOnly attribute (can't be directly checked, needs browser interaction)
            cookie_info["HttpOnly"] = "N/A" # Indicate HttpOnly needs manual check

            # Check for Secure attribute
            cookie_info["Secure"] = "False"
            if 'secure' in str(cookies).lower():  # Simple check if 'secure' is mentioned (inaccurate)
                cookie_info["Secure"] = "Potentially True (manual check needed)"  # More accurate would require Selenium or similar

            # Check for SameSite attribute
            cookie_info["SameSite"] = "N/A"  # Cannot reliably determine SameSite with requests alone

            results.append(cookie_info)
            logging.debug(f"Processed cookie: {name}")

        except Exception as e:
            logging.error(f"Error processing cookie {name}: {e}")

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
        response = requests.get(url, allow_redirects=True)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        cookies = response.cookies.get_dict()
        if not cookies:
            logging.warning(f"No cookies found for URL: {url}")
            return []

        logging.info(f"Found cookies for URL: {url}")
        results = check_cookie_attributes(url, cookies)
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
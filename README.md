SQL Injection Waf bypass Testing Script

Overview

This script automates SQL injection testing by sending various payloads to a specified parameter in a target URL. It checks whether a Web Application Firewall (WAF) is blocking any of the payloads and provides a summary of the results

Features

Automated SQL Injection Testing: Sends multiple SQL injection payloads to a given URL parameter.

WAF Detection: Identifies blocked payloads by checking response status codes and keywords in responses.

Proxy Support: Allows routing requests through an HTTP proxy (e.g., Burp Suite).

Custom Block Detection: Lets users specify a keyword to identify WAF blocking responses.



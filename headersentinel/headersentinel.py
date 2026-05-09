#!/usr/bin/env python3

import urllib.request
import urllib.error
import urllib.parse
import http.client
import socket
import sys
import ssl
import os
import json
from optparse import OptionParser


def colorize(text, mode):
    if mode == "ok":      # present -> green
        return f"\033[92m{text}\033[0m"
    if mode == "error":   # missing -> red
        return f"\033[91m{text}\033[0m"
    return text


client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': 1
}

# Security headers 
sec_headers = {
    'X-XSS-Protection': 'deprecated',
    'X-Frame-Options': 'warning',
    'X-Content-Type-Options': 'warning',
    'Strict-Transport-Security': 'error',
    'Content-Security-Policy': 'warning',
    'X-Permitted-Cross-Domain-Policies': 'deprecated',
    'Referrer-Policy': 'warning',
    'Expect-CT': 'deprecated',
    'Permissions-Policy': 'warning',
    'Cross-Origin-Embedder-Policy': 'warning',
    'Cross-Origin-Resource-Policy': 'warning',
    'Cross-Origin-Opener-Policy': 'warning'
}

information_headers = {
    'X-Powered-By',
    'Server',
    'X-AspNet-Version',
    'X-AspNetMvc-Version'
}

cache_headers = {
    'Cache-Control',
    'Pragma',
    'Last-Modified',
    'Expires',
    'ETag'
}

headers = {}


def log(string):
    print(string)


def banner():
    log("")
    log("========================================================================")
    log("||   HeaderSentinel.py - HTTP Security Header Recon Toolkit           ||")
    log("||--------------------------------------------------------------------||")
    log("|| Author : Bharathkumar M (a.k.a XpL0itX)                            ||")
    log("|| GitHub : https://github.com/Bharathkumar-2006/Header-Sentinel.git  ||")
    log("||--------------------------------------------------------------------||")
    log("|| Description:                                                       ||")
    log("||  HeaderSentinel inspects HTTP responses for modern security        ||")
    log("||  headers (CSP, HSTS, XFO, etc.), helping you quickly spot          ||")
    log("||  missing or misconfigured protections based on OWASP guidance.     ||")
    log("========================================================================")
    log("")


def parse_headers(hdrs):
    global headers
    headers = dict((x.lower(), y) for x, y in hdrs)


def append_port(target, port):
    return target[:-1] + ':' + port + '/' if target.endswith('/') else target + ':' + port + '/'


def build_opener(ssldisabled):
    if ssldisabled:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    else:
        opener = urllib.request.build_opener()

    urllib.request.install_opener(opener)


def normalize(target):
    try:
        if (socket.inet_aton(target)):
            target = 'http://' + target
    except Exception:
        pass
    return target


def print_error(target, e):
    if isinstance(e, ValueError):
        sys.stderr.write("Unknown URL type\n")
    elif isinstance(e, urllib.error.HTTPError):
        sys.stderr.write(f"[!] URL Returned an HTTP error: {e.code}\n")
    elif isinstance(e, urllib.error.URLError):
        if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
            sys.stderr.write("SSL certificate validation error. Use -d to disable.\n")
        else:
            sys.stderr.write(f"Target host {target} seems unreachable ({e.reason})\n")
    else:
        sys.stderr.write(f"{str(e)}\n")


def check_target(target):
    ssldisabled = options.ssldisabled
    useget = options.useget
    usemethod = options.usemethod

    target = normalize(target)

    request = urllib.request.Request(target, headers=client_headers)
    method = "GET" if useget else usemethod
    request.get_method = lambda: method

    build_opener(ssldisabled)

    try:
        response = urllib.request.urlopen(request, timeout=10)

    except http.client.UnknownProtocol as e:
        print(f"Unknown protocol: {e}")
        return None

    except Exception as e:
        print_error(target, e)
        if hasattr(e, 'code') and 400 <= e.code < 500:
            return e
        return None

    return response


def is_https(target):
    return target.startswith('https://')


def report(target, safe, unsafe):
    log("-------------------------------------------------------")
    log(f"[!] Analyzing headers for {target}")
    log(f"[+] {safe} security header(s) present")
    log(f"[-] {unsafe} security header(s) missing")
    log("")


def parse_csp(csp):
    unsafe_operators = ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes', 'wasm-unsafe-eval', 'self']
    log("Value:")
    policy_directive = csp.split(";")
    for policy in policy_directive:
        elements = policy.lstrip().split(" ", 1)
        values = elements[1] if len(elements) > 1 else ""
        log("\t" + elements[0] + (": " + values if values else ""))


def main():
    global options
    options, targets = parse_options()

    port = options.port
    cookie = options.cookie
    information = options.information
    cache_control = options.cache_control
    show_deprecated = options.show_deprecated

    banner()

    if cookie is not None:
        client_headers.update({'Cookie': cookie})

    safe = 0
    unsafe = 0

    for target in targets:
        if port is not None:
            target = append_port(target, port)

        log(f"[*] Analyzing headers of {target}")

        response = check_target(target)
        if not response:
            continue

        rUrl = response.geturl()

        log(f"[*] Effective URL: {rUrl}")
        parse_headers(response.getheaders())

        safe = 0
        unsafe = 0

        if "content-security-policy" in headers and "frame-ancestors" in headers["content-security-policy"].lower():
            sec_headers.pop("X-Frame-Options", None)
            headers.pop("x-frame-options", None)

        for safeh in sec_headers:
            lsafeh = safeh.lower()
            if lsafeh in headers:
                safe += 1

                if lsafeh == "content-security-policy":
                    log(colorize(f"[*] Header {safeh} is present!", "ok"))
                    parse_csp(headers[lsafeh])

                else:
                    log(colorize(f"[*] Header {safeh} is present! (Value: {headers[lsafeh]})", "ok"))

            else:
                if safeh == "Strict-Transport-Security" and not is_https(rUrl):
                    continue

                if not show_deprecated and sec_headers[safeh] == "deprecated":
                    continue

                unsafe += 1
                log(colorize(f"[!] Security header missing: {safeh}", "error"))

        if information:
            log("")
            found = False
            for infoh in information_headers:
                if infoh.lower() in headers:
                    found = True
                    log(f"[!] Information disclosure: {infoh} (Value: {headers[infoh.lower()]})")
            if not found:
                log("[*] No information disclosure headers detected")

        if cache_control:
            log("")
            found = False
            for cacheh in cache_headers:
                if cacheh.lower() in headers:
                    found = True
                    log(f"[!] Cache header: {cacheh} (Value: {headers[cacheh.lower()]})")
            if not found:
                log("[*] No caching headers detected")

        report(rUrl, safe, unsafe)


def parse_options():
    parser = OptionParser("Usage: %prog [options] <target>", prog=sys.argv[0])

    parser.add_option("-p", "--port", dest="port", help="Set a custom port")
    parser.add_option("-c", "--cookie", dest="cookie", help="Set cookies")
    parser.add_option("-d", "--disable-ssl-check", dest="ssldisabled",
                      default=False, action="store_true",
                      help="Disable SSL/TLS certificate validation")
    parser.add_option("-g", "--use-get-method", dest="useget",
                      default=False, action="store_true",
                      help="Use GET instead of HEAD")
    parser.add_option("-m", "--use-method", dest="usemethod", default='HEAD',
                      choices=["HEAD", "GET", "POST", "PUT", "DELETE", "TRACE"],
                      help="Use a specific HTTP method")
    parser.add_option("-i", "--information", dest="information",
                      default=False, action="store_true",
                      help="Display information disclosure headers")
    parser.add_option("-x", "--caching", dest="cache_control",
                      default=False, action="store_true",
                      help="Display caching headers")
    parser.add_option("-k", "--deprecated", dest="show_deprecated",
                      default=False, action="store_true",
                      help="Show deprecated security headers")

    (options, targets) = parser.parse_args()

    if len(targets) < 1:
        parser.print_help()
        sys.exit(12)

    return options, targets


if __name__ == "__main__":
    main()
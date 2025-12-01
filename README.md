# HeaderSentinel - Security Header Check


## Check security headers on a target website

Built this quick CLI tool to scan websites for essential security headers like CSP, HSTS, X-Frame-Options, and more.

It fetches HTTP responses, analyzes key headers, and generates a clear report showing what's properly configured vs. missing or weak.

Minimalist design from a short coding session - perfect starting point for contributions like JSON export, batch scanning, or advanced validation rules.

## How to run:

### From source
```bash
git clone https://github.com/Bharathkumar-2006/Header-Sentinel && cd headersentinel
./headersent.py https://google.com
```

### Standalone script
If you want to run Headersentinel as a standalone script, just grab the `headersentinel.py` script from the `headersentinel` module/folder and copy it around.

## Usage
```
Usage: ./headersentinel.py [options] <target>

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  Set a custom port to connect to
  -c COOKIE_STRING, --cookie=COOKIE_STRING
                        Set cookies for the request
  -d, --disable-ssl-check
                        Disable SSL/TLS certificate validation
  -g, --use-get-method  Use GET method instead HEAD method
  -j, --json-output     Print the output in JSON format
  -i, --information     Display information headers
  -x, --caching         Display caching headers
  -k, --deprecated      Display deprecated headers
```

# HeaderSentinel - Security Header Check


## Check security headers on a target website

I did this tool to help me to check which security headers are enabled on certain websites.

The tool is very simple and it's the result of few minutes of coding.

It just check headers and print a report about which are enabled and which not

I think there is a lot to improve, and I will be grateful if somebody wants to help

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

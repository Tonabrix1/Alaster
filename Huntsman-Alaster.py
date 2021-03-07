# python-nmap
import nmap
import json, socket, discord, requests, time, io, os, sys, base64
from discord.ext import commands
from lxml import html
from scapy.layers.inet import traceroute
# python-whois
import whois as who
# py-jwt
import python_jwt as jwt
from myjwt.vulnerabilities import bruteforce_wordlist

token = 'ODE2MTU3MzMwOTY5MzI5NjY0.YD23vw.AvT2vRlTdk-79TjUGhhL6Nv7fVQ'
client = discord.Client()
bot = commands.Bot('*')
found = set()
default_crawl_exclusions = ''  # 'google,github,facebook,wikipedia,twitter,.gov'
halt_keywords = ['halt', 'stop', 'quit', 'exit', 'abort', 'cancel', 'wait']
halt_flag = False

commands = {
    **dict.fromkeys(['info', 'help', 'commands'], lambda x: info(x)),
    **dict.fromkeys(['ls', 'list', 'lst', 'l'], lambda x: listdir(x)),
    **dict.fromkeys(['scan', 'nmap'], lambda x: scan(x)),
    **dict.fromkeys(['crawl', 'spider'], lambda x: crawl(x)),
    **dict.fromkeys(['clear', 'delete', 'wipe'], lambda x: clear(x)),
    **dict.fromkeys(['ping', 'ip'], lambda x: ping(x)),
    **dict.fromkeys(['trace', 'traceroute'], lambda x: trace(x)),
    **dict.fromkeys(['whois', 'who', 'dnslookup'], lambda x: whois(x)),
    **dict.fromkeys(['scrape', 'get'], lambda x: scrape(x)),
    **dict.fromkeys(['decodejwt', 'jwtdecode'], lambda x: decode_jwt(x)),
    **dict.fromkeys(['decodeb64', 'b64decode'], lambda x: decodeb64(x)),
    **dict.fromkeys(['hextostr', 'hex2str', 'decodehex', 'hexdecode'], lambda x: hextostr(x)),
    **dict.fromkeys(['encodeb64', 'b64encode'], lambda x: encodeb64(x)),
    **dict.fromkeys(['inttobin', 'int2bin', 'bin', 'binint'], lambda x: int2binary(x)),
    **dict.fromkeys(['crackjwt', 'jwtcrack'], lambda x: crackjwt(x)),
    **dict.fromkeys(['forgejwt', 'makejwt', 'newjwt'], lambda x: forgejwt(x)),
    **dict.fromkeys(['post', 'scrapepost'], lambda x: post(x)),
    **dict.fromkeys(['postraw', 'rawpost'], lambda x: postraw(x)),
    **dict.fromkeys(['getraw', 'rawget'], lambda x: getraw(x)),
    **dict.fromkeys(['bustdir', 'dirbust', 'dirbuster', 'dirsearch', 'searchdirs'], lambda x: bustdir(x)),
    **dict.fromkeys(['snglhex', 'strurlhex', 'urlhex', 'urlencode',
                     'singlehex', 'snglhex', 'str2urlhex'], lambda x: strtourlhex(x)),
    **dict.fromkeys(['dbhex', 'strdburlhex', 'dburlhex', 'dburlencode',
                     'doublehex', 'str2dburlhex', 'dbenc'], lambda x: strtodoubleurlhex(x)),
    **dict.fromkeys(['crackuser', 'crackusername', 'cracku', 'bruteuser', 'bfuser'], lambda x: crackuser(x)),
    **dict.fromkeys(['crackpass', 'crackpassword', 'crackp', 'brutepass', 'bfpass'], lambda x: crackpass(x))
}


# init function
def initiate(): client.run(token)


@client.event
async def on_ready(): print('We have logged in as {0.user}'.format(client))


@client.event
async def on_message(msg):
    global halt_flag, halt_keywords
    if msg.author is not bot.user:
        mes = msg.content.lower()
        for key in halt_keywords:
            if key in mes: halt_flag = True
        if mes[0] == bot.command_prefix: await process_commands(msg)


# clear <num> or "all" for all messages
async def clear(msg):
    num = await splitmsg(msg, " ", 1)
    if num != 'all':
        number = int(num) + 1  # Converting the amount of messages to delete to an integer
        counter = 0
        async for x in msg.channel.history(limit=number):
            if counter < number:
                await x.delete()
                counter += 1
                time.sleep(1)
    else:
        async for x in msg.channel.history():
            await x.delete()
            time.sleep(1)


# util
async def process_commands(msg):
    global commands
    func = commands.get(str(msg.content.split(" ")[0][1:]).lower())
    await func(msg)


# *scan <host> ports:'<ports>' args:'<args>'
async def scan(msg):
    await msg.channel.send("Initiating scan, this may take a while...")
    nm = nmap.PortScanner()
    host = await splitmsg(msg, " ", 1)
    port = await checkoptional(msg, 'ports',"1-1024")
    args = await checkoptional(msg, 'args',"-sS -vv")
    nm.scan(hosts=host, ports=port, arguments=args)
    await msg.channel.send("Running command: " + nm.command_line())
    await pretty_nmap(nm, msg)


# util
async def pretty_nmap(nm, msg):
    outp = ""
    for host in nm.all_hosts():
        outp += '----------------------------------------------------\n'
        outp += 'Host : %s (%s)\n' % (host, nm[host].hostname())
        outp += 'State : %s\n' % nm[host].state()
        for proto in nm[host].all_protocols():
            outp += '----------\n'
            outp += 'Protocol : %s\n' % proto
            lport = nm[host][proto].keys()
            lport = sorted(lport)
            for port in lport: outp += ('port : %s\tstate : %s\n' % (port, nm[host][proto][port]['state']))
        try:
            await msg.channel.send(outp)
            outp = ""
        except discord.errors.HTTPException:
            await msg.channel.send("Caught an HTTP exception...")


# *crawl <url> <excludes>
async def crawl(msg):
    await msg.channel.send("Crawling...")
    global found, default_crawl_exclusions, halt_flag
    url = await splitmsg(msg, " ", 1)
    excludes = default_crawl_exclusions if len(msg.content.split(" ")) <= 2 else \
        await chopcsl(await splitmsg(msg, " ", 2))
    await recursive_crawl(url, msg, excludes)
    outp, i = "", 0
    for a in found:
        i += 1
        if a.startswith("http") or a.startswith("www") or "?" in a:
            outp += a + '\n'
        if i % 5 == 0:
            await msg.channel.send("Final list #" + str(int(i / 8)) + ": \n" + str(outp))
            outp = ""
    if outp != "": await msg.channel.send("Final list #" + str(int(i / 8)) + ": \n" + str(outp))
    found = set()
    if halt_flag: halt_flag = False


# util
async def recursive_crawl(url, msg, excludes):
    global found, halt_flag
    for ex in excludes:
        if url.__contains__(ex):
            print("out of scope link")
            return
    resp = requests.get(url)
    page = html.fromstring(resp.content)
    links = set(page.xpath('//a/@href'))
    links.update(page.xpath('//img/@src'))
    found.add(url)
    print(links)
    for link in links:
        if link not in found and url + link not in found and link[0] != '#':
            found.add(link)
            if len(link > 1) and link[0] == "/" and url[-1] != "/": found.add(url + link)
            await msg.channel.send("found: " + str(link))
            if halt_flag:
                await msg.channel.send("cancelling...")
                return found
            try:
                await recursive_crawl(link, msg, excludes)
            except requests.exceptions.MissingSchema:
                safe_url = url if url[-1] == "/" and len(link) > 1 and link[0] == "/" else url[:-1]
                safe_link = link if safe_url[-1] == '/' or link[0] == '/' else "/" + link
                await recursive_crawl(safe_url + safe_link, msg, excludes)


# *ping <host>
async def ping(msg):
    host = await splitmsg(msg, " ", 1)
    try: addr = socket.gethostbyname_ex(host)
    except socket.gaierror:
        await msg.channel.send("Couldn't get address info for that domain.")
        return
    outp = "Host: " + addr[0]
    for a in addr[1:]:
        if len(a) != 0:
            for b in a:
                if str(b) != "": outp += "\nIP: " + str(b)
    await msg.channel.send(outp)


# *trace <host>
async def trace(msg):
    host = [await splitmsg(msg, " ", 1)]
    old, buf = await qstdout()
    try: traceroute(host, maxttl=32)
    except socket.gaierror:
        await msg.channel.send("Couldn't get address info for that domain.")
        return
    ret = await deqstdout(old, buf)
    await msg.channel.send(ret)


# util
async def qstdout():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    return old, buf


# util
async def deqstdout(old, buf):
    sys.stdout = old
    return buf.getvalue()


# *whois <host>
async def whois(msg):
    host = await splitmsg(msg, " ", 1)
    a = who.whois(host)
    await msg.channel.send(a)


# *scrape <host> split:'<string>' len:'<len>'
async def scrape(msg):
    host = await splitmsg(msg, " ", 1)
    length = await checkoptional(msg, 'len', 10000)
    splt = await checkoptional(msg, 'split', None)
    msg.channel.send("Scraping data...")
    data = requests.get(host)
    d = data.text if len(data.text) <= length else data.text[:length]
    if splt is not None: d = d.split(splt)
    c, outp = 0, ''
    for dat in d:
        outp += dat
        c += len(dat)
        if c >= 450:
            await msg.channel.send(outp)
            time.sleep(1)
            c, outp = 0, ''
    if outp != '': await msg.channel.send(outp)


# decodejwt <token>
async def decode_jwt(msg):
    tk = await splitmsg(msg, " ", 1)
    tk = tk.split(".")
    header = base64.urlsafe_b64decode(tk[0] + '=' * (4 - len(tk[0]) % 4))
    payload = base64.urlsafe_b64decode(tk[1] + '=' * (4 - len(tk[1]) % 4))
    await msg.channel.send(header)
    await msg.channel.send(payload)


# decodeb64 <string>
async def decodeb64(msg):
    string = bytes(str(await splitmsg(msg, " ", 1)), 'utf-8')
    ans = base64.b64decode(string)
    await msg.channel.send(ans.decode("utf-8"))


# encodeb64 <string>
async def encodeb64(msg):
    string = bytes(await splitmsg(msg, " ", 1), 'utf-8')
    ans = base64.b64encode(string)
    await msg.channel.send(ans.decode("utf-8"))


# *inttobin size:'<size>' base:'<base>'
async def int2binary(msg):
    await msg.channel.send("Calculating")
    try:
        size = await checkoptional(msg, 'size', 8)
    except TypeError:
        await msg.channel.send("The size variable must be an integer.")
        size = 8
    try:
        base = await checkoptional(msg, 'base', 10)
    except TypeError:
        await msg.channel.send("The base variable must be an integer.")
        base = 10
    inp = int(await splitmsg(msg, " ", 1), base)
    bin_lst = list("0" * size)
    for f in bin_lst[:len(str(inp))]:
        bin_lst.remove(f)
    bin_lst.append(inp)
    outp = ""
    for a in bin_lst: outp += str(a)
    await msg.channel.send(str(bin(int(outp)))[2:])


# *crackjwt <csl, no spaces token> <filepath>
async def crackjwt(msg):
    await msg.channel.send("Cracking jwt...")
    payload = await chopcsl(await splitmsg(msg, " ", 1))
    lst = await splitmsg(msg, " ", 2)
    enc = await dictfromcsl(payload)
    key = bruteforce_wordlist(json.dumps(enc), lst)
    await msg.channel.send("Key: " + str(key))


# *forgejwt <csl, no spaces payload> <key> enc:'<encoding>'
async def forgejwt(msg):
    await msg.channel.send("Forging jwt...")
    payload = await chopcsl(await splitmsg(msg, " ", 1))
    key = await splitmsg(msg, " ", 2)
    enc = await checkoptional(msg, 'enc', 'HS256')
    values = await dictfromcsl(payload)
    encoded = jwt.encode(values, key, enc)
    await msg.channel.send(encoded)


# *post <host> <csl no spaces, obj> dat:'<data>'
async def post(msg):
    host = await splitmsg(msg, " ", 1)
    await msg.channel.send("Posting to: " + host)
    obj = await chopcsl(await splitmsg(msg, " ", 2))
    pst = await dictfromcsl(obj)
    dat = await checkoptional(msg, 'dat', '')
    resp = requests.post(url=host, headers=pst, data=dat).text
    await msg.channel.send(resp)


# util
async def chopcsl(csl) -> list: return str(csl).strip(" ").split(",")


# util
async def dictfromcsl(csl):
    pst = dict()
    for i in range(len(csl)):
        if i % 2 == 0: continue
        pst[csl[i]] = csl[i + 1]
    return pst


# *postraw <host> head:'<csl no spaces, headers>' dat:'<dat>'
async def postraw(msg):
    host = await splitmsg(msg, " ", 1)
    hd = await checkoptional(msg, 'head', {})
    hd = await dictfromcsl(await chopcsl(hd))
    dat = await checkoptional(msg, 'dat', '')
    ck = await checkoptional(msg, 'ck', '')
    req = requests.post(host, headers=hd, data=dat, cookies=ck)
    await sendchunk(msg, req.headers)


# *getraw <host> head:'<csl no spaces, headers>' ck:'<cookies>'
async def getraw(msg):
    host = await splitmsg(msg, " ", 1)
    hd = await checkoptional(msg, 'head', {})
    hd = await dictfromcsl(await chopcsl(hd))
    ck = await checkoptional(msg, 'ck', '')
    req = requests.get(host, headers=hd, cookies=ck)
    await sendchunk(msg, req.headers)


# util
async def splitmsg(msg, char, indx):
    if len(msg.content.split(char)) > indx: return msg.content.split(char)[indx]
    else: await msg.channel.send("List requires " + str(indx) + " args split by \'" + char + "\'")


# util
async def sendchunk(msg, s, length=100):
    if type(s) == str:
        for i in range(int(len(s)/length)):
            await msg.channel.send(s[i*length:(i+1)*length])
            time.sleep(1)
    elif type(s) == requests.structures.CaseInsensitiveDict or type(s) == dict:
        for a in s:
            await msg.channel.send(a + ": " + s[a])
            time.sleep(1)
    else: await msg.channel.send("Unknown response type")


# util
async def checkoptional(msg, s, default): return default if s not in msg.content else \
    str(msg.content.lower().split(s+":\'")[1]).split("\'")[0]

# *bustdir <host> (optional)<filepath>
async def bustdir(msg):
    global halt_flag
    await msg.channel.send("Initiating directory buster...")
    debug = False if "debug" not in msg.content else True
    url = await splitmsg(msg, " ", 1)
    excluded = await checkoptional(msg, 'ex', 404)
    alert = await checkoptional(msg, 'alrt', 403)
    excluded = [excluded] if "," not in str(excluded) else await chopcsl(excluded)
    alert = [alert] if "," not in str(alert) else await chopcsl(alert)
    lst = "dirlists1.txt" if len(msg.content.split(" ")) <= 2 else await splitmsg(msg, " ", 2)
    fnd, count = [], 0
    try:
        path = os.getcwd() + (lst if os.getcwd()[-1] == "/" or lst[0] == "/" else "/" + lst)
        if os.getcwd()[-1] == "/" and lst[0] == "/": path = os.getcwd() + url[1:]
        with open(path, "r") as dat:
            await msg.channel.send("Found file at: " + path)
            lst = dat.read().split("\n")
    except FileNotFoundError:
        await msg.channel.send("File couldn't be found at path: " + os.getcwd() +
                               (lst if os.getcwd()[-1] == "/" or (len(lst) > 1 and lst[0] == "/") else "/" + lst))
        return
    await msg.channel.send("List aggregated...")
    for dir in lst:
        count += 1
        safe_url = url if url[-1] != "/" or (len(dir) > 1 and dir[0] != "/") else url[:-1]
        safe_dir = dir if url[-1] == '/' or (len(dir) > 1 and dir[0]) == '/' else "/" + dir
        myurl = safe_url + safe_dir
        # try:
        k = requests.get(myurl, timeout=4)
        if debug or count % 15 == 0:
            if halt_flag:
                await msg.channel.send("Canceling attack...")
                halt_flag = False
                return
            await msg.channel.send("Try #" + str(count) + ": " + myurl)
        if k.history:
            for hhh in k.history:
                await msg.channel.send("redirect path: " + hhh.url + " status code: " + str(hhh.status_code))
        fnd = True
        # except:
        #    await msg.channel.send("couldn't connect to " + myurl)
        #    fnd = False
        if int(k.status_code) in [int(a) for a in excluded]:
            fnd = False
        if int(k.status_code) in [int(a) for a in alert]:
            await msg.channel.send("Found: " + str(k.status_code) + " at " + k.url)
            fnd = False
        if fnd:
            await msg.channel.send("Hit: " + k.url + "\nStatus code: " + str(k.status_code))
            fnd.append(k.url)
    await msg.channel.send("found: " + str(len(set(fnd))) + " directories")
    for a, b in zip(set(found), lst):
        await msg.channel.send(a + b if (len(b) > 0 and b[0] == "/") or a[-1] == "/" else "/" + b)


# *info
async def info(msg):
    global commands
    outp, lst = "", None
    for key in commands:
        if commands[key] != lst: outp += "\n" + key
        else: outp += ", (alias) " + key
        lst = commands[key]
    await msg.channel.send(outp)


# *listdir <path>
async def listdir(msg):
    command = os.getcwd() if len(msg.content.split(" ")) < 2 else \
        (os.getcwd() + "/" if await splitmsg(msg, " ", 1)[0] != "/" else "") + await splitmsg(msg, " ", 1)
    lst = os.listdir(command)
    outp, c = "", 0
    for a in lst:
        c += 1
        outp += a + ", " if lst[-1] != a else a
        if c >= 20:
            await msg.channel.send(outp)
            outp, c = "", 0
    if outp != "": await msg.channel.send(outp)


async def hextostr(msg):
    hx = msg.content.split(" ")[1:]
    hx = str(str(hx).strip()).replace("\\", "").replace("x", "")
    hx = bytes.fromhex(hx[2:-2])
    hx = hx.decode("utf-8")
    await msg.channel.send(hx)

async def strtourlhex(msg):
    s = await splitmsg(msg, " ", 1)
    ret = ""
    for a in s:
        ret += "%" + str(bytes.hex(a.encode("utf-8")))
    await msg.channel.send(ret)


async def strtodoubleurlhex(msg):
    s = await splitmsg(msg, " ", 1)
    ret = ""
    for a in s:
        ret += "%25" + str(bytes.hex(a.encode("utf-8")))
    await msg.channel.send(ret)


# *crackuser <host> <filepath> ex:'<excludes>' start:'<startpoint>' pw:'<password>'
async def crackuser(msg):
    global halt_flag
    url = await splitmsg(msg, " ", 1)
    data = "rockyou.txt" if len(msg.content.split(" ")) <= 2 else await splitmsg(msg, " ", 2)
    pw = await checkoptional(msg, "pw", '')
    startpoint = int(await checkoptional(msg, "start", 0))
    excluded = await checkoptional(msg, "ex", "invalid u")
    try:
        path = os.getcwd() + (data if os.getcwd()[-1] == "/" or data[0] == "/" else "/" + data)
        if os.getcwd()[-1] == "/" and data[0] == "/": path = os.getcwd() + url[1:]
        with open(path, "r", encoding='latin-1' if "rockyou" in path else 'utf-8') as dat:
            await msg.channel.send("Found file at: " + path)
            data = dat.read().split("\n")
    except FileNotFoundError:
        await msg.channel.send("File couldn't be found at path: " + os.getcwd() +
                               (data if os.getcwd()[-1] == "/" or (len(data) > 1 and data[0] == "/") else "/" + data))
    obj, count = {'username': '', 'password': pw}, startpoint
    for name in data[startpoint:]:
        if halt_flag:
            await msg.channel.send("Canceling attack...")
            halt_flag = False
            return
        count += 1
        obj['username'] = name
        x = requests.post(url, obj)
        if excluded not in x.text.lower():
            await msg.channel.send(x.text)
            await msg.channel.send("key:" + name + "\nAt website: " + url)
            return
        if count % 25 == 0: await msg.channel.send("attempt: " + str(count) + " last name used: " + name)
    await msg.channel.send("couldn't find it")


# *crackpass <host> <filepath> ex:'<excludes>' start:'<startpoint>' user:'<username>'
async def crackpass(msg):
    global halt_flag
    url = await splitmsg(msg, " ", 1)
    data = "rockyou.txt" if len(msg.content.split(" ")) <= 2 else await splitmsg(msg, " ", 2)
    name = await checkoptional(msg, "user", '')
    startpoint = int(await checkoptional(msg, "start", 0))
    excluded = await checkoptional(msg, "ex", "invalid p")
    try:
        path = os.getcwd() + (data if os.getcwd()[-1] == "/" or data[0] == "/" else "/" + data)
        if os.getcwd()[-1] == "/" and data[0] == "/": path = os.getcwd() + url[1:]
        with open(path, "r", encoding='latin-1' if "rockyou" in path else 'utf-8') as dat:
            await msg.channel.send("Found file at: " + path)
            data = dat.read().split("\n")
    except FileNotFoundError:
        await msg.channel.send("File couldn't be found at path: " + os.getcwd() +
                               (data if os.getcwd()[-1] == "/" or (len(data) > 1 and data[0] == "/") else "/" + data))
    obj, count = {'username': name, 'password': ''}, startpoint
    for pw in data[startpoint:]:
        if halt_flag:
            await msg.channel.send("Canceling attack...")
            halt_flag = False
            return
        count += 1
        obj['password'] = pw
        x = requests.post(url, obj)
        if excluded not in x.text.lower():
            await msg.channel.send(x.text)
            await msg.channel.send("key:" + pw + "\nAt website: " + url)
            return
        if count % 25 == 0: await msg.channel.send("attempt: " + str(count) + " last pass used: " + pw)
    await msg.channel.send("couldn't find it")


initiate()

# python-nmap
import nmap
import json, socket, discord, requests, time, io, os, sys, base64, subprocess, signal
from discord.ext import commands
from lxml import html
from scapy.layers.inet import traceroute
# python-whois
import whois as who
# py-jwt
import jwt
from myjwt.utils import jwt_to_json
from myjwt.modify_jwt import signature
from requests_toolbelt.utils import dump
import re

token = 'ODE2MTU3MzMwOTY5MzI5NjY0.YD23vw.AvT2vRlTdk-79TjUGhhL6Nv7fVQ'
client = discord.Client()
bot = commands.Bot('*')
found = set()
default_crawl_exclusions = 'google,github,facebook,wikipedia,twitter,.gov'
halt_keywords = ['halt', 'stop', 'quit', 'exit', 'abort', 'cancel', 'wait']
halt_flag = False
vpn_conn = None


commands = {
    **dict.fromkeys(['info', 'inf', 'commands'], lambda x: info(x)),
    **dict.fromkeys(['ls', 'list', 'lst', 'l'], lambda x: listdir(x)),
    **dict.fromkeys(['scan', 'nmap'], lambda x: scan(x)),
    **dict.fromkeys(['crawl', 'spider'], lambda x: crawl(x)),
    **dict.fromkeys(['clear', 'delete', 'wipe'], lambda x: clear(x)),
    **dict.fromkeys(['ping', 'ip'], lambda x: ping(x)),
    **dict.fromkeys(['trace', 'traceroute'], lambda x: trace(x)),
    **dict.fromkeys(['whois', 'who', 'dnslookup'], lambda x: whois(x)),
    **dict.fromkeys(['scrape', 'get'], lambda x: scrape(x)),
    **dict.fromkeys(['decodejwt', 'jwtdecode', 'jwt'], lambda x: decode_jwt(x)),
    **dict.fromkeys(['b64', 'decodeb64', 'b64decode'], lambda x: decodeb64(x)),
    **dict.fromkeys(['hextostr', 'hex2str', 'decodehex', 'hexdecode', 'hstr'], lambda x: hextostr(x)),
    **dict.fromkeys(['encodeb64', 'b64encode'], lambda x: encodeb64(x)),
    **dict.fromkeys(['inttobin', 'int2bin', 'bin', 'binint'], lambda x: int2binary(x)),
    **dict.fromkeys(['crackjwt', 'jwtcrack, breakjwt, jwtcracker, jwtbreaker'], lambda x: crackjwt(x)),
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
    **dict.fromkeys(['crackpass', 'crackpassword', 'crackp', 'brutepass', 'bfpass'], lambda x: crackpass(x)),
    **dict.fromkeys(['loginfuzzer', 'fuzzlogin', 'credfuzzer', 'fuzzcreds', 'postfuzzer'], lambda x: loginfuzzer(x)),
    **dict.fromkeys(['fullinfo', 'help', 'commandinf', 'finf'], lambda x: commandinfo(x)),
    **dict.fromkeys(['vpn','openvpn','vpnstatus'], lambda x: toggle_vpn(x)),
    **dict.fromkeys(['fuzzer', 'fuzz', 'repeater', 'repeat', 'getfuzzer'], lambda x: getfuzzer(x))}

full_info_dict = {
    **dict.fromkeys(['info', 'help', 'commands'], 'Usage: *info\nDescription: lists all commands.'),
    **dict.fromkeys(['ls', 'list', 'lst', 'l'], 'Usage: *ls <path>\nDescription: lists files in a directory. leave path blank for \'./\'.'),
    **dict.fromkeys(['scan', 'nmap'], 'Usage: *scan <host> ports:\'<ports>\' args:\'<args>\'\nDescription: scans an ip with nmap, default usages is \"nmap -sS -vvv -Pn -p 1-1024\"'),
    **dict.fromkeys(['crawl', 'spider'], 'Usage: *crawl <host> <excludes>\nDescription: gets all links on a page, then each link on all of the pages found, etc.  Leave excludes blank for default \"google, github, facebook, wikipedia, twitter, .gov\".'),
    **dict.fromkeys(['clear', 'delete', 'wipe'], 'Usage: *clear <num> or *clear all\nDescription: clears messages in a discord channel, clear all will clear messages until the bot times out.'),
    **dict.fromkeys(['ping', 'ip'], 'Usage: *ping <host>\nDescription: attempts to ping a domain to get a site\'s IP.'),
    **dict.fromkeys(['trace', 'traceroute'], 'Usage: *trace <host>\nDescription: attempts to use traceroute on a domain to find all IP\'s that a packet reaches during transit.'),
    **dict.fromkeys(['whois', 'who', 'dnslookup'], 'Usage: *whois <host>\nDescription: attempts a dns look-up on a domain.'),
    **dict.fromkeys(['scrape', 'get'], 'Usage *scrape <host>  split:\'<string>\' len:\'<len>\' regx:\'<regular expression>\'\nDescription: scrapes the html from a page, \'split\' splits the data into a comma separated list, \'len\' is the number of characters the bot will scrape. \'regx\' is the regular expression to use when carving values. Scrape can also be used with a regular expression in order to carve out matching values. EX: regx:\'<b>(.+?)</b>\''),
    **dict.fromkeys(['decodejwt', 'jwtdecode', 'jwt'], 'Usage: *decodejwt <token>\nDescription: decodes a b64url encoded jwt, requires a <header>.<payload>.<signature> structure with len%4=0 length.'),
    **dict.fromkeys(['b64','decodeb64', 'b64decode'], 'Usage: *b64 <string>\nDescription: decodes a b64 encoded string, must be len%4=0 structure.'),
    **dict.fromkeys(['hextostr', 'hex2str', 'decodehex', 'hexdecode', 'hstr'], 'Usage: *hextostr <hexstr>\nDescription: decodes a string from hex to ascii.'),
    **dict.fromkeys(['encodeb64', 'b64encode'], 'Usage: *encodeb64 <string>\nDescription: encodes a string to b64.'),
    **dict.fromkeys(['inttobin', 'int2bin', 'bin', 'binint'], 'Usage: *inttobin <int> size:\'<size>\' base:\'<base>\'\nDescription: changes an integer to a different base, defaults to base 2 (binary).'),
    **dict.fromkeys(['crackjwt', 'jwtcrack, breakjwt, jwtcracker, jwtbreaker'], 'Usage: *crackjwt <token> <filepath>\nDescription: attemps to crack the signature on a jwt via dictionary.'),
    **dict.fromkeys(['forgejwt', 'makejwt', 'newjwt'], 'Usage: *forgejwt (comma separated list, no spaces) <payload> <key> enc:\'<encoding>\'\nDescription: creates a jwt using a predefined payload, signature, and encoding.  default encoding is HS256.'),
    **dict.fromkeys(['post', 'scrapepost'], 'Usage: *post <host> (comma separated list, no spaces) <obj> dat:\'<data>\'\nDescription: scrapes a webpage after sending data via HTTP POST.'),
    **dict.fromkeys(['postraw', 'rawpost'], 'Usage: *postraw <host> head:\'(comma separated list, no spaces) <headers>\' dat:\'<dat>\' ck:\'<cookies>\'\nDescription: gets raw data (html + HTTP headers) from a post request.'),
    **dict.fromkeys(['getraw', 'rawget'], 'Usage: *getraw <host> head:\'(comma separated list, no spaces) <headers>\' ck:\'(comma separated list, no spaces) <cookies>\' auth:\'<authorization>\'\nDescription: gets raw data (html + HTTP headers) from a get request.'),
    **dict.fromkeys(['bustdir', 'dirbust', 'dirbuster', 'dirsearch', 'searchdirs'], 'Usage: *bustdir <host> <filepath> ex:\'<excluded codes>\' alrt:\'<alert codes>\' start:\'<index>\'\nDescription: tries to find valid directories via a dictionary attack, \'start\' will skip directory entries in the list until it reaches the number set.'),
    **dict.fromkeys(['snglhex', 'strurlhex', 'urlhex', 'urlencode',
                     'singlehex', 'snglhex', 'str2urlhex'], 'Usage: *snglhex <string>\nDescription: encodes a string to url hex (%<value>).'),
    **dict.fromkeys(['dbhex', 'strdburlhex', 'dburlhex', 'dburlencode',
                     'doublehex', 'str2dburlhex', 'dbenc'], 'Usage: *dbhex <string>\nDescription: double encodes a string to url hex (%25<value>).'),
    **dict.fromkeys(['crackuser', 'crackusername', 'cracku', 'bruteuser', 'bfuser'], 'Usage: *crackuser <host> <filepath> ex:\'<excludes>\' start:\'<startpoint>\' pw:\'<password>\'\nDescription: attempts a dictionary attack against the username attribute of a website (only useful for sites that disclose whether a username is valid).'),
    **dict.fromkeys(['crackpass', 'crackpassword', 'crackp', 'brutepass', 'bfpass'], 'Usage: *crackpass <host> <filepath> ex:\'<excludes>\' start:\'<startpoint>\' user:\'<username>\'\nDescription: attemps a dictionary attack against the password attribute of a website.'),
    **dict.fromkeys(['loginfuzzer','fuzzlogin','credfuzzer', 'fuzzcreds', 'postfuzzer', 'fuzz'],'Usage: *postfuzzer <host> list:\'<list of chars>\' usr:\'<user var name>\' pass:\'<pw var name>\' find:\'<kw to find on page>\' usrpl1:\'<payload to be added before fuzzing>\' userpl2:\'<payload to be added after fuzzing>\' passpl1:\'<payload to be added before fuzzing>\' passpl2:\'<payload added after fuzzing>\' usrperm:\'<unfuzzed username>\' passperm:\'<unfuzzed pass>\'\nDescription: attempts to fuzz variables in username or password elements of a website, especially useful forsome sql injections.'),
     **dict.fromkeys(['vpn','openvpn','vpnstatus'], 'Usage: *vpn <filename/index> to connect or <\'off\'> and/or <\'status\'>\nDescription: can connect, disconnect, and display the status of openvpn based connections'),
     **dict.fromkeys(['fuzzer','fuzz','repeater','repeat','getfuzzer'], 'Usage: *fuzzer <host> file:\'<filepath>\' or list:\'<comma separated list>\'\nDescription: allows alaster to fuzz directories or variables in a url, use $F$ to represent where the fuzzed variable should be placed. EX: *fuzz http://www.google.com/backup.$F$ file:\'extensions.txt\' carve:\'<label>(.+?)</label>\'')
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


#clear <num> or all for as many as the bot can without timing out
async def clear(msg):
    global halt_flag
    num = await splitmsg(msg, " ", 1)
    if num != 'all':
        number = int(num) + 1  # Converting the amount of messages to delete to an integer
        counter = 0
        async for x in msg.channel.history(limit=number):
            if halt_flag:
                await msg.channel.send("Cancelling...")
                halt_flag = False
                return
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
    mes = msg.content.split(" ")
    for i in range(len(mes)): 
        if mes[i] == "" and len(mes) > i and mes[i+1] == "": del mes[i+1]
        func = commands.get(str(msg.content.split(" ")[0][1:]).lower())
    if func is None: 
        await msg.channel.send("Error: command not recognized")
        return
    try:
        await func(msg)
    except Exception as error:
        await msg.channel.send(repr(error))


# *scan <host> ports:'<ports>' args:'<args>'
async def scan(msg):
    await msg.channel.send("Initiating scan, this may take a while...")
    nm = nmap.PortScanner()
    host = await splitmsg(msg, " ", 1)
    port = await checkoptional(msg, 'ports',"1-1024")
    args = await checkoptional(msg, 'args',"-sC -sV -vvv")
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
            await msg.channel.send("Caught an HTTP exception")


async def toggle_vpn(msg):
    global vpn_conn
    if vpn_conn is not None:
        for f in ['off','stop','disable','quit','exit','abort','disconnect']:
            if f in msg.content: 
                await msg.channel.send("Disconnecting from vpn, please wait...")
                x = vpn_conn
                os.killpg(os.getpgid(x.pid), signal.SIGTERM)
                time.sleep(5)
                vpn_conn = None
                os.system("sudo killall openvpn")
                await msg.channel.send("VPN is active: " + str(vpn_conn is not None))
        return
    else:
        for i in range(4):
            if str(i) in msg.content: file = {1:'htblab.ovpn',2:'tryhackme.ovpn',3:'htbarena.ovpn'}.get(i) 
        for f in ['htblab.ovpn','htbarena.ovpn','tryhackme.ovpn']:
            if f in msg.content: file = f
        if file is not None:
            x = subprocess.Popen(['sudo', 'openvpn', '--auth-nocache', '--config', "/home/pi/Huntsman-Alaster/"+file],preexec_fn=os.setsid)
            vpn_conn = x
            await msg.channel.send("VPN is active: " + str(vpn_conn is not None) +"\nUsing " + file)
        else: await msg.channel.send("Could not find file.")


# *crawl <url> <excludes>
async def crawl(msg):
    await msg.channel.send("Crawling...")
    global found, default_crawl_exclusions, halt_flag
    url = await splitmsg(msg, " ", 1)
    excludes = await chopcsl(default_crawl_exclusions) if len(msg.content.split(" ")) <= 2 else \
        await chopcsl(await splitmsg(msg, " ", 2))
    await recursive_crawl(url, msg, excludes)
    outp = ""
    await msg.channel.send("Found urls:\n")
    for a in found:
        outp += a + '\n'
        await msg.channel.send(outp)
    found = set()
    if halt_flag: halt_flag = False


# util
async def recursive_crawl(url, msg, excludes):
    global found, halt_flag
    print(url)
    for ex in excludes:
        if ex in url:
            print("out of scope link")
            return
        try: 
            if len(url) > 1:
                resp = requests.get(url)
            else: return found
        except:
            await msg.channel.send("couldn't get " + url)
            return found
    page = html.fromstring(resp.content)
    links = set(page.xpath('//a/@href'))
    links.update(page.xpath('//img/@src'))
    found.add(resp.url)
    for link in links:
        if len(link) > 0 and link not in found and await formatlink(url, link) not in found and link[0] != "#" and link not in ["./"," ","  ","../"]:
            for a in [link if link.startswith("ht") else url, await formatlink(url,link)]:
                    try:
                        print(a)
                        m = requests.get(a)
                        if int(m.status_code) != 404: found.add(a)
                    except: continue
                    await msg.channel.send("found: " + str(url+link + " with status code of " + str(m.status_code)))
                    if halt_flag:
                        await msg.channel.send("cancelling...")
                        return found
                    try: await recursive_crawl(link, msg, excludes)
                    except requests.exceptions.MissingSchema:
                        try: await recursive_crawl(await formatlink(url, link), msg, excludes)
                        except: continue
                        
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


# *scrape <host> split:'<string>' len:'<len>' regx:'<regular expression>'
async def scrape(msg):
    global halt_flag
    host = await splitmsg(msg, " ", 1)
    length = await checkoptional(msg, 'len', 10000)
    splt = await checkoptional(msg, 'split', None)
    regx = await checkoptional(msg, 'regx', '')
    await msg.channel.send("Scraping data...")
    data = requests.get(host)
    d = data.text if len(data.text) <= length else data.text[:length]
    if len(regx)>0:
        compiled = re.compile(regx)
        filtered = compiled.findall(data.text)
        for line in filtered: 
            if halt_flag:
                halt_flag = False
                return
            await msg.channel.send(line)
            time.sleep(1)
        await msg.channel.send("Filtered data complete")
        return
    if splt is not None: d = d.split(splt)
    c, outp = 0, ''
    for dat in d:
        outp += dat
        c += len(dat)
        if c >= 450:
            await msg.channel.send(outp)
            time.sleep(1)
            c, outp = 0, ''
            if halt_flag:
                halt_flag = False
                return
    if len(out) > 0: await msg.channel.send(outp)


#*postfuzzer <host> list:'<list of chars>' usr:'<user var name>' pass:'<pw var name>' find:'<kw to find on page>' usrpl1:'<payload to be added before fuzzing>' userpl2:'<payload to be added after fuzzing>' passpl1:'<payload to be added before fuzzing>' passplw:'<payload added after fuzzing>' usrperm:'<unfuzzable username>' passperm:'<unfuzzable pass>'
async def loginfuzzer(msg):
    global halt_flag
    host = await splitmsg(msg, " ", 1)
    lst = await checkoptional(msg, 'list', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    usr = await checkoptional(msg, 'usr', 'username')
    pw = await checkoptional(msg, 'pass', 'password')
    find = await checkoptional(msg, 'find', None)
    usrpl1, usrpl2 = await checkoptional(msg, 'usrpl1', ''), await checkoptional(msg, 'usrpl2', '')
    passpl1, passpl2 = await checkoptional(msg, 'passpl1', ''), await checkoptional(msg, 'passpl2', '')
    usrperm, passperm = await checkoptional(msg, 'usrperm', None), await checkoptional(msg, 'passperm', None)
    c = 0
    for a in lst:
        c += 1
        dat = {usr : usrpl1+a+usrpl2 if usrperm is None else usrperm, pw : passpl1+a+passpl2 if passperm is None else passperm}
        req = requests.post(url=host,data=dat)
        mylast = req.text
        if halt_flag:
            await msg.channel.send("Cancelling...")
            halt_flag = False
            return
        if c % 10 == 0 and find is not None: await msg.channel.send("data: " + str(dat) + "\n" + req.text)
        if mylast != req.text or find is not None and find in req.text or req.status_code == 404:
            await msg.channel.send(req.text)
            await msg.channel.send("keys: " + str(dat))
            return
        if find is None or len(find) <= 0: 
            time.sleep(1)
            await msg.channel.send(dat)
            await msg.channel.send(req.text)
    await msg.channel.send('found nothing matching kw: ' + find) 


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
    string = bytes(await wholestrafter(msg, " ", 1), 'utf-8')
    ans = base64.b64encode(string)
    await msg.channel.send(ans.decode("utf-8"))


# *inttobin <int> size:'<size>' base:'<base>'
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


# *crackjwt <token> <filepath> enc:'<encoding>'
async def crackjwt(msg):
    global halt_flag
    await msg.channel.send("Cracking jwt...")
    payload = await splitmsg(msg, " ", 1)
    lst = await splitmsg(msg, " ", 2)
    payld = jwt_to_json(payload)
    enc = await checkoptional(msg,"enc",None)
    with open(lst, encoding="latin-1") as file:
        all_password,c = [line.rstrip() for line in file], 0
    await msg.channel.send("List aggregated, starting attack...")
    for password in all_password:
        c += 1
        if halt_flag:
            await msg.channel.send("Cancelling attack...")
            halt_flag = False
            return
        newpayld = signature(payld, password) if enc is None else jwt.encode(payld, password, enc)
        if c % 5000 == 0: await msg.channel.send("Try #:" + str(c) + " " + password + " : " + str(newpayld))
        newsig = '' if len(str(newpayld).split(".")) <= 2 else str(newpayld).split(".")[2]
        if len(newsig) > 3 and len(str(payld).split(".")) > 2 and newsig == str(payld).split(".")[2]:
            key = password
        key =""
    await msg.channel.send("Key: " + str(key) if len(key) > 0 else "couldn't be found...")


# *forgejwt <csl, no spaces payload> <key> enc:'<encoding>'
async def forgejwt(msg):
    await msg.channel.send("Forging jwt...")
    payload = await chopcsl(await splitmsg(msg, " ", 1))
    key = '' if len(msg.content.split(" ")) <= 2 else await splitmsg(msg, " ", 2)
    enc = await checkoptional(msg, 'enc', 'HS256')
    values = await dictfromcsl(msg, payload)
    if enc == 'none':
        encoded = jwt.encode(values, None, algorithm=enc)
        await msg.channel.send(encoded)
        return
    if key != '':
        encoded = jwt.encode(values, key, algorithm=enc)
    else: 
        encoded = list()
        encoded.append(jwt.encode(values, key, algorithm=enc))
        encoded.append(jwt.encode(values, ' ', algorithm=enc))
    await msg.channel.send(encoded)


async def b64urlencode(data):
    byt = bytes(data, 'utf-8')
    encod = str(base64.b64encode(byt))
    return encod.replace('+', '-').replace('/', '_').replace('=', '')


# *post <host> <csl no spaces, obj> dat:'<data>'
async def post(msg):
    host = await splitmsg(msg, " ", 1)
    await msg.channel.send("Posting to: " + host)
    obj = await chopcsl(await splitmsg(msg, " ", 2))
    pst = await dictfromcsl(msg, obj)
    dat = await checkoptional(msg, 'dat', '')
    resp = requests.post(url=host, headers=pst, data=dat).text
    await msg.channel.send(resp)


# util
async def chopcsl(csl) -> list: return str(csl).strip(" ").split(",")


# util (takes a list)
async def dictfromcsl(msg, csl: list) -> dict:
    pst = dict()
    if len(csl) < 2 or len(csl) % 2 != 0:
        await msg.channel.send("Comma separated list: " + str(csl) + " must be at least length 2 and even.")
        return None
    for i in range(len(csl)):
        if i % 2 == 1: continue
        pst[csl[i]] = csl[i + 1]
    return pst


# *postraw <host> head:'<csl no spaces, headers>' dat:'<dat>' ck:'<cookies>'
async def postraw(msg):
    host = await splitmsg(msg, " ", 1)
    hd = await checkoptional(msg, 'head', {})
    hd = await dictfromcsl(msg, await chopcsl(hd)) if hd != {} else dict()
    dat = await checkoptional(msg, 'dat', '')
    ck = await checkoptional(msg, 'ck', '')
    ck = await dictfromcsl(ck) if ck != '' else ck
    req = requests.post(host, headers=hd, data=dat, cookies=ck)
    data = dump.dump_all(req)
    await sendchunk(msg, data.decode('latin-1'), 350)

# *getraw <host> head:'<csl no spaces, headers>' ck:'<csl no spaces, cookies>' auth:'<authorization>'
async def getraw(msg):
    host = await splitmsg(msg, " ", 1)
    hd = await checkoptional(msg, 'head', {})
    if hd != {}: hd = await dictfromcsl(await chopcsl(hd))
    ck = await checkoptional(msg, 'ck', '')
    auth = await checkoptional(msg, 'auth', '')
    if len(auth) > 1: hd.update({"Authorization": auth})
    if len(ck) > 0: hd.update({"Cookie": ck})
    await msg.channel.send("Using auth" + str(auth))
    req = requests.get(host, headers=hd)
    data = dump.dump_all(req)
    await sendchunk(msg, data.decode('latin-1'), 350)


# util
async def splitmsg(msg, char, indx):
    if len(msg.content.split(char)) > indx: return msg.content.split(char)[indx]
    else: await msg.channel.send("List requires " + str(indx) + " args split by \'" + char + "\'")


# util
async def sendchunk(msg, s, length=100):
    global halt_flag
    if type(s) == str:
        chunkn = int(len(s)/length)
        for i in range(chunkn):
            await msg.channel.send("```" + (s[i*length:(i+1)*length] if i+1 != chunkn or len(s) % length == 0 else s[i*length:]) + "```")
            time.sleep(1)
    elif type(s) == requests.structures.CaseInsensitiveDict or type(s) == dict:
        for a in s:
            await msg.channel.send("```" + a + ": " + s[a] + "```")
            time.sleep(1)
            if halt_flag:
                halt_flag = False
                return
    else: await msg.channel.send("sendchunk(): Unknown response type")


# util
async def checkoptional(msg, s, default): 
    filt = [":\"\"",":\'\'",":``",":\"",":\'",":`"]
    for b in filt:    
        if s + b in msg.content: return str(msg.content.split(s+b)[1]).split(b.strip(":"))[0]
    return default


# *bustdir <host> <filepath> ex:'<excluded codes>' alrt:'<alert codes>' start:'<index>'
async def bustdir(msg):
    global halt_flag
    await msg.channel.send("Initiating directory buster...")
    debug = False if "debug" not in msg.content else True
    url = await splitmsg(msg, " ", 1)
    excluded = await checkoptional(msg, 'ex', 404)
    alert = await checkoptional(msg, 'alrt', 403)
    excluded = [excluded] if "," not in str(excluded) else await chopcsl(excluded)
    alert = [alert] if "," not in str(alert) else await chopcsl(alert)
    lst = "quickhits.txt" if len(msg.content.split(" ")) <= 2 else await splitmsg(msg, " ", 2)
    fnd, count = [], int(await checkoptional(msg, 'start', 0))
    try:
        path = os.getcwd() + (lst if os.getcwd()[-1] == "/" or lst[0] == "/" else "/" + lst)
        if os.getcwd()[-1] == "/" and lst[0] == "/": path = os.getcwd() + lst[1:]
        with open(path, "r",encoding="latin-1") as dat:
            await msg.channel.send("Found file at: " + path)
            lst = dat.read().split("\n")
    except FileNotFoundError:
        await msg.channel.send("File couldn't be found at path: " + os.getcwd() +
                               (lst if os.getcwd()[-1] == "/" or (len(lst) > 1 and lst[0] == "/") else "/" + lst))
        return
    await msg.channel.send("List aggregated...")
    for dr in lst[count:]:
        count += 1
        myurl = await formatlink(url, dr)
        k = requests.get(myurl, timeout=4)
        if debug or count % 15 == 0:
            if halt_flag:
                await msg.channel.send("Canceling attack...")
                await msg.channel.send("Final list: " + str(fnd))
                halt_flag = False
                return
            await msg.channel.send("Try #" + str(count) + ": " + myurl)
        if k.history:
            for hhh in k.history:
                await msg.channel.send("redirect path: " + hhh.url + " status code: " + str(hhh.status_code))
        fd = True
        if int(k.status_code) in [int(a) for a in excluded]:
            fd = False
        elif int(k.status_code) in [int(a) for a in alert]:
            await msg.channel.send("Found: " + str(k.status_code) + " at " + k.url)
            fd = False
        if fd:
            await msg.channel.send("Hit: " + k.url + "\nStatus code: " + str(k.status_code))
            fnd.append(str(k.url))
    await msg.channel.send("found: " + str(len(set(fnd))) + " directories")
    for b in set(found):
        await msg.channel.send(await formatlink(url, b))

#util
async def formatlink(url, dr):
    print(url, dr)
    url = url.replace(" ","")
    dr = dr.replace(" ","")
    if len(url) <= 3 or len(dr) <= 0: 
        print("invalid link/dir")
        return
    url = str(url) if url[-1] != "#" else str(url[:-1])
    dr = str(dr) if dr[0] != "#" else str(dr[1:])
    if url[-1] in ["=","?"]: return url + dr if dr[0] not in["/","?","\\"] else dr[1:]
    elif url[-1] == "/" and dr[0] == "/": return url + dr[1:]
    elif url[-1] == "/" or dr[0] == "/": return url + dr
    else: return url + "/" + dr


# *info
async def info(msg):
    global commands
    outp, lst = "", None
    for key in commands:
        if commands[key] != lst: outp += "\n" + key
        else: outp += ", (alias) " + key
        lst = commands[key]
    await msg.channel.send(outp)

async def commandinfo(msg):
    global full_info_dict
    key = await splitmsg(msg, " ", 1)
    await msg.channel.send(key + "\n" + full_info_dict[key])


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
    hx = await wholestrafter(msg, 1, " ")
    hx = str(str(hx).strip()).replace("\\", "").replace("x", "")
    hx = bytes.fromhex(hx[2:-2])
    hx = hx.decode("latin-1")
    await msg.channel.send(hx)

async def strtourlhex(msg):
    s = await wholestrafter(msg, 1, " ")
    ret = ""
    for a in s:
        ret += "%" + str(bytes.hex(a.encode("utf-8")))
    await msg.channel.send(ret)


#util
async def wholestrafter(msg, index, char):
    a,b,c = msg.content, False, ""
    for d in a:
        if b: c += d
        if d == char: b = True
    return c

async def strtodoubleurlhex(msg):
    s = await wholestrafter(msg, 1, " ")
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

#*fuzz <host> file:'<filepath>' or list:'csl' carve:'<regex>'
async def getfuzzer(msg):
    global halt_flag
    host = await splitmsg(msg, " ", 1)
    fil = await checkoptional(msg, 'file', '')
    lst = await checkoptional(msg, 'list', '')
    carve = await checkoptional(msg, 'carve', '(.+?)')
    compiled = re.compile(carve)
    print(fil)
    print(lst.split("\n"))
    print(host)
    if len(fil) + len(lst) == 0:
        await msg.channel.send("Found no valid file or list entries")
        return
    elif len(fil) > 1:
        with open(fil,'r') as mydat:
            for line in mydat:
                mes = requests.get(host.replace("$F$",line)).text
                compiled.findall(mes)
                if halt_flag:
                    halt_flag = False
                    return
                await sendchunk(msg, mes)
        await msg.channel.send("Fuzz by file completed.")
    else:
        lst = lst.split("\n") if "\n" in lst else lst.split(",")
        for line in lst:
            mes = requests.get(host.replace("$F$",line)).text
            compiled.findall(mes)
            if halt_flag:
                halt_flag = False
                return
            await senchunk(msg, mes)
        await msg.channel.send("Fuzz by list completed.")


initiate()

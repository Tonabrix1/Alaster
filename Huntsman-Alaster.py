import nmap
from discord.ext import commands
import socket
import discord
import requests
from lxml import html
import time
from scapy.layers.inet import traceroute
import sys
import io
import whois as who
import binascii
import jwt
import base64

token = ''
client = discord.Client()
bot = commands.Bot('*')
found = set()
default_crawl_exclusions = 'google,github,facebook,wikipedia,twitter,.gov'

commands = {
    'scan': lambda x: scan(x),
    'crawl': lambda x: crawl(x),
    'clear': lambda x: clear(x),
    'ping': lambda x: ping(x),
    'trace': lambda x: trace(x),
    'whois': lambda x: whois(x),
    'scrape': lambda x: scrape(x),
    'decodejwt': lambda x: decode_jwt(x),
    'decodeb64': lambda x: decodeb64(x),
    'encodeb64': lambda x: encodeb64(x),
    'inttobin': lambda x: int2binary(x)
}

def initiate(): client.run(token)

@client.event
async def on_ready(): print('We have logged in as {0.user}'.format(client))

@client.event
async def on_message(msg):
    if msg.content[0] == bot.command_prefix:
        #try :
            await process_commands(msg)
        #except TypeError: await msg.channel.send("Invalid command.")

#clear <num> or "all" for all messages
async def clear(msg):
    num = msg.content.split(" ")[1]
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

async def process_commands(msg):
    global commands
    func = commands.get(str(msg.content.split(" ")[0][1:]).lower())
    await func(msg)

#*scan <host> ports:'<ports>' args:'<args>'
async def scan(msg):
    await msg.channel.send("Initiating scan, this may take a while...")
    nm = nmap.PortScanner()
    host = msg.content.split(" ")[1]
    port = "1-1024" if "ports\'" not in msg.content else str(msg.content.split("ports:\'")[1]).split("\'")[0]
    args = "-sS -vv" if "args\'" not in msg.content else str(msg.content.split("args:\'")[1]).split("\'")[0]
    nm.scan(hosts=host,ports=port,arguments=args)
    await msg.channel.send("Running command: " + nm.command_line())
    await pretty_nmap(nm,msg)

async def pretty_nmap(nm, msg):
    outp = ""
    for host in nm.all_hosts():
        outp += ('----------------------------------------------------\n')
        outp += ('Host : %s (%s)\n' % (host, nm[host].hostname()))
        outp += ('State : %s\n' % nm[host].state())
        for proto in nm[host].all_protocols():
            outp += ('----------\n')
            outp += ('Protocol : %s\n' % proto)
            lport = nm[host][proto].keys()
            lport = sorted(lport)
            for port in lport: outp += ('port : %s\tstate : %s\n' % (port, nm[host][proto][port]['state']))
    await msg.channel.send(outp)

#*crawl <url> <excludes>
async def crawl(msg):
    global found, default_crawl_exclusions
    url = msg.content.split(" ")[1]
    excludes = default_crawl_exclusions if len(msg.content.split(" ")) <= 2 else str(msg.content.split(" ")[2]).split(",")
    await recursive_crawl(url, msg, excludes)
    outp = ""
    for i, a in enumerate(found):
        if a.startswith("http"):
            if i:
                outp += "\n"
            outp += a
    await msg.channel.send("Final list: \n" + str(outp))
    found = set()

async def recursive_crawl(url, msg, excludes):
    global found
    for ex in excludes:
        if url.__contains__(ex):
            print("out of scope link")
            return
    resp = requests.get(url)
    if str(resp.status_code) == '404':
        print("404'd")
        return
    page = html.fromstring(resp.content)
    links = set(page.xpath('//a/@href'))
    found.add(url)
    print(links)
    for link in links:
        if link not in found and url+link not in found and link[0] != '#':
            found.add(link)
            if link[0] == "/": found.add(url+link)
            await msg.channel.send("found: " + str(link))
            try: await recursive_crawl(link, msg, excludes)
            except requests.exceptions.MissingSchema: await recursive_crawl(url+link,msg, excludes) if url[-1] == '/' or link[0] == '/' else await recursive_crawl(url+"/"+link,msg,excludes)
            finally: return

#*ping <host>
async def ping(msg):
    host = msg.content.split(" ")[1]
    addr = socket.gethostbyname_ex(host)
    outp = "Host: " + addr[0]
    for a in addr[1:]:
        if len(a) != 0:
            for b in a:
                if str(b) != "": outp += "\nIP: " + str(b)
    await msg.channel.send(outp)

#*trace <host>
async def trace(msg):
    host = [msg.content.split(" ")[1]]
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    result, unans = traceroute(host,maxttl=32)
    sys.stdout = old_stdout
    ret = buffer.getvalue()
    await msg.channel.send(ret)

#*whois <host>
async def whois(msg):
    host = msg.content.split(" ")[1]
    a = who.whois(host)
    await msg.channel.send(a)

#*scrape <host> split:'<string>' len:'<len>'
async def scrape(msg):
    host = msg.content.split(" ")[1]
    length = 10000 if "len:\'" not in msg.content else str(msg.content.split("len: \'")[1]).split("\'")[0]
    splt = None if "split:\'" not in msg.content else str(msg.content.split("split: \'")[1]).split("\'")[0]
    msg.channel.send("Scraping data...")
    data = requests.get(host)
    d = data.text if len(data.text) <= length else data.text[:length]
    if splt is None: d = d.split(splt)
    c , outp = 0, ''
    for d in data:
        outp += d.decode('utf=8')
        c += len(d)
        if c >= 450:
            await msg.channel.send(outp)
            time.sleep(1)
            c, outp = 0, ''
    if outp != '': await msg.channel.send(outp)

#decodejwt <token>
async def decode_jwt(msg):
    token = msg.content.split(" ")[1]
    token = token.split(".")
    header = base64.urlsafe_b64decode(token[0] + '=' * (4 - len(token[0]) % 4))
    payload = base64.urlsafe_b64decode(token[1] + '=' * (4 - len(token[1]) % 4))
    await msg.channel.send(header)
    await msg.channel.send(payload)

#decodeb64 <string>
async def decodeb64(msg):
    string = bytes(str(msg.content.split(" ")[1]),'utf-8')
    ans = base64.b64decode(string)
    await msg.channel.send(ans.decode("utf-8"))

#encodeb64 <string>
async def encodeb64(msg):
    string = bytes(str(msg.content.split(" ")[1]), 'utf-8')
    ans = base64.b64encode(string)
    await msg.channel.send(ans.decode("utf-8"))

#*inttobin size:'<size>' base:'<base>'
async def int2binary(msg):
    print("Calculating")
    try: size = 8 if "size:\'" not in msg.content else int(str(msg.content.split("size:\'")[1]).split("\'")[0])
    except TypeError: await msg.channel.send("The size variable must be an integer.")
    try: base = 10 if "base:\'" not in msg.content else int(str(msg.content.split("base:\'")[1]).split("\'")[0])
    except TypeError: await msg.channel.send("The base variable must be an integer.")
    inp = int(msg.content.split(" ")[1], base)
    k = list("0"*size)
    for f in k[:len(str(inp))]:
        k.remove(f)
    k.append(inp)
    l = ""
    for a in k: l += str(a)
    await msg.channel.send(str(bin(int(l)))[2:])

#*crackudict
"""async def crack_user_dict(url, data, debug=False, start_point=0):
    count = 0
    obj = {'username': '', 'password': ''}
    for name in data:
        count += 1
        if count < start_point: continue
        obj['username'] = name
        x = requests.post(url, obj)
        if error_msg_usr not in x.text:
            print(x.text)
            alaster.send("key:" + name + "\nAt website: " + url)
            alaster.act()
            return
        if count % 25 == 0: print("attempt: " + str(count) + " last name used: " + name)
        if debug: print(name)
    if debug: print("couldn't find it")"""

initiate()
#!/usr/bin/env python

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import logging
import os
import random
import select
import socket
import sys
import time

# Set default config values
CONFIG = {
    "stun": ["stun.l.google.com:19302", "stun1.l.google.com:19302",
             "stun2.l.google.com:19302", "stun3.l.google.com:19302",
             "stun4.l.google.com:19302"],
    "turn": [],  # Contains dicts with "server", "user", "pass" keys
    "ip4": "172.31.0.100",
    "localhost": "127.0.0.1",
    "ip6_prefix": "fd50:0dbc:41f2:4a3c",
    "localhost6": "::1",
    "ip4_mask": 24,
    "ip6_mask": 64,
    "subnet_mask": 32,
    "svpn_port": 5800,
    "tcp_port": 30000,
    "local_uid": "",
    "uid_size": 40,
    "sec": True,
    "wait_time": 30,
    "buf_size": 4096,
    "tincan_logging": 1,
    "controller_logging" : "INFO",
    "multihop": False
}

IP_MAP = {}

def gen_ip4(uid, peer_map, ip4=None):
    ip4 = ip4 or CONFIG["ip4"]
    try:
        return peer_map[uid]
    except KeyError:
        pass

    ips = set(peer_map.itervalues())
    prefix, _ = ip4.rsplit(".", 1)
    # We allocate to *.101 - *.254. This ensures a 3-digit suffix and avoids
    # the broadcast address. *.100 is our IPv4 address.
    for i in range(101, 255):
        peer_map[uid] = "%s.%s" % (prefix, i)
        if peer_map[uid] not in ips:
            return peer_map[uid]
    del peer_map[uid]
    raise OverflowError("Too many peers, out of IPv4 addresses")

def gen_ip6(uid, ip6=None):
    if ip6 is None:
        ip6 = CONFIG["ip6_prefix"]
    for i in range(0, 16, 4): ip6 += ":" + uid[i:i+4]
    return ip6

def b2a_ip6(bin_ip6):
    a_ip6=""
    for i in range (0, 16, 2):
         a_ip6 += bin_ip6[i:i+2].encode("hex")
         if not i == 14:
             a_ip6 += ":"
    return a_ip6
         

def gen_uid(ip4):
    return hashlib.sha1(ip4).hexdigest()[:CONFIG["uid_size"]]

def make_call(sock, **params):
    if socket.has_ipv6: dest = (CONFIG["localhost6"], CONFIG["svpn_port"])
    else: dest = (CONFIG["localhost"], CONFIG["svpn_port"])
    return sock.sendto(json.dumps(params), dest)

def do_set_cb_endpoint(sock, addr):
    return make_call(sock, m="set_cb_endpoint", ip=addr[0], port=addr[1])

def do_register_service(sock, username, password, host):
    return make_call(sock, m="register_service", username=username,
                     password=password, host=host)

def do_create_link(sock, uid, fpr, overlay_id, sec, cas, stun=None, turn=None):
    if stun is None:
        stun = random.choice(CONFIG["stun"])
    if turn is None:
        if CONFIG["turn"]:
            turn = random.choice(CONFIG["turn"])
        else:
            turn = {"server": "", "user": "", "pass": ""}
    return make_call(sock, m="create_link", uid=uid, fpr=fpr,
                     overlay_id=overlay_id, stun=stun, turn=turn["server"],
                     turn_user=turn["user"],
                     turn_pass=turn["pass"], sec=sec, cas=cas)

def do_trim_link(sock, uid):
    return make_call(sock, m="trim_link", uid=uid)

def do_set_local_ip(sock, uid, ip4, ip6, ip4_mask, ip6_mask, subnet_mask):
    return make_call(sock, m="set_local_ip", uid=uid, ip4=ip4, ip6=ip6,
                     ip4_mask=ip4_mask, ip6_mask=ip6_mask,
                     subnet_mask=subnet_mask)

def do_set_remote_ip(sock, uid, ip4, ip6):
    return make_call(sock, m="set_remote_ip", uid=uid, ip4=ip4, ip6=ip6)

def do_get_state(sock):
    return make_call(sock, m="get_state")

def do_set_logging(sock, logging):
    return make_call(sock, m="set_logging", logging=logging)

def do_inject_to_channel(sock, src_uid, dest_uid, data):
    b64=base64.b64encode(data)
    return make_call(sock, m="inject_to_channel", src_uid=src_uid, dest_uid=dest_uid, data=b64)

class UdpServer(object):
    def __init__(self, user, password, host, ip4, uid):
        self.state = {}
        self.peers = {}
        self.far_peers = {}
        self.peerlist = set()
        self.ip_map = dict(IP_MAP)

        if socket.has_ipv6:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            self.tcp_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("", 0))

        do_set_logging(self.sock, CONFIG["tincan_logging"])
        do_set_cb_endpoint(self.sock, self.sock.getsockname())
        do_set_local_ip(self.sock, uid, ip4, gen_ip6(uid), CONFIG["ip4_mask"],
                        CONFIG["ip6_mask"], CONFIG["subnet_mask"])
        do_register_service(self.sock, user, password, host)
        do_get_state(self.sock)

        if CONFIG["multihop"]:
            if socket.has_ipv6:
                self.tcp_sock = socket.socket(socket.AF_INET6, 
                                              socket.SOCK_STREAM)
            else:
                self.tcp_sock = socket.socket(socket.AF_INET, 
                                              socket.SOCK_STREAM)

            #Wait until ipop tap device up
            while True:
                try:
                    self.tcp_sock.bind((gen_ip6(uid), CONFIG["tcp_port"]))
                except:
                    time.sleep(1)
                    continue
                else:
                    break

            self.tcp_sock.listen(1)
            self.sock_list = [self.sock, self.tcp_sock]
            self.tcp_conn = None
        else:
            self.sock_list = [self.sock]

    def create_connection(self, uid, data, overlay_id, sec, cas, ip4):
        self.peerlist.add(uid)
        do_create_link(self.sock, uid, data, overlay_id, sec, cas)
        do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))

    def trim_connections(self):
        for k, v in self.peers.iteritems():
            if "fpr" in v and v["status"] == "offline":
                if v["last_time"] > CONFIG["wait_time"] * 2:
                    do_trim_link(self.sock, k)

    def tcp_send(self, to, msg):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.connect((to, CONFIG["tcp_port"]))
        s.send(msg)
        s.close()

    def update_farpeers(self, key, hop_count, via):
        if not key in self.far_peers:
            self.far_peers[key] = {}
            self.far_peers[key]["hop_count"] = sys.maxint
        if self.far_peers[key]["hop_count"] >= hop_count:
            self.far_peers[key]["hop_count"] = hop_count
            self.far_peers[key]["via"] = via

    def lookup(self, dest_ip6):
        for k, v in self.peers.iteritems():
            if "ip6" in v:
                msg = json.dumps({"m":"lookup_request", "dest_ip6":dest_ip6, 
                                  "via":[self.state["_ip6"], v["ip6"]]})
                self.tcp_send(v["ip6"], msg)

    def handle_lookup_request(self, msg):
        for k, v in self.peers.iteritems():
            # found in peer, do lookup_reply
            if "ip6" in v and v["ip6"] == msg["dest_ip6"]:
                # IP is found in my peers,  
                # send reply message back to previous sender
                jmsg = json.dumps({"m":"lookup_reply", 
                       "dest_ip6":msg["via"][-2], "src_ip6":msg["dest_ip6"], 
                       "src_uid":k, "via":msg["via"], 
                       "hop_uid":self.state["_uid"], "hops":2})
                self.tcp_send(msg["via"][-2], jmsg)
                self.update_farpeers(msg["via"][0], len(msg["via"]), 
                                     msg["via"][-2]) 
                return

        # dest not in my peer, multicasting to peers
        for k, v in self.peers.iteritems():
            #Do not send lookup_request back to source
            if msg["via"][-2] == v["ip6"]:
                continue

            #If this message visit here before, just drop it
            cyclic = False
            for via in msg["via"]:
                if v["ip6"] == via:
                    cyclic = True
                    break
                 
            #Multicast lookup_request
            if not cyclic:
                msg["via"].append(v["ip6"])
                msg = json.dumps(msg)
                self.tcp_send(v["ip6"], msg)

    def handle_lookup_reply(self, msg):
        # update far_peers if ip6 does not exists or shortest hop count
        self.update_farpeers(msg["src_ip6"], msg["hops"], 
                             msg["via"][-msg["hops"] + 1]) 
        if msg["dest_ip6"] != self.state["_ip6"]:
            self.tcp_send(hop, msg)
        
        for k, v in self.peers.iteritems():
            if msg["dest_ip6"] == v["ip6"]:
                return
        self.update_farpeers(msg["dest_ip6"], len(msg["via"]) - msg["hops"], 
                             msg["via"][len(msg["via"]) - msg["hops"]]) 

    def serve(self):
        socks, _, _ = select.select(self.sock_list, [], [], CONFIG["wait_time"])
        for sock in socks:
            if sock == self.sock:
                data, addr = sock.recvfrom(CONFIG["buf_size"])
                # TODO maybe we should put header to distinguish actual data 
                # packet and controller message
                if data[0] == "{" and data[-2] == "}" and data[-1] == "\n":
                    msg = json.loads(data)
                    logging.debug("recv %s %s" % (addr, data))
                    msg_type = msg.get("type", None)

                    if msg_type == "local_state": self.state = msg
                    elif msg_type == "peer_state": 
                        if "far_peers" in self.peers:
                            msg["far_peers"] = \
                                   self.peers[msg["uid"]]["far_peers"]
                        self.peers[msg["uid"]] = msg
                    # we ignore connection status notification for now
                    elif msg_type == "con_stat": pass
                    elif msg_type == "con_req" or msg_type == "con_resp":
                        fpr_len = len(self.state["_fpr"])
                        fpr = msg["data"][:fpr_len]
                        cas = msg["data"][fpr_len + 1:]
                        ip4 = gen_ip4(msg["uid"], self.ip_map, 
                                      self.state["_ip4"])
                        self.create_connection(msg["uid"], fpr, 1, 
                                               CONFIG["sec"], cas, ip4)
                else:
                    # 0:20 source uid
                    # 20:40 destination uid
                    # 40:46 destination mac
                    # 46:52 source mac
                    # 52:53 ether type
                    # we don't handle 802.1Q at this point
         
                    #packet is ipv6 and not multicast
                    if data[52:54] == "\x86\xdd" and data[78:80] != "\xff\x02":
                        dest_ip6=b2a_ip6(data[78:94])
                        logging.debug("non-peer destination({0}) packet is" 
                                                " forwarded".format(dest_ip6))
                        if dest_ip6 in self.far_peers:
                            self.tcp_send(self.far_peers[dest_ip6]["via"], 
                                          data[40:])
                        else:
                            self.lookup(dest_ip6)

            if not CONFIG["multihop"]:
                return
             
            if sock == self.tcp_sock:
                self.tcp_conn, addr = sock.accept()
                logging.debug("TCP Connection from {0}".format(addr))
                self.sock_list.append(self.tcp_conn)

            if sock == self.tcp_conn:
                data = sock.recv(CONFIG["buf_size"]);
                if not data:
                    self.sock_list.remove(self.tcp_conn)
                    return

                if data[0] == "{" and data[-1] == "}":
                    msg = json.loads(data)
                    logging.debug("Control message arrived {0}".format(msg))
                    if msg["m"] == "lookup_request":
                        self.handle_lookup_request(msg)
                    elif msg["m"] == "lookup_reply":
                        self.handle_lookup_reply(msg)
                else:
                    dest_ip6=b2a_ip6(data[38:54])
                    logging.debug("Traffic packet destined to {0}" 
                                  "arrived".format(dest_ip6))
                    for k, v in self.peers.iteritems():
                        if v["ip6"] == dest_ip6:
                            do_inject_to_channel(self.sock, self.state["_uid"], 
                                                 k, data)
                            return
                      
                    if dest_ip6 in self.far_peers:
                        self.tcp_send(self.far_peers[dest_ip6]["via"], data)

def setup_config(config):
    """Validate config and set default value here. Return ``True`` if config is
    changed.
    """
    if not config["local_uid"]:
        uid = binascii.b2a_hex(os.urandom(CONFIG["uid_size"] / 2))
        config["local_uid"] = uid
        return True # modified
    return False

def load_peer_ip_config(ip_config):
    with open(ip_config) as f:
        ip_cfg = json.load(f)

    for peer_ip in ip_cfg:
        uid = peer_ip["uid"]
        ip = peer_ip["ipv4"]
        IP_MAP[uid] = ip
        logging.debug("MAP %s -> %s" % (ip, uid))

def parse_config():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", help="load configuration from a file",
                        dest="config_file", metavar="config_file")
    parser.add_argument("-u", help="update configuration file if needed",
                        dest="update_config", action="store_true")
    parser.add_argument("-p", help="load remote ip configuration file",
                        dest="ip_config", metavar="ip_config")

    args = parser.parse_args()

    if args.config_file:
        # Load the config file
        with open(args.config_file) as f:
            loaded_config = json.load(f)
        CONFIG.update(loaded_config)

    need_save = setup_config(CONFIG)
    if need_save and args.config_file and args.update_config:
        with open(args.config_file, "w") as f:
            json.dump(CONFIG, f, indent=4, sort_keys=True)

    if not ("xmpp_username" in CONFIG and "xmpp_host" in CONFIG):
        raise ValueError("At least 'xmpp_username' and 'xmpp_host' must be "
                         "specified in config file")

    if "xmpp_password" not in CONFIG:
        prompt = "\nPassword for %s: " % CONFIG["xmpp_username"]
        CONFIG["xmpp_password"] = getpass.getpass(prompt)

    if "controller_logging" in CONFIG:
        level = getattr(logging, CONFIG["controller_logging"])
        logging.basicConfig(level=level)

    if args.ip_config:
        load_peer_ip_config(args.ip_config)

def main():

    parse_config()
    count = 0
    server = UdpServer(CONFIG["xmpp_username"], CONFIG["xmpp_password"],
                       CONFIG["xmpp_host"], CONFIG["ip4"], CONFIG["local_uid"])
    last_time = time.time()
    while True:
        server.serve()
        time_diff = time.time() - last_time
        if time_diff > CONFIG["wait_time"]:
            count += 1
            server.trim_connections()
            do_get_state(server.sock)
            last_time = time.time()

if __name__ == "__main__":
    main()


# THIS MODULE WILL HOLD LOGIC FOR WIFI EXECUTION


# UI IMPORTS
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
import pyfiglet


# NETWORK IMPORTS
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11ProbeReq, Dot11Elt


# ETC IMPORTS 
import time, threading


# NSM IMPORTS
from nsm_database import DataBase_WiFi, Utilities


console = Console()
LOCK = threading.Lock()




class WiFi_Snatcher():
    """This class will be responsible for grabbing surrounding layer 2 traffic <-- snatch"""



    @classmethod
    def _sniffer(cls, iface, timeout=5, verbose=False):
        """This will sniff frames out the air"""

        loops = 0

        
        while cls.sniff:

            try:

                loops += 1
                if verbose: console.print(f"[bold yellow]Loop: {loops}")

                sniff(iface=iface, timeout=timeout, store=0, prn=WiFi_Snatcher._parser); time.sleep(1)


            except KeyboardInterrupt as e: console.print(f"[bold yellow][-] Byeeeeee......."); cls.sniff = False


            except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}"); cls.sniff = False
        


        console.print(f"[bold red][-] SNIFFER Terminated! - Threads: {cls.thread_count}")
    


    @classmethod
    def _parser(cls, pkt):
        """This method will be resposible for parsing said packets that are recieved from _sniffer <-- pass argument"""
        

        def parser(pkt):
            

            c1 = "bold green"
            c2 = "bold blue"
            c3 = "bold yellow"

            go = False
            ssid = False

            # ADDR1 == DST
            # ADDR2 == SRC
            # ADDR3 == SRC



            if pkt.haslayer(Dot11Beacon):
                

                try:
                    addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                    addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False

                    ssid    = pkt[Dot11Elt].info.decode(errors="ignore") or "Hidden SSID"
                    vendor  = DataBase_WiFi.get_vendor_main(mac=addr2)
                    rssi    = DataBase_WiFi.get_rssi(pkt=pkt, format=False)
                    channel = DataBase_WiFi.get_channel(pkt=pkt)



                    if ssid:
                        t = [s for s in ssid]
                        if len(t) > 4: 
                            ssid = (f"{t[0]}{t[1]}{t[2]}{t[3]}")
                

                except Exception as e: console.print(f"[bold red][-] Parse Error:[bold yelow] {e}")
                

                try:
                    if ssid not in cls.ssids:
                        cls.master[ssid] = {
                            "rssi": rssi,
                            "mac": addr2,
                            "channel": channel,
                            "vendor": vendor,
                            "clients": []
                        }

                        cls.ssids.append(ssid)
                    
                except Exception as e: console.print(f"[bold red][-] Beacon Error: {e}"); cls.sniff = False



            elif pkt.haslayer(Dot11): 

                addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False

                try:
                    if pkt.haslayer(Dot11Elt): ssid = pkt[Dot11Elt].info.decode(errors="ignore") or "Hidden SSID" 
                except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}")
            

                if ssid:
                    t = [s for s in ssid]
                    if len(t) >= 4: 
                        ssid = (f"{t[0]}{t[1]}{t[2]}{t[3]}")
                
                    for key, _ in cls.master.items():

                        if key == ssid: go = True
                
                    if not go: return
                

                vendor  = DataBase_WiFi.get_vendor_main(mac=addr1 or addr2)
                channel = DataBase_WiFi.get_channel(pkt=pkt)
                
                
                with LOCK:
                    try:

                        if addr1 not in cls.macs and addr1 and ssid:
                                
                            data = (
                                addr2,
                                channel,
                                vendor,
                            )
                            
                            cls.master[ssid]["clients"].append(data)
                            cls.macs.append(addr1)
                        

                        
                        if addr2 not in cls.macs and addr2 and ssid:
                            
                            data = (
                                addr2,
                                channel,
                                vendor,
                            )
                            
                            cls.master[ssid]["clients"].append(data)
                            cls.macs.append(addr2)
                           
                        console.print(cls.master)
                    

                    except Exception as e: console.print(f"[bold red][-] GO Error: {e}"); cls.sniff = False


        threading.Thread(target=parser, args=(pkt,), daemon=True).start(); cls.thread_count += 1

                
    
    @classmethod
                
    def main(cls, iface):
        """This will run class wide logic"""


        # VARS
        cls.thread_count = 0
        cls.sniff = True
        cls.macs = []
        cls.ssids = []
        cls.master = {}
    
 
         
        if not iface: console.print(f"[bold red][-] Enter a iface goofy!")
        Utilities.channel_hopper(iface="wlan1", verbose=False)
        WiFi_Snatcher._sniffer(iface=iface)





"""



master = {

  sko_wifi = {
    "mac":
    "channel":
    "vendor":
    "nodes":
    "clients": {

      "mac"{
        "pkts":
        "vendor":
        ""
    }
    
    
    }
  }


  bari_wifi 





}


"""







if __name__ == "__main__":
    WiFi_Snatcher.main(iface="wlan1")







    """
    if pkt.haslayer(Dot11Beacon):
        console.print(f"[{c1}]Beacon: {addr1}")
        pass
    

    elif pkt.haslayer(Dot11ProbeReq):
        console.print(f"[{c2}]Probe: {addr1}")
    

    elif pkt.haslayer(Dot11AssoReq):
        console.print(f"[{c3}]Asso: {addr1}")
        pass
    """


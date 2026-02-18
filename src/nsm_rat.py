# THIS MODULE WILL HOLD LOGIC FOR WIFI EXECUTION


# UI IMPORTS
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
import pyfiglet


# NETWORK IMPORTS
from scapy.all import sniff, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11ProbeReq, Dot11Elt, Dot11Deauth


# ETC IMPORTS 
import time, threading
from concurrent.futures import ThreadPoolExecutor


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
            c4 = "bold red"

            go = False
            ssid = False

            # ADDR1 == DST
            # ADDR2 == SRC
            # ADDR3 == SRC
            
            if not cls.sniff: return


            if pkt.haslayer(Dot11Deauth) and cls.mode == 1:

                addr1 = pkt[Dot11].addr1 
                addr2 = pkt[Dot11].addr2 

                channel  = DataBase_WiFi.get_channel(pkt=pkt)

                console.print(f"[{c4}][*] Deauth Attack detected[/{c4}] - Dst: {addr1} Src: {addr2} - Channel: {channel}")


            elif pkt.haslayer(Dot11Beacon):


                try:
                    addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                    addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False

                    ssid        = pkt[Dot11Elt].info.decode(errors="ignore") or "Hidden SSID"
                    vendor      = DataBase_WiFi.get_vendor_main(mac=addr2)
                    rssi        = DataBase_WiFi.get_rssi(pkt=pkt, format=False)
                    channel     = DataBase_WiFi.get_channel(pkt=pkt)
                    encryption  = DataBase_WiFi.get_encryption(pkt=pkt)
                    frequency   = DataBase_WiFi.get_frequency(freq=pkt[RadioTap].ChannelFrequency)



                    if cls.hide:
                        t = [s for s in ssid]
                        if len(t) > 4: 
                            ssid = (f"{t[0]}{t[1]}{t[2]}{t[3]}")
                

                except Exception as e: console.print(f"[bold red][-] Parse Error:[bold yelow] {e}"); cls.sniff = False  
                

                try:
                    
                    if not any(stored_ssid == ssid for stored_ssid, _ in cls.ssids):
                        cls.master[ssid] = {
                            "rssi": rssi,
                            "mac": addr2,
                            "encryption": encryption,
                            "frequency": frequency,
                            "channel": channel,
                            "vendor": vendor,
                            "traffic": 0,
                            "clients": []
                        }

                        cls.ssids.append((ssid, addr2))
                        console.print(f"[bold green][+] SSID:[bold yellow] {ssid} --> {addr2}")
                    
                except Exception as e: console.print(f"[bold red][-] Beacon Error: {e}"); cls.sniff = False



            elif pkt.haslayer(Dot11) and pkt.type == 2 and cls.mode == 2: 


                addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False


                for id, id_mac in cls.ssids:
                    
                    if id_mac == addr2 or id_mac == addr1: go = True; ssid = id
                    #print(id, id_mac, go)

                    if go:
                        cls.master[id]["traffic"] +=1

            
                if not go: return
            

                vendor  = DataBase_WiFi.get_vendor_main(mac=addr1 or addr2)
                channel = DataBase_WiFi.get_channel(pkt=pkt)
                #console.print(vendor, channel)
                
          
                try:

                    if addr1 not in cls.macs and addr1 and ssid:
                        console.print("heyyy")
                            
                        data = (
                            addr1,
                            channel,
                            vendor,
                        )
                        
                        cls.master[ssid]["clients"].append(data)
                        cls.macs.append(addr1)


                        console.print(f"[bold green][+] addr1: {addr1} -> ")
                    

                    
                    if addr2 not in cls.macs and addr2 and ssid:
                        
                        data = (
                            addr2,
                            channel,
                            vendor,
                        )
                        
                        cls.master[ssid]["clients"].append(data)
                        cls.macs.append(addr2)


                        console.print(f"[bold green][+] addr2: {addr2} -> ")
                    
                        #console.print(cls.master)
                

                except Exception as e: console.print(f"[bold red][-] GO Error: {e}"); cls.sniff = False

 
        if not cls.sniff: return Exception 
        #print(pkt)
        cls.executor.submit(parser, pkt); cls.thread_count += 1
        #parser(pkt=pkt)

                
    
    @classmethod
                
    def main(cls, iface, mode):
        """This will run class wide logic"""


        # VARS
        cls.mode = mode
        cls.master = {}
        cls.hide = False
        cls.thread_count = 0
        cls.sniff = True
        cls.macs = []
        cls.ssids = []
        cls.executor = ThreadPoolExecutor(max_workers=80)
    

        Utilities.channel_hopper(iface=iface, verbose=False)
        WiFi_Snatcher._sniffer(iface=iface
        3258+)
        #threading.Thread(target=WiFi_Snatcher._sniffer, args=(iface, ), daemon=True).start()





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


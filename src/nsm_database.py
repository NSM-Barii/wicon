# THIS MODULE WILL BE RESPONSIBLE FOR SIDE TASK HELPING THE MAIN TASK


# UI IMPORTS
from rich.console import Console
from rich.live import Live


# NETWORK IMPORTS
from scapy.all import RadioTap
from scapy.layers.dot11 import Dot11Elt


# ETC IMPORTS
import subprocess, threading, time


# FILE IMPORTS
import manuf, json
from pathlib import Path


console = Console()
LOCK = threading.Lock()


class Utilities():

    hop = True

    @classmethod
    def channel_hopper(cls, iface, set_channel=False, verbose=False):
        """This method will be responsible for automatically hopping channels"""


        # NSM IMPORTS
        from nsm_files import Settings
        

        def hopper():

            delay = 0.25
            all_hops = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
            
            #iface = Settings.get_json()['iface']


            # TUNE HOP
            if set_channel:


                cls.hop = False; time.sleep(2)


                try:

                    subprocess.Popen(
                    ["sudo", "iw", "dev", iface, "set", "channel", str(set_channel)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True
                )

                except Exception as e:
                    console.print(f"[bold red]Exception Error:[bold yellow] {e}")
   

            # AUTO HOPPING
            while cls.hop:

                for channel in all_hops:


                    try:
                    

                        # HOP CHANNEL
                        subprocess.Popen(
                            ["sudo", "iw", "dev", iface, "set", "channel", str(channel)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL,
                            start_new_session=True
                        )
                        cls.channel = channel
                        if verbose:
                            console.print(f"[bold green]Hopping on Channel:[bold yellow] {channel}")

                        # DELAY
                        time.sleep(delay)
                    
                    except Exception as e:
                        console.print(f"[bold red]Exception Error:[bold yellow] {e}")



        threading.Thread(target=hopper, args=(), daemon=True).start()
        cls.hop = True





class DataBase_WiFi():
    """This will be responsible for pulling extra shit for parsing"""


    @classmethod
    def _get_vendor(cls, mac: str, verbose=True) -> str:
        """MAC --> Vendor | lookup"""
        
        try:

            manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_old.txt")

            vendor = manuf.MacParser(manuf_path).get_manuf_long(mac=mac)
            
            if verbose:
                console.print(f"Manuf.txt pulled -> {manuf_path}")            
                console.print(f"[bold green][+] Vendor Lookup:[/bold green] {vendor} -> {mac}")
            

            return vendor
                
        

        except FileNotFoundError:
            console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); return False
      

        except Exception as e:
            console.print(f"[bold red][-]Exception Error:[bold yellow] {e}"); return False
    

    @staticmethod
    def _get_vendor_new(mac: str, verbose=True) -> str:
        """MAC Prefixes --> Vendor"""
        

        try:

            manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_ring_mast4r.txt")

            mac_prefix = mac.split(':'); prefix = mac_prefix[0] + mac_prefix[1] + mac_prefix[2]


            with open(manuf_path, "r") as file:

                for line in file:
                    parts = line.strip().split('\t')
                    
                    if parts[0] == prefix:

                        vendor = parts[1]

                        if verbose: console.print(f"[bold green][+] {parts[0]} --> {vendor}" )
                        
                        return vendor


        except FileNotFoundError:
            console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
      

        except Exception as e:
            console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")
    

    @staticmethod
    def get_vendor_main(mac: str, verbose=False) -> str:
        """This will use ringmast4r and wireshark vendor database"""


        vendor = DataBase._get_vendor(mac=mac, verbose=verbose) or False; c = 1

        if not vendor: vendor = DataBase._get_vendor_new(mac=mac, verbose=verbose) or False; c = 2 

        return vendor


    @staticmethod
    def get_frequency(frequency):
        """Get the frequency being used by the wifi"""


        # 2.4GHZ OR 5GHZ
        if  frequency in range(2400000, 2500000):
            return "2.4 GHz"
        
        elif frequency in range(5000000, 5800000):
            return "5 GHz"
        
        elif frequency in range(5900000, 7200000):
            return "6 GHz"


        else:
            return frequency
    

    @staticmethod
    def _get_channel_from_radiotap(pkt):
        """This is when first attempt fails"""


        if pkt.haslayer(RadioTap):
            try:

                freq = pkt[RadioTap].ChannelFrequency
                if freq: return DataBase_WiFi._freq_to_channel(freq)
            
            except: pass
        
        return False


    @classmethod
    def get_channel(cls, pkt):
        """This will be used to get the ssid channel"""

        if not pkt.haslayer(Dot11Elt): return False
         
        elt = pkt[Dot11Elt]
        channel = 0


        while isinstance(elt, Dot11Elt):


            if elt.ID == 3:
                channel = elt.info[0]
                return channel
            
            elt = elt.payload


            channel = DataBase_WiFi._get_channel_from_radiotap(pkt=pkt)


        return channel

    
    @staticmethod
    def get_rssi(pkt, format=False):
        """This method will be responsible for pulling signal strength"""

        signal = ""; signal = f"[bold red]Signal:[/bold red] {signal}"  

        
        # CHECK FOR RADIO HEADER
        if pkt.haslayer(RadioTap):
            

            # PULL RSSI
            rssi = getattr(pkt, "dBm_AntSignal", False)
            
            # NOW RETURN
            if rssi:

                if format:
                    return f"{rssi} dBm"
                
                return rssi








class DataBase():
    """This will be a database for service uuids"""


    database = Path(__file__).parent.parent / "database" / "bluetooth_sig" / "assigned_numbers" / "company_identifiers"
    company_ids_path = database / "company_ids.json"



    @staticmethod
    def _importer(file_path: str, type="json", verbose=True) -> any:
        """This method will be responsble for returning all file paths"""

        
        if type == "json":
            with open(file_path, "r") as file:
                
                data = json.load(file)

                if verbose: console.print(f"[bold green][+] Successfully pulled: {file_path}")

                return data 
        

    @staticmethod
    def _services():
        """This will house the database for service uuids"""

        
        services = [
            {
                "name": "Tuya",
                "uuid": "fd50",
                "notes": "Used in cheap BLE smart locks, plugs, bulbs, and scales sold under dozens of brands.",
                "likelihood": "Very High"
            },
            {
                "name": "Xiaomi",
                "uuid": "fd21",
                "notes": "Used in BLE sensors and fitness trackers. Common in Mijia/Mi Band devices.",
                "likelihood": "High"
            },
            {
                "name": "Xiaomi (MiBeacon)",
                "uuid": "fe95",
                "notes": "BLE advertisement extension. Seen in multiple Xiaomi ecosystem devices.",
                "likelihood": "High"
            },
            {
                "name": "Fitbit",
                "uuid": "fd6f",
                "notes": "Used in fitness trackers for sync and telemetry.",
                "likelihood": "Medium"
            },
            {
                "name": "Tile",
                "uuid": "fe9f",
                "notes": "Custom protocol for encrypted BLE location beacons.",
                "likelihood": "Medium"
            },
            {
                "name": "Oura Ring",
                "uuid": "fd88",
                "notes": "Used for health data sync over BLE from biometric rings.",
                "likelihood": "Medium"
            },
            {
                "name": "Amazon Echo Buds",
                "uuid": "fdcf",
                "notes": "Custom telemetry + control services for earbuds.",
                "likelihood": "Low"
            },
            {
                "name": "Garmin",
                "uuid": "fd19",
                "notes": "Used in fitness watches and sensors with proprietary ANT+/BLE profiles.",
                "likelihood": "Medium"
            },
            {
                "name": "Apple (Find My)",
                "uuid": "fdc0",
                "notes": "Used in AirTags and Find My-enabled BLE devices.",
                "likelihood": "Low"
            },
            {
                "name": "Samsung",
                "uuid": "fee0",
                "notes": "Health device sync and BLE watch pairing.",
                "likelihood": "Medium"
            },
            {
                "name": "Nordic Semiconductor",
                "uuid": "fd3d",
                "notes": "Often shows up in DIY firmware. Some devices use it for OTA or control.",
                "likelihood": "High"
            },
            {
                "name": "Withings",
                "uuid": "fdc1",
                "notes": "Used in smart scales, BP monitors, and watches.",
                "likelihood": "Medium"
            },
            {
                "name": "Anker Soundcore",
                "uuid": "fd12",
                "notes": "Controls BLE headphone settings, EQ, and firmware.",
                "likelihood": "Medium"
            },
            {
                "name": "Google (Fast Pair)",
                "uuid": "fdaf",
                "notes": "Used in Android Fast Pair BLE handshake.",
                "likelihood": "Low"
            }
        ]
        

        return services


    @staticmethod
    def _etcs() -> str:
        """Hold data"""

        mappings = {
            "12020002": "Apple Watch (device class)",
            "12020003": "Apple Audio Accessory (e.g. AirPods)",
            "12020000": "Apple Setup Device (generic)",
            "10063b1d": "Apple Nearby/Continuity rotating ID"
        }

        return mappings 
   

    @classmethod
    def _get_service_uuids(cls, uuid: any) -> str:
        """this will take given services and parse them through known database"""


        pass
    

    @classmethod
    def _get_uuids_main(cls, CONSOLE: str, uuid:any, verbose=False) -> any:
        """Are uuids vulnerable and or mapable"""



        services = DataBase._services()


        if len(uuid) > 1:

            for service in services:
                for id in uuid:

                    if id == service: 

                        if verbose: CONSOLE.print(f"[bold green][+] Mapped service:[bold yellow] uuid <--> {service} ")

                        return service           

            return False
        

        else:
            
            for service in service:

                if uuid == service: 
                    if verbose: CONSOLE.print(f"[bold green][+] Mapped service:[bold yellow] uuid <--> {service} ")

                    return service        

            return False



    @classmethod
    def _get_etc(cls, data: any, verbose=False) -> str:
        """etc --> model"""

        mapping = DataBase._etcs()

        for key, value in mapping.items():

            if data == key:

                if verbose: console.print(f"[+] Found: {key} --> {value}")

                return value
            

    @classmethod
    def _get_manufacturers(cls, manufacturer_hex, verbose=True) -> str:
        """Manufacturer ID --> Manufacturer / Vendor"""

 
        if not manufacturer_hex: return "N/A"


        data = {}
        for key, value in manufacturer_hex.items():
            id = key; data = DataBase._get_etc(data=value.hex()) or value.hex()
            

        company_ids = DataBase._importer(file_path=cls.company_ids_path, verbose=False)


        for key, value in company_ids.items():

            if int(key) == int(id):

                manufacturer = value["company"]

                if verbose: console.print(f"[bold green][+] {id} --> {manufacturer}")
                
                if data: return f"{manufacturer} | {data}"
                return manufacturer
        
        return False



        pass


    @classmethod
    def _get_vendor(cls, mac: str, verbose=True) -> str:
        """MAC --> Vendor | lookup"""
        
        try:

            manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_old.txt")

            vendor = manuf.MacParser(manuf_path).get_manuf_long(mac=mac)
            
            if verbose:
                console.print(f"Manuf.txt pulled -> {manuf_path}")            
                console.print(f"[bold green][+] Vendor Lookup:[/bold green] {vendor} -> {mac}")
            

            return vendor
                
        

        except FileNotFoundError:
            console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
      
        
        except Exception as e:
            console.print(f"[bold red][-]Exception Error:[bold yellow] {e}"); exit()
    

    @staticmethod
    def _get_vendor_new(mac: str, verbose=True) -> str:
        """MAC Prefixes --> Vendor"""
        

        try:

            manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_ring_mast4r.txt")

            mac_prefix = mac.split(':'); prefix = mac_prefix[0] + mac_prefix[1] + mac_prefix[2]


            with open(manuf_path, "r") as file:

                for line in file:
                    parts = line.strip().split('\t')
                    
                    if parts[0] == prefix:

                        vendor = parts[1]

                        if verbose: console.print(f"[bold green][+] {parts[0]} --> {vendor}" )
                        
                        return vendor


        except FileNotFoundError:
            console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
      

        except Exception as e:
            console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")
    

    @staticmethod
    def _get_vendor_main(mac: str, verbose=False) -> str:
        """This will use ringmast4r and wireshark vendor database"""


        vendor = DataBase._get_vendor(mac=mac, verbose=verbose) or False; c = 1

        if not vendor: vendor = DataBase._get_vendor_new(mac=mac, verbose=verbose) or False; c = 2 

        return vendor
     
    

    @classmethod
    def push_results(cls, devices:any, verbose=True) -> None:
        """This will save ble wardriving results"""
        

        with LOCK:

            data  = {}
            num = 0
            macs = []
            
            if False:
                try:
                    NAME = "bluehound"
                    USER_HOME = Path(os.getenv("SUDO_USER") and f"/home/{os.getenv('SUDO_USER')}") or Path.home()
                    BASE_DIR = USER_HOME / "Documents" / "nsm_tools" / f"{NAME}" / "gui"

                except Exception as e:
                    BASE_DIR = Path.home() / "Documents" / "nsm_tools" / f"{NAME}" / "gui"
                
                BASE_DIR.mkdir(exist_ok=True, parents=True)

            path = Path(__file__).parent.parent / "database" 
            #console.print(path)

            try:

                drive = path / "database.json"
    
    
                if drive.exists():

                    with open(drive, "r") as file: data = json.load(file)

                    for _, value in data.items(): macs.append(value["addr"]); num+=1

                for _, device in devices.items(): 

                    if device["addr"] not in macs:

                        num += 1; macs.append(device["addr"]); data[num] = device
            

                with open(drive, "w") as file: json.dump(data, file, indent=4)
                if verbose: console.print("[bold green][+] Wardrive pushed!")
                #console.print(data)
            
            except json.JSONDecodeError as e:
                console.print(f"[bold red][!] JSON Error:[bold yellow] {e}")
                with open(drive, "w") as file: json.dump(data, file, indent=4)
                console.print("[bold green][+] json file created!")

                          
            except Exception as e:
                console.print(f"[bold red][!] Exception Error:[bold yellow] {e}")


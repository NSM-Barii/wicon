# THIS WILL START MODULE WIDE LOGIC


# ETC IMPORTS
import threading, argparse


# NSM IMPORTS
from nsm_rat import WiFi_Snatcher
from nsm_server import Web_Server







class Main_Thread():
    """Module starts here"""



    @staticmethod
    def main(iface="wlan1"):
        """Start"""


        # CHOOSE THE ARGUMENT
        parser = argparse.ArgumentParser()
        parser.add_argument("-d", help="This is to filter and look for deauth attacks")
        parser.add_argument("-s", action="store_true", help="This will set no filter and will instead passively sniff and process all Dot11 Traffic")
        parser.add_argument("-i", help="This will be what the user will call upon to pass a interface (Thats in monitor mode)")


        args = parser.parse_args()

        scan   = args.s or False
        iface  = args.i or False
        deauth = args.d or False

        
        if scan:

            if not iface: print("[-] Pass a valid iface using -i  silly goose"); exit()

            # START WiFi SNIFFING
            print(f"[+] Iface: {iface}")
            threading.Thread(target=WiFi_Snatcher.main, args=(iface, ), daemon=True).start()


            # START SERVER
            from nsm_server import Web_Server
            Web_Server.start()
        

        elif deauth: WiFi_Snatcher.main(iface=iface, )





if __name__ == "__main__":
    Main_Thread.main()
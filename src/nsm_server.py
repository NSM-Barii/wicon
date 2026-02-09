# THIS MODULE WILL HOST WEB SERVER


# IMPORTS
from http.server import SimpleHTTPRequestHandler, HTTPServer



# ETC IMPORTS
from rich.console import Console
from pathlib import Path
import os, json


CONSOLE = Console()




class HTTP_Handler(SimpleHTTPRequestHandler):
    """This class will handle/server http traffic"""

    def __init__(self, *args, **kwargs):
        # Set the directory to serve files from
        gui_path = str(Path(__file__).parent.parent / "gui")
        super().__init__(*args, directory=gui_path, **kwargs)


    def log_message(self, fmt, *args):
        """Silence HTTP server logs"""
        pass

    def do_GET(self) -> None:
        """This will handle basic web server requests"""

        import nsm_rat

        try:
            if self.path == "/api/devices":

                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", '*')
                self.end_headers()

                data = nsm_rat.WiFi_Snatcher.master
                self.wfile.write(json.dumps(data).encode())

            else:
                # Serve static files from gui directory
                super().do_GET()
        
        except Exception as e: CONSOLE.print(f"[bold red][-] Exception Error:[bold yellow] {e}")





class Web_Server():
    """This will launch the web server"""



    @staticmethod
    def start(address="0.0.0.0", port=8000):
        """This will start the web server"""

        server = HTTPServer(server_address=(address, port), RequestHandlerClass=HTTP_Handler)
        CONSOLE.print(f"[bold green][+] Successfully Launched web server")
        CONSOLE.print(f"[bold green][+] Starting Web_Server on:[bold yellow] http://localhost:{port}")
        server.serve_forever(poll_interval=2)



"""


 I am getting this error below in the system log of the website and its also not loading any of the info 


 [00:00:00] System initialized successfully
[23:53:15] Application initialized successfully
[23:53:15] Failed to load devices: devices.forEach is not a function
[23:53:20] Failed to load devices: devices.forEach is not a function
[23:53:25] Failed to load devices: devices.forEach is not a function 

"""
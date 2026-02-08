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

        from nsm_rat import WiFi_Snatcher


        if self.path == "/api/devices":

            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", '*')
            self.end_headers()

            self.wfile.write(json.dumps(WiFi_Snatcher.master).encode())

        else:
            # Serve static files from gui directory
            super().do_GET()






class Web_Server():
    """This will launch the web server"""



    @staticmethod
    def start(address, port):
        """This will start the web server"""

        server = HTTPServer(server_address=(address, port), RequestHandlerClass=HTTP_Handler)
        CONSOLE.print(f"[bold green][+] Successfully Launched web server")
        CONSOLE.print(f"[bold green][+] Starting Web_Server on:[bold yellow] http://localhost:{port}")
        server.serve_forever(poll_interval=2)
# THIS WILL HOLD DATA MANIPULATION CODE OUTSIDE OF SAID /database, instead /.data/ <--


# UI IMPORTS
from rich.console import Console


# ETC IMPORTS
from datetime import datetime
from pathlib import Path
import json



console = Console()      # src/wicon/nsm_tools
BASE_DIR = Path(__file__).parent.parent.parent / ".data" / "wicon"


class Settings():
    """This method will be responsible for controlling json info"""


    def __init__(self):
        pass


    
    @classmethod
    def get_json(cls, verbose=False):
        """This will pull and return json info"""


        while True:
            try:

                if BASE_DIR.exists():

                    path = BASE_DIR / "settings.json"

                    with open(path, "r") as file:

                        settings = json.load(file)

                        if verbose: console.print(f"Successfully Pulled settings.json from {path}", style="bold green")

                    return settings
                
                else: BASE_DIR.mkdir(exist_ok=True, parents=True)


            except FileNotFoundError as e:

                if verbose: console.print(f"[bold red]FileNotFound Error:[yellow] {e}")
                Settings.create_json()

            except Exception as e: console.print(f"[bold red]Exception Error:[yellow] {e}"); break


    @classmethod
    def push_json(cls, data):
        """This method will be used to push info to settings.json"""

        verbsoe = True
        time_stamp = datetime.now().strftime("%m/%d/%Y - %I:%M:%S")


        while True:
            try:

                if BASE_DIR.exists():
                    
                    path = BASE_DIR / "settings.json"

                    with open(path, "w") as file:

                        json.dump(data, file, indent=4)
                        if verbsoe: console.print("Successfully pushed settings.json", style="bold green")
                    
                    return


                else:

                    BASE_DIR.mkdir(exist_ok=True, parents=True)
                    if verbsoe: console.print(f"Successfully created dir", style="bold green")
                
            


            except FileNotFoundError as e:

                if verbsoe: console.print(f"[bold red]FileNotFound Error:[yellow] {e}")
                Settings.create_json()

                
            except Exception as e: console.print(f"[bold red]Exception Error:[yellow] {e}"); break
    

    @classmethod
    def create_json(cls):
        """This is a sub method to be called upon when the json file is missing"""

 
        path = BASE_DIR / "settings.json"
        data = {
                "iface": "",
                "captures": ""
            }


        with open(path, "w") as file: json.dump(data, file, indent=4)
        console.print("Successfully created json file", style="bold green")

    
   
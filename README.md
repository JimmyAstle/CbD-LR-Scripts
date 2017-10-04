#Cb Defense Live Response Automation scripts
Collection of POC scripts that can be used with Cb Defense Live Response capabilities.   

Shout out to Jrotenberger for his collection of CbR scripts here: https://github.com/Jrotenberger/CBIRAutomation

**NOTE**
- This script was tested on a Linux machine. Path structure would need to be modified to run on Windows
- You'll need to fill in your API endpoint URL and token in the top of each script
- You'll need to have the Cb Python API bindings installed. Link here: https://cbapi.readthedocs.io/en/latest/installation.html

#Details
- psrecon - When executed this will copy down a slightly modified version of PSRecon(https://github.com/gfoss/PSRecon) to `C:\recon`, execute PSRecon, pull back the results, and recursively delete the `C:\recon` folder

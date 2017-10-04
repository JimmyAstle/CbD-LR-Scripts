#!/usr/bin/python

from cbapi.defense import *
import os
import time
import argparse
import sys


cb_url = ""
cb_token = ""
cb_ssl = "True"
recon_path = "C:\\recon"

def execute_recon(cb, host=None):
    #Select the device you want to gather recon data from
    query_hostname = "hostNameExact:%s" % host
    print ("[DEBUG] Executing remote forensics on Hostname: " + host)

    #Create a new device object to launch LR on
    device = cb.select(Device).where(query_hostname).first()

    #Execute our LR session
    with device.lr_session() as lr_session:
        print ("[DEBUG] Create remote recon directory on: " + host)
        lr_session.create_directory(recon_path)

        print ("[DEBUG] Putting PsRecon on the remote host")
        lr_session.put_file(open("psrecon.ps1", "rb"), recon_path + "\\psrecon.ps1")

        print ("[DEBUG] Setting PowerShell execution policy to unrestricted")
        lr_session.create_process("powershell.exe SET-EXECUTIONPOLICY UNRESTRICTED")

        print ("[DEBUG] Executing PsRecon on host: " + host)
        lr_session.create_process("powershell.exe -nologo -file %s\\psrecon.ps1" % recon_path)

        p = recon_path

        p = os.path.normpath(p)

        try:
            path = lr_session.walk(p, False)  # False because bottom->up walk, not top->down
            for items in path:  # For each subdirectory in the path
                directory = os.path.normpath((str(items[0])))  # The subdirectory in OS path syntax
                subpathslist = items[1]  # List of all subpaths in the subdirectory
                fileslist = items[2]  # List of files in the subdirectory
                if str(fileslist) != "[]":  # If the subdirectory is not empty
                    for afile in fileslist:  # For each file in the subdirectory
                        if not(afile.endswith(".ps1")):
                            fpath = os.path.normpath(directory + "\\" + afile)  # The path + filename in OS path syntax
                            print ("[DEBUG] Reading File: " + fpath)
                            dmp = lr_session.get_file(fpath)
                            time.sleep(2.5)  # Ensures script and server are synced
                            save_path1 = "{0}".format(directory)
                            save_path1 = (save_path1.replace(p, ""))
                            if save_path1.startswith('\\'):
                                save_path1 = save_path1[1:]
                            save_path1 = save_path1.replace("\\", "/")
                            save_path1 = os.path.normpath(save_path1)
                            if not os.path.exists(save_path1):
                                os.makedirs(save_path1)
                                os.chmod(save_path1, 0o777)  # read and write by everyone
                            save_path1 = save_path1 + "/" + afile
                            print ("[DEBUG] Writing file to path " + save_path1)
                            open(save_path1, "wb").write(dmp)
                print ("[DEBUG] Reading Path: " + directory)

        except Exception as err:  # Could occur if main path did not exist, session issue, or unusual permission issue
            print("[ERROR] Encountered: " + str(err) + "\n[FAILURE] Fatal error caused abort!")  # Report error, and continue

        print ("[DEBUG] Setting PowerShell execution policy back to restricted")
        lr_session.create_process("powershell.exe SET-EXECUTIONPOLICY RESTRICTED")

        #Lets clean up the recon scripts on the endpoint now that we collected all the data
        path = lr_session.walk(p,False)
        for items in path:  # For each subdirectory in the path
            directory = os.path.normpath((str(items[0])))  # The subdirectory in OS path syntax
            fileslist = items[2]  # List of files in the subdirectory
            if str(fileslist) != "[]":  # If the subdirectory is not empty
                for afile in fileslist:  # For each file in the subdirectory
                    fpath = os.path.normpath(directory + "\\" + afile)  # The path + filename in OS path syntax
                    print ("[DEBUG] Deleting File: " + fpath)
                    lr_session.delete_file(fpath)  # Delete the file
            print ("[DEBUG] Deleting Path: " + directory)
            lr_session.delete_file(directory)  # Delete the empty directory

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--machinename", help="machinename to run host forensics recon on")
    args = parser.parse_args()

    #Create the CbD LR API object
    cb = CbDefenseAPI(url=cb_url, token=cb_token, ssl_verify=cb_ssl)

    if args.machinename:
        execute_recon(cb, host=args.machinename)
    else:
        print ("[ERROR] You must specify a machinename with a --machinename parameter. IE ./run_recon.py --machinename cheese")

if __name__ == '__main__':
    sys.exit(main())

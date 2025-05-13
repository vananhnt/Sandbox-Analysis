
import configparser
import argparse
import requests
import time
import pprint
import json
import os
import hashlib
import shutil
from pathlib import Path

CAPEAPI = ''
SAMPLE_DIR = '/home/cape/data/samples'
CAPE_REPORTS = ''   # path to CAPE report
REPORTS = ''        # path to analysis report 
HISTORY_FILE = ''
CAPE_STORE = ''

def get_md5(full_path):
	""" Calculate MD5 hash """
	md5 = hashlib.md5()
	with open(full_path, 'rb') as file:
		line = file.read()
		md5.update(line)

	md5_hash = md5.hexdigest()
	return md5_hash

def get_machine_list(CAPEAPI):
    REST_URL = CAPEAPI + "/machines/list"
    PARAMS = {}
    r = requests.post(REST_URL, params=PARAMS)
    if r.status_code != 200:
        print("[ERROR] Error getting machine list")
        return
    r.json()["machines"]

def send_file(CAPEAPI, full_path, machine_id=None):
    """ Send suspicious file CAPE API """
    """ 1. Send suspicious file via API REST """
    print("[INFO] Sending file {}".format(full_path))
    REST_URL = CAPEAPI + "/tasks/create/file/"
    PARAMS = { }
    if machine_id is not None:
        PARAMS = {'machine': machine_id, 'options':'no-stealth=1 force-sleepskip=1'}
    
    with open(full_path, "rb") as sample:
        files = {"file": (full_path, sample)}
        r = requests.post(REST_URL, params=PARAMS, files=files)
    print("[INFO] File {} has been sent".format(full_path))

    if r.status_code != 200:
        print("[ERROR] Error sending sample {}", full_path)
        return

    if "data" in r.json():
        task_id = r.json()["data"]["task_ids"][0]
    else:
        task_id = None
    if task_id == None:
        print("[ERROR] Task ID is null")
        if 'errors' in r.json():
            print("[ERROR] " + str(r.json()["errors"][0]))
        return  

    """ 2. Check suspicious file """
    print("[INFO] Checking task no. {} ({})".format(task_id, full_path))
    REST_URL = CAPEAPI + "/tasks/status/" + str(task_id)
    r = requests.get(REST_URL, params=PARAMS)
    if r.status_code != 200 or r.json()["error"] == "True":
        print("[ERROR] Task not found")
        return
	
    """ Check suspicious file until report finished """
    pending = 0
    not_exec = False
    status = r.json()["data"]
    while status != "reported" and not_exec == False:
        r = requests.get(REST_URL, params=PARAMS)
        if r.status_code != 200:
            print("[ERROR] Task not found")
            return

        if status == "pending" or \
            status == "failed_processing" or \
            status == "failed_analysis":
            pending += 1
            if pending >= 10:
                not_exec = True

        status = r.json()["data"]
        print("[INFO] Waiting analysis for task no. {}. Status: {}".format(task_id, 
                                                                        status))
        time.sleep(10)


    if not_exec == True:
        print("[ERROR] File {} could not be executed".format(full_path))
        """ Return -1 as task_id value in order to analyze next file """
        return -1

    print("[INFO] Task no. {} has been reported!".format(task_id))
    return task_id

def read_configuration(config_file, log_level):
    """ Read configuration file """
    config = configparser.ConfigParser()
    config.read(config_file)
    if 'reports' in config:
        report_path = config['reports']['path']
    else:
        if log_level > 0:
            print("[ERROR] Reports section has not been configured")

    if 'binaries' in config:
        bingood_path = config['binaries']['good']
        binbad_path = config['binaries']['bad']
        samples_path = config['binaries']['sample']
    else:
        if log_level > 0:
            print("[ERROR] Binaries section has not been configured")

    if 'cape' in config:
        api_uri = config['cape']['api']
        storage_path = config['cape']['storage']
    else:
        if log_level > 0:
            print("[ERROR] Cape section has not been configured")

    if 'history' in config:
        log_path = config['history']['log']
        latest_path = config['history']['latest']

    return {'reports_path': report_path, 
            'samples_path': samples_path, 
            'api_uri': api_uri, 
            'storage_path': storage_path, 
            'history_path': log_path,
            'latest_path': latest_path }

def push_a_sample(file, reports, f_good, capeapi, cape_storage):
            """ Return task id if successful """ 
            full_path = str(file.resolve())
           
            task_id = send_file(capeapi, full_path)
            if task_id is None: return
            if task_id > 0:
                    """ Retrieve reports based on task_id """
                    md5_hash = get_md5(full_path)

                    """ Copy report json file """
                    src_file = cape_storage + str(task_id) + "/reports/report.json"
                    if os.path.isfile(src_file):
                        dst_file = reports + "report-" + md5_hash + "-0.json"
                        shutil.copy(src_file, dst_file)

                        """ Copy sysmon xml file """
                        src_file = cape_storage + str(task_id) + "/sysmon/sysmon.xml"
                        if os.path.isfile(src_file):
                            dst_file = reports + "sysmon-" + md5_hash + "-0.xml"
                            shutil.copy(src_file, dst_file)

                            print("[+] Reports has been copied to {}".format(reports))
                            f_good.write("{} - Executed\n".format(full_path))
                
                            good += 1
                            if good % 10 == 0:
                                print("[+] We have analyzed {} good samples.".format(good))
                                print("[+] Last sample was {}".format(full_path))
                        else:
                            f_good.write("{} - Failed sysmon.xml\n".format(full_path))
                    else:
                        f_good.write("{} - Failed report.json\n".format(full_path))
                    return task_id
            else:
                    f_good.write("{} - Failed in send_file() func.\n".format(full_path))
                    return 
        
def push_samples(sample_dir, reports=REPORTS, history_file=HISTORY_FILE, capeapi=CAPEAPI, cape_storage=CAPE_STORE):
    """ Return analysed task ID"""
    print("[INFO] Send samples")
    good = 0
    f_good = open(history_file, 'a')

    tasks = []

    Path(reports).mkdir(exist_ok=True)

    path = Path(sample_dir)
    if os.path.isfile(path):
        id = push_a_sample(path, reports, f_good, capeapi, cape_storage)
        tasks.append(id)
    else:
        tasks = []
        for file in path.rglob("*"):
            if os.path.isfile(file):
                id = push_a_sample(file, reports, f_good, capeapi, cape_storage)
                tasks.append(id)

    f_good.flush()
    f_good.close()
    return tasks


def main():
    """ Read configuration file """
    parser = argparse.ArgumentParser(description="This script performs requests to CAPE API")
    parser.add_argument('--verbose', '-v', dest='log_level', 
                        type=int, default=0)
    parser.add_argument('--conf', '-c', dest='conf_file', 
                        type=argparse.FileType('r'),
                        help='Path to configuration file')
    parser.add_argument('--path', '-f', dest='sample_path',
                        type=str, default=None,
                        help='Specify path to sample')
    parser.add_argument('--report-suffix', '-sf', dest='report_suffix', 
                        type=str, default='', 
                        help="Specify the suffix of report folder: cape-reports-sf")
    
    args = parser.parse_args()
    if args.log_level > 0:
        print("[DEBUG] Configuration file: {}".format(args.conf_file.name))

    conf_vars = read_configuration(args.conf_file.name, args.log_level)
	
    CAPEAPI = conf_vars['api_uri']
    CAPE_STORE = conf_vars['storage_path']
    REPORTS = conf_vars['reports_path'].rstrip('/') + '-' + args.report_suffix + '/' if args.report_suffix else conf_vars['reports_path']
    HISTORY_FILE = conf_vars['history_path']
    LASTEST_FILE = conf_vars['latest_path']
    SAMPLE_DIR = args.sample_path if args.sample_path is not None else conf_vars['samples_path']
    
    reported_tasks = push_samples(SAMPLE_DIR, REPORTS, HISTORY_FILE, CAPEAPI, CAPE_STORE)
    print("[INFO] Reported in {}".format(REPORTS))

    open(LASTEST_FILE, "w").write("\n".join(map(str,reported_tasks)) + "\n")
    print("[INFO] Analysed task IDs saved in {}".format(LASTEST_FILE))
			
if __name__  == "__main__":
	main()
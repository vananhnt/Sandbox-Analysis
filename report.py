import argparse
import os
import pandas as pd
import time
from pathlib import Path
import time

from utils.preprocessor import Preprocessor
from utils.analysis import Analysis

def save_dynamic_to_csv(log_level, dataset, results_path):
    if log_level > 0:
        print("[DEBUG] We are going to print all dataset")
        print(dataset)
        print("-"*78)

    """ Dataset info """
    dataset.info()

    """ Dump all dataset to csv in order to perform data analysis for 
    future project """
    dataset.to_csv(results_path + 'dynamic-test.csv')

def normalize_report(reports):
    """ Build your Panda DataFrame structure 
        with metadata , dynamic features, static features """
    normalize_dict = []
    for binary in reports:
        binary_dict =  { 'binary': binary[0]['md5'], 
                'classification': binary[0]['classification'],
                'registry_usage': binary[1]['registry_usage'],
                # Dyn features
                'n_read_keys': binary[1]['n_read_keys'],
                'n_write_keys': binary[1]['n_write_keys'],
                'n_delete_keys': binary[1]['n_delete_keys'],
                'instruction_traces': binary[1]['instruction_traces'],
                'instruction_traces_data': binary[1]['instruction_traces_data'],
                'n_inst': binary[1]['n_inst'],
                'read_inst': binary[1]['read_inst'],
                'write_inst': binary[1]['write_inst'],
                'delete_inst': binary[1]['delete_inst'],
                'load_inst': binary[1]['load_inst'],
                'create_inst': binary[1]['create_inst'],
                'execute_inst': binary[1]['execute_inst'],
                'move_inst': binary[1]['move_inst'],
                'copy_inst': binary[1]['copy_inst'],
                'findwindow_inst': binary[1]['findwindow_inst'],
                'start_inst': binary[1]['start_inst'],
                'modify_inst': binary[1]['modify_inst'],
                'browser_inst': binary[1]['browser_inst'],
                'api_call_traces': binary[1]['api_call_traces'],
                'n_api_calls': binary[1]['n_api_calls'],
                'windows_api_calls': binary[1]['windows_api_calls'],
                'services_api_calls': binary[1]['services_api_calls'],
                'system_api_calls': binary[1]['system_api_calls'],
                'synchronization_api_calls': binary[1]['synchronization_api_calls'],
                'registry_api_calls': binary[1]['registry_api_calls'],
                'threading_api_calls': binary[1]['threading_api_calls'],
                'process_api_calls': binary[1]['process_api_calls'],
                'network_api_calls': binary[1]['network_api_calls'],
                'misc_api_calls': binary[1]['misc_api_calls'],
                'hooking_api_calls': binary[1]['hooking_api_calls'],
                'filesystem_api_calls': binary[1]['filesystem_api_calls'],
                'device_api_calls': binary[1]['device_api_calls'],
                'crypto_api_calls': binary[1]['crypto_api_calls'],
                'com_api_calls': binary[1]['com_api_calls'],
                'browser_api_calls': binary[1]['browser_api_calls'],
                'network_traffic': binary[1]['network_traffic'],
                # Static features
                'signatures': binary[2]['signatures'] 
                }
        normalize_dict.append(binary_dict)

    dataset = pd.DataFrame.from_dict(normalize_dict)
    return dataset

def save_static_to_csv(log_level, dataset, results_path):
    if log_level > 0:
        print("[DEBUG] We are going to print all dataset")
        print(dataset)
        print("-"*78)

    """ Dataset info """
    dataset.info()

    """ Dump all dataset to csv in order to perform data analysis for 
    future project """
    dataset.to_csv(results_path + 'static-test.csv')

def main():
    parser = argparse.ArgumentParser(description='Project description.')
    parser.add_argument('--verbose', '-v', dest="log_level", 
                        type=int, default=0,)
    parser.add_argument('--conf', '-c', dest='conf_file', 
                        type=argparse.FileType('r'), 
                        help="Path to configuration file")
    args = parser.parse_args()
    if args.log_level > 0:
        print("[DEBUG] Configuration file: {}".format(args.conf_file.name))

    print("[INFO] Starting to process reports...")
    conf_file = args.conf_file.name
    log_level = args.log_level
    timestr = time.strftime("%Y%m%d-%H%M%S")

    preprocessor = Preprocessor(conf_file, log_level)
    conf_vars = preprocessor.get_configuration()

    """ Get configuration vars from configuration file """
    reports_path = conf_vars['reports_path']
    results_path = conf_vars['results_path']
    results_folder = results_path + timestr + '/'
    Path(results_folder).mkdir(parents=True, exist_ok=True)
   
    """ Starting time """
    start = time.time()

    """ Iterate over all reports """
    iterator = os.scandir(reports_path)
    reports = []
    
    for item in iterator:
        if os.path.isfile(item.path):
            metadata, dyn_features, sta_features = preprocessor.get_json_report(reports_path + item.name)
           
            """ We store as tuple <metadata, dyn_features,sta_features> """
            binary = tuple((metadata, dyn_features,sta_features))
            reports.append(binary)

    dataset = normalize_report(reports)
    save_dynamic_to_csv(log_level, dataset, results_folder)

    """ Data analysis """
    data_analysis = Analysis(log_level, dataset, results_folder)
    data_analysis.signature_category_count('signatures')
    save_static_to_csv(log_level, dataset, results_folder)
    
    end = time.time()
    print("[INFO] Elapsed time for normalizing and splitting dataset:"  
                                    + " {} seconds".format(end - start))

if __name__ == '__main__':
    main()

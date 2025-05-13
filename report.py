import argparse
import os
import pandas as pd
import time
from pathlib import Path
import time
import shutil

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

def normalize_summary_report(reports):
    """ Build your Panda DataFrame structure 
        with metadata , dynamic features, static features """
    normalize_dict = []
    for binary in reports:
        #binary[0] = metadata, binary[1]=dynamic_features, binary[2]=static_features
        binary_dict =  { 'binary': binary[0]['md5'], 
                        'name': binary[0]['name'],
                        'analysis_id':binary[0]['id'],
                'classification': binary[0]['classification'],
                'timestamp': binary[0]['timestamp'],
                # Dyn features
                'registry_usage': binary[1]['registry_usage'],
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

def normalize_api_report(reports):
    normalize_dict = []
    for binary in reports:
        #binary[0] = metadata, binary[1]=api_sequences
        binary_dict =  { 'binary': binary[0]['md5'], 
                        'name': binary[0]['name'],
                        'analysis_id':binary[0]['id'],
                'classification': binary[0]['classification'],
                'timestamp': binary[0]['timestamp'],
                # API details
                'api_ids': binary[1]['call_ids'],
                'api_names': binary[1]['call_apis'],
                'call_timestamps': binary[1]['call_timestamps'],
                'process_ids': binary[1]['process_ids'],
                'process_names': binary[1]['process_names'],
                'call_categories': binary[1]['call_categories'],
                'call_statuses': binary[1]['call_statuses'],
                'call_returns': binary[1]['call_returns'],
                'call_pretty_returns': binary[1]['call_pretty_returns'],
                'call_argument_list': binary[1]['call_argument_list'],
                'call_repeats': binary[1]['call_repeats']
        }

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

def get_all_report_from_storage(cape_storage, report_dest):
    """ Retrieve all report.json from storage if not in report_dest yet"""
    for id in Path(cape_storage).glob("*"):
        full_path = str(id.resolve())
        task_id = int(id.stem) if id.stem != 'latest' else -1
        if task_id > 0: 
                    """ Retrieve reports based on task_id """
                    """ Copy report json file """
                    src_file = cape_storage + str(task_id) + "/reports/report.json"
                    if os.path.isfile(src_file):
                        dst_file = report_dest + "report-" + str(task_id) + ".json"
                        shutil.copy(src_file, dst_file)

def main():
    parser = argparse.ArgumentParser(description='Project description.')
    parser.add_argument('--verbose', '-v', dest="log_level", 
                        type=int, default=0,)
    parser.add_argument('--conf', '-c', dest='conf_file', 
                        type=argparse.FileType('r'), 
                        help="Path to configuration file")
    parser.add_argument('--report-suffix', '-sf', dest='report_suffix', 
                        type=str, default='', 
                        help="Specify the suffix of report folder: cape-reports-sf")
    
    args = parser.parse_args()
    if args.log_level > 0:
        print("[DEBUG] Configuration file: {}".format(args.conf_file.name))

    print("[INFO] Starting to process reports...")
    conf_file = args.conf_file.name
    log_level = args.log_level
    timestr = time.strftime("%Y%m%d-%H%M%S")

    preprocessor = Preprocessor(conf_file, log_level)
    conf_vars = preprocessor.get_configuration()

    """ Get configuration vars from configuration file & args"""
    reports_path = conf_vars['reports_path'].rstrip('/') + '-' + args.report_suffix + '/' if args.report_suffix else conf_vars['reports_path']
    cape_storage = conf_vars['cape_storage'] #Path to storage of CAPE
    
    """ Set the folder to save analysis result """
    root_results_path = conf_vars['results_path'] 
    results_folder = root_results_path + timestr + '/'
    Path(results_folder).mkdir(parents=True, exist_ok=True)

    """ Starting time """
    start = time.time()

    """ Iterate over all CAPE reports """
    iterator = os.scandir(reports_path)
    sum_reports = []
    prompt_reports = []

    for item in iterator:
        if os.path.isfile(item.path):
            metadata, dyn_features, sta_features = preprocessor.get_json_report(reports_path + item.name)
            metadata, prompts = preprocessor.get_prompts(reports_path + item.name)      
            """ We store as tuple <metadata, dyn_features,sta_features> """
            sum_reports.append(tuple((metadata, dyn_features,sta_features)))
            prompt_reports.append(tuple((metadata, prompts)))

    """ Convert reports to dataframe """
    dataset = normalize_summary_report(sum_reports)
    
    """ Data analysis """
    data_analysis = Analysis(log_level, dataset, results_folder, cape_storage)
    
    if not dataset.empty:
        signature_df = data_analysis.signature_category_count()
        result_file_df = data_analysis.check_result_output()
        
        report_df = data_analysis.get_merged_report(signature_df, result_file_df)
        report_df.to_csv(results_folder + "extracted_result" + '_raw.csv', index=True)

    else: 
        print("[INFO] No CAPE report found from {}".format(reports_path))

    end = time.time()
    print("[INFO] Elapsed time for normalizing and analysing dataset:"  
                                    + " {} seconds".format(end - start))

if __name__ == '__main__':
    main()
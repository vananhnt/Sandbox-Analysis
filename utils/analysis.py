import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import json
import pandas as pd
import ast
from utils.hook_modify import CapemonHook

### Malscore in CAPE is defined as
#0 = No malicious behavior detected
#1–3 = Suspicious or weakly malicious
#4–10+ = Clear malicious behavior
#>10 = Highly malicious (e.g., ransomware, rootkits
###

class Analysis:
    """ Performs data analysis """

    """ TODO: printing some message by log_level var """
    def __init__(self, log_level, summary_dataset, results_path, storage_path):
        self.log_level = log_level
        self.dataset = summary_dataset
        self.api_dataset = None
        self.network_dataset = None
        self.results_path = results_path
        self.storage_path = storage_path

    def set_api_data(self, api_data):
        self.api_dataset = api_data

    def column_categorical_to_numerical(self, column):
        """ We use this function in order to conver categorical values to 
        numerical. For instance, epilogue and prologue that are hashes """
        print("[INFO] We are going to extract uniques values" +
                                            " from {}".format(column))
        unique_values = self.dataset[column].unique()
        
        print("[INFO] There are {} (of {})".format(len(unique_values), 
                                                len(self.dataset[column]))\
                    + " unique values from {}".format(column))
        print(unique_values)

        mapping_numerical = {}
        for i in range(len(unique_values)):
            mapping_numerical[unique_values[i]] = i

        if self.log_level > 0:
            print("[DEBUG] Mapping for {}".format(column))
            print(mapping_numerical)
        
        self.dataset[column + '_num'] =\
                        self.dataset[column].map(mapping_numerical).astype(int)
        if self.log_level > 0:
            print("[DEBUG] Printing numerical column {}".format(column + '_num'))
            print(self.dataset[['binary', column, column + '_num']])

        return column + '_num'

    def column_categorical_to_numerical_array(self, column):
        """ We use this function in order to convert categorical array values
        to numerical ones. """
        print("[INFO] We are going to extract uniques values" +
                                            " from {}".format(column))
        unique_values_array = self.dataset[column].explode().unique()

        print("[INFO] There are {} (of {})".format(len(unique_values_array), 
                                    len(self.dataset[column].explode()))\
                    + " unique values from {}".format(column))

        mapping_numerical = {}
        for i in range(len(unique_values_array)):
            mapping_numerical[unique_values_array[i]] = i

        if self.log_level > 0:
            print("[DEBUG] Mapping for {}".format(column))
            print(mapping_numerical)
        
        binary_list_mapping = []
        for column_name, row in self.dataset[[column]].iteritems():
            for item in row:
                list_mapping = [mapping_numerical[i] for i in item]
                binary_list_mapping.append(list_mapping)
        
        self.dataset[[column + '_num']] = binary_list_mapping

        if self.log_level > 0:
            print("[DEBUG] Printing numerical column {}".format(column + '_num'))
            print(self.dataset[['binary', column, column + '_num']])

        return column + '_num'

    def registry_usage_keys_topn(self, keys, topn):
        """ Keys calls top N """
        registry_usage_out = self.dataset\
            .loc[:, ['binary', 'classification', keys]]\
                .nlargest(topn, [keys])

        print("[INFO] Printing top {} binaries that performs".format(topn) +
                                        " most {} calls".format(keys))

        colors = np.where(registry_usage_out['classification'] == 1, 'b', 'c')
        registry_usage_out\
            .sort_values(by=keys)\
                .plot.barh(x='binary', 
                        y=keys, 
                        title='Top high {} keys binaries'.format(keys),
                        color=colors[::-1],
                        legend=None)\
                            .set_xlabel('Keys calls')

        print("[INFO] Saving top {} result CSV file".format(topn) +
                        "{}_top{}.csv".format(self.results_path + keys, topn))
        registry_usage_out.to_csv(self.results_path + keys\
                                + '_top{}.csv'.format(topn), index=True)
        #plt.show()

    def registry_usage_keys_class(self, keys):
        """ Keys calls classified by legitimate (0) and illegitimate (1) """
        registry_usage_out = self.dataset\
            .loc[:, ['binary', 'classification', keys]]

        print("[INFO] Printing scatter plot that shows {}".format(keys) +
                                                    " keys classes")
        registry_usage_out.plot.scatter(x=keys,
                                        y='binary',
                                        c='classification',
                                        yticks=[],
                                        colormap='viridis')

        ordered_registry_usage_out = registry_usage_out.sort_values(by=keys)
        print("[INFO] Printing ordered values of {}".format(keys))
        print(ordered_registry_usage_out)

        print("[INFO] Saving class result CSV file" +
                        " {}.csv".format(self.results_path + keys))
        ordered_registry_usage_out.to_csv(self.results_path + keys + '.csv', 
                                            index=True)

        #plt.show()

    def registry_usage_keys_cross_class(self, keys):
        """ Cross two operations in registry """
        registry_usage_cross_out = self.dataset\
            .loc[:, ['binary', 'classification', keys[0], keys[1] ]]
        
        registry_usage_cross_out[keys[2]] = registry_usage_cross_out[keys[0]] \
                                            + registry_usage_cross_out[keys[1]]

        print("[INFO] Printing scatter plot that shows {}".format(keys) +
                                                    " keys classes")
        registry_usage_cross_out.plot.scatter(x=keys[2],
                                              y='binary',
                                              c='classification',
                                              yticks=[],
                                              colormap='viridis')
        ordered_registry_usage_cross_out =\
                    registry_usage_cross_out.sort_values(by=keys[2])
        print("[INFO] Printing ordered values of {}".format(keys[2]))
        print(ordered_registry_usage_cross_out)

        print("[INFO] Saving class result CSV file" + 
                                " {}.csv".format(self.results_path + keys[2]))
        ordered_registry_usage_cross_out.to_csv(self.results_path + 
                                                keys[2] + '.csv', index=True)

        #plt.show()

    def instruction_traces_topn(self, inst, topn):
        """ Instruction traces top N """
        instruction_traces_out = self.dataset\
            .loc[:, ['binary', 'classification', inst]]\
                .nlargest(topn, [inst])

        print("[INFO] Printing top {} binaries that performs".format(topn) +
                            " most {} instruction traces calls".format(inst))

        colors = np.where(instruction_traces_out['classification'] == 1, 'b', 'c')
        instruction_traces_out\
            .sort_values(by=inst)\
                .plot.barh(x='binary', 
                        y=inst, 
                        title='Top high {} instruction traces'.format(inst),
                        color=colors[::-1],
                        legend=None)\
                            .set_xlabel('Instruction traces')

        print("[INFO] Saving top {} result CSV file".format(topn) +
                        "{}_top{}.csv".format(self.results_path + inst, topn))
        instruction_traces_out.to_csv(self.results_path + inst\
                                + '_top{}.csv'.format(topn), index=True)
        #plt.show()

    def instruction_traces_ninst_class(self, inst):
        """ Instruction traces classified by legitimate (0) and illegitimate (1) """
        instruction_traces_out = self.dataset\
            .loc[:, ['binary', 'classification', inst]]

        print("[INFO] Printing scatter plot that shows N" 
                    + " instruction {} traces classes".format(inst))

        instruction_traces_out.plot.scatter(x=inst, 
                                        y='binary',
                                        c='classification',
                                        yticks=[],
                                        colormap='viridis')

        ordered_instruction_traces_out = instruction_traces_out.\
                                        sort_values(by=inst)
        print("[INFO] Printing ordered values of n_inst")
        #print(ordered_instruction_traces_out)

        print("[INFO] Saving class result CSV file" +
                " {}_class.csv".format(self.results_path + inst))
        ordered_instruction_traces_out.to_csv(self.results_path\
                            + inst + '_class.csv', index=True)

        #plt.show()

    def api_calls_traces_category_topn(self, category, topn):
        """ Category API calls top N """
        api_call_traces_out = self.dataset\
            .loc[:, ['binary', 'classification', category]]\
                .nlargest(topn, [category])

        print("[INFO] Printing top {} binaries that performs".format(topn) +
                                        " most {} API calls".format(category))

        colors = np.where(api_call_traces_out['classification'] == 1, 'b', 'c')
        api_call_traces_out\
            .sort_values(by=category)\
                .plot.barh(x='binary', 
                        y=category, 
                        title='Top high {} API calls binaries'.format(category),
                        color=colors,
                        legend=None)\
                            .set_xlabel('API calls')

        print("[INFO] Saving top {} result CSV file".format(topn) +
                        "{}_top{}.csv".format(self.results_path + category, topn))
        api_call_traces_out.to_csv(self.results_path + category 
                                    + '_top{}.csv'.format(topn), index=True)
        #plt.show()

    def api_calls_traces_category_class(self, category):
        """ Category API calls classified by legitimate (0) and illegitimate (1) """
        api_call_traces_out = self.dataset\
            .loc[:, ['binary', 'classification', category]]

        print("[INFO] Printing scatter plot that shows windows N API calls classes")

        api_call_traces_out.plot.scatter(x=category, 
                                        y='binary',
                                        c='classification',
                                        yticks=[],
                                        colormap='viridis')

        ordered_api_call_traces_out = api_call_traces_out.\
                                        sort_values(by=category)
        print("[INFO] Printing ordered values of {}".format(category))
        print("[INFO] Saving class result CSV file" +
                " {}.csv".format(self.results_path + category))
        ordered_api_call_traces_out.to_csv(self.results_path + category\
                                                + '_class.csv', index=True)
        #plt.show()

    def signature_category_count(self):
        """ List all detected signatures """
        category = 'signatures'
        signatures_out = self.dataset\
            .loc[:, ['binary', 'name', 'analysis_id', category]]
        
        low, mid, high = [], [], []
        for index, row in signatures_out.iterrows():
            serverity_count_1, serverity_count_2, serverity_count_3 = 0, 0, 0
            sign_sum = []
            file_binary = row['binary']
            signature_raw = row[category]
            for sign in signature_raw:
                if sign['severity'] == 1: serverity_count_1 += 1
                elif sign['severity'] == 2: serverity_count_2 += 1
                elif sign['severity'] == 3: serverity_count_3 += 1
                sign_sum.append(sign['name']+'_'+str(sign['severity']))
            
            low.append(serverity_count_1)
            mid.append(serverity_count_2)
            high.append(serverity_count_3)
        signatures_out['low'] = low
        signatures_out['mid'] = mid
        signatures_out['high'] = high
        print("[INFO] Saving raw result CSV file" +
                " {}_raw.csv".format(self.results_path + category))
        signatures_out.to_csv(self.results_path + category\
                                                + '_raw.csv', index=True)
        return signatures_out
        
    def check_result_output(self):
        """ Check the result generated"""
        analysis_out = self.dataset\
            .loc[:, ['binary', 'analysis_id', 'timestamp']]

        reported_results = []
        reported_evasions = []
        is_sandboxs = []
        maliciouses = []
        malscores = []
        for index, row in analysis_out.iterrows():
                file_binary = row['binary']
                analysis_id = row['analysis_id']
                result_json_path = ""
                reported_result = ""
                reported_evasion = ""
                is_sandbox = ""
                data = []
                if Path(self.storage_path + str(analysis_id)).exists():
                    """ Read dropped json file result.json if exist"""
                    if Path(self.storage_path + str(analysis_id) + '/files.json').exists():
                        with open(self.storage_path + str(analysis_id) + '/files.json', 'r') as f:
                            content = f.read()
                            """ Match top-level JSON objects using regex (simple version) """
                            data = content.splitlines()
                            dropped_files = [json.loads(x) for x in data]
                            for dropped_file in dropped_files:
                                if 'result.json' == dropped_file['filepath'].split('\\')[-1]:
                                    result_json_path = dropped_file['path']
                    
                    if not result_json_path == "":
                        with open(self.storage_path + str(analysis_id) + '/' + result_json_path, 'r') as f:
                            recorded = False
                            try:
                                results = ast.literal_eval(f.read())
                                for result in results:
                                    if 'User Environment' == result['Result'] \
                                        or 'Sandbox Environment' == result['Result']:
                                        recorded = True
                                        reported_result = result['Details']
                                        reported_evasion = result['Evasion Method']
                                        is_sandbox = 'sandbox' if result['Result'] == 'Sandbox Environment' else 'user'
                                if not recorded:
                                    reported_evasion = results[0]['Evasion Method']
                                    is_sandbox = 'nan'
                            except: 
                                if self.log_level > 0:
                                    print("[DEBUG] Parsing result.json error in {}".\
                                    format(self.storage_path + str(analysis_id)))
                    else:
                        if self.log_level > 0:
                            print("[DEBUG] There is no dropped file in {}".\
                            format(self.storage_path + str(analysis_id)))
                        
                    """ If result.json not exist read prompt"""
                    if Path(self.storage_path + str(analysis_id) + '/reports/report.json').exists():
                        with open(self.storage_path + str(analysis_id) + '/reports/report.json', 'rb') as f:
                            json_report_data = json.load(f)
                            call_ids, call_apis, call_timestamps, process_ids, process_names,  \
                            call_categories, call_statuses, call_returns, call_pretty_returns, \
                            call_argument_list, call_repeats = self.__read_api_seq_details(json_report_data)
                            
                            prompts = []
                            for index in range(0, len(call_ids)):
                                if call_apis[index] == 'NtWriteFile':
                                    prompts.append(call_argument_list[index][2]['value'])
                            for prompt in prompts:
                                if 'Result = [sandbox]' in prompt: 
                                    is_sandbox = 'sandbox'
                                elif 'Result = [user]' in prompt:
                                    is_sandbox = 'user'
                            maliciouses.append(json_report_data['malstatus'])
                            malscores.append(json_report_data['malscore'])
                else:
                    if self.log_level > 0:
                        print("[ERROR] Cannot found {}".\
                            format(self.storage_path + str(analysis_id)))
                
                if self.log_level > 0:
                    print("[INFO] Check reported result from {}".\
                            format(self.storage_path + str(analysis_id)))    
                
                if is_sandbox == '':
                    is_sandbox = 'error'
                reported_results.append(reported_result)
                reported_evasions.append(reported_evasion)
                is_sandboxs.append(is_sandbox)

        analysis_out['reported_result'] = reported_results
        analysis_out['reported_evasion'] = reported_evasions
        analysis_out['reported_sandbox'] = is_sandboxs
        analysis_out['malscore'] = malscores
        analysis_out['malstatus'] = maliciouses

        print("[INFO] Saving raw result CSV file" +
                " {}.csv".format(self.results_path + "json_result"))
        analysis_out.to_csv(self.results_path + "json_result"\
                                                + '_raw.csv', index=True)
        return analysis_out
    
    def get_merged_report(self, df_left, df_right):
        df_right = df_right.drop(columns=['binary', 'analysis_id'])
        return pd.concat([df_left, df_right], axis=1).drop('signatures', axis=1)
    
    def __read_api_seq_details(self, json_obj):
        """ API calls of a sample"""
        api_call_traces = []

        n_api_calls = 0
        process_ids = []
        process_names = []
        call_ids = []
        call_apis, call_timestamps, call_categories, call_statuses, call_returns = [], [], [],[],[]
        call_pretty_returns, call_argument_list, call_repeats = [], [], []

        for p in json_obj['behavior']['processes']: # for each processes
            pid = p['process_id']
            pname = p['process_name']
            api_calls = p['calls']
            for call in api_calls:
                call_timestamp = call['timestamp']
                call_id = call['id']
                call_api = call['api']
                call_category = call['category']
                call_status = call['status']
                call_return = call['return']
                call_pretty_return = call['pretty_return'] if 'pretty_return' in call else ''
                call_arguments = call['arguments'] #name, value, pretty_value(if exist)
                call_repeated = call['repeated']
        
                # The api data
                process_ids.append(pid)
                process_names.append(pname)
                call_ids.append(call_id)
                call_apis.append(call_api)
                call_timestamps.append(call_timestamp)
                call_categories.append(call_category)
                call_statuses.append(call_status)
                call_returns.append(call_return)
                call_pretty_returns.append(call_pretty_return)
                call_argument_list.append(call_arguments)
                call_repeats.append(call_repeated)

        return  call_ids, call_apis, call_timestamps, process_ids, process_names,  \
                call_categories, call_statuses, call_returns, call_pretty_returns, \
                call_argument_list, call_repeats
    
    def ___read_prompt_print(self, json_obj):
        call_ids, call_apis, call_timestamps, process_ids, process_names,  \
                call_categories, call_statuses, call_returns, call_pretty_returns, \
                call_argument_list, call_repeats = self.__read_api_seq_details(json_obj)

        prompts = []
        for index in range(0, len(call_ids)):
            if call_apis[index] == 'NtWriteFile':
                # NtWriteFile (FileHandle, Handlename, Buffer, Length)
                prompts.append(call_argument_list[index][2]['value'])
        return prompts
    
    def __get_hookdef_by_name(self, hookdefs, x):
        for hook in hookdefs:
            if hook['api'] == 'GetUserNameW':
                return hook
        return None
    
    def get_api_seq_report(self):
        """ Get new Matsuzawa result that from the prompt output """
        analysis_out = self.dataset\
            .loc[:, ['binary', 'analysis_id']]

        reported_results = []
        reported_evasions = []
        is_sandboxs = []
        prompts = []
        hooked_apis, hookdefs = CapemonHook.extract_capemon_hookdef()
        encountered_hooks = set()
        all_apis = set()
        for index, row in analysis_out.iterrows():
                file_binary = row['binary']
                analysis_id = row['analysis_id']
                result_json_path = ""
                reported_result = ""
                reported_evasion = ""
                is_sandbox = ""
                data = []
                
                if Path(self.storage_path + str(analysis_id)).exists():
                    if Path(self.storage_path + str(analysis_id) + '/reports/report.json').exists():
                        with open(self.storage_path + str(analysis_id) + '/reports/report.json', 'rb') as f:
                            json_report_data = json.load(f)
                            call_ids, call_apis, call_timestamps, process_ids, process_names,  \
                            call_categories, call_statuses, call_returns, call_pretty_returns, \
                            call_argument_list, call_repeats = self.__read_api_seq_details(json_report_data)
                            for index in range(0, len(call_ids)):
                                all_apis.add(call_apis[index])
                                if call_apis[index] == 'NtWriteFile':
                                    prompts.append(call_argument_list[index][2]['value'])
                                if call_apis[index] in hooked_apis:
                                    encountered_hooks.add(call_apis[index])

        detected = ''
        for prompt in prompts:
            if 'Result = [sandbox]' in prompt: 
                detected = 'sandbox'
            elif 'Result = [user]' in prompt:
                detected = 'user'

        analysis_out['detected'] = detected
        
        return analysis_out
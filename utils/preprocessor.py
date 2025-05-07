import configparser
import json

class Preprocessor:
    """Performs a preprocessed steps of configuration file and json reports """ 
    def __init__(self, conf_file, log_level):
        self.conf_file = conf_file
        self.log_level = log_level
        self.cape_storage = ''
        self.reports_path = ''
        self.results_path = ''
        self.p_train = 0.0
        self.p_test = 0.0
        self.nfirst = 0
        self.nlast = 0

    def __read_configuration(self):
        """Reads configuration file (*.conf) and returns variables 
            values as dictionary"""
        config = configparser.ConfigParser()
        config.read(self.conf_file)
        if 'cape' in config:
            self.cape_storage = config['cape']['storage']
        if 'reports' in config:
            self.reports_path = config['reports']['path']
            if self.log_level > 0:
                print("[DEBUG] Reports path is {}".format(self.reports_path))

            # self.p_train = config['reports']['train']
            # self.p_test = config['reports']['test']
            # self.nfirst = config['reports']['nfirst']
            # self.nlast = config['reports']['nlast']

        if 'results' in config:
            self.results_path = config['results']['path']
            if self.log_level > 0:
                print("[DEBUG] Results path is {}".format(self.results_path))
            
            return { 'reports_path': self.reports_path,
                    'results_path': self.results_path,
                    'cape_storage': self.cape_storage,
                    # 'p_train': self.p_train, 
                    # 'p_test': self.p_test,
                    'nfirst': self.nfirst,
                    'nlast': self.nlast }
       
        else:
            if self.log_level > 0:
                print("[ERROR] Reports section has not been configured")

            return None

    def get_configuration(self):
        """Returns reports path"""
        try:
            return self.__read_configuration()
        except:
            raise

    def __read_metadata(self, json):
        """ Reads binary metadada and builds a dictionary """
        if 'name' in json['target']['file']:
            name = json['target']['file']['name']
        else:
            name = "None"

        if 'md5' in json['target']['file']:
            md5 = json['target']['file']['md5']
        else:
            md5 = "None"

        if 'sha1' in json['target']['file']:
            sha1 = json['target']['file']['sha1']
        else:
            sha1 = "None"

        if 'entrypoint' in json['target']['file']:
            entrypoint = json['target']['file']['entrypoint']
        else:
            entrypoint = "None"
        
        if 'timestamp' in json['target']['file']:
            timestamp = json['target']['file']['timestamp']
        elif 'ended' in json['info']:
            timestamp = json['info']['ended']
        else:
            timestamp = "None"
        
        if 'id' in json['info']:
            id = json['info']['id']
        else:
            id = None
        return {'name': name, 'id':id, 'md5': md5, 
            'sha1': sha1, 'entrypoint': entrypoint, 
            'timestamp': timestamp, 'classification': -1 }

    def __read_registers_usage(self, json):
        """ Read registers' usage """
        registry_usage = {'read_keys': [], 'write_keys': [], 'delete_keys': [] }
        for k in json['behavior']['summary']['read_keys']:
            registry_usage['read_keys'].append(k)

        if self.log_level > 0:
            print("[DEBUG] Read keys normalize")

        for k in json['behavior']['summary']['write_keys']:
            registry_usage['write_keys'].append(k)

        if self.log_level > 0:
            print("[DEBUG] Write keys normalize")

        for k in json['behavior']['summary']['delete_keys']:
            registry_usage['delete_keys'].append(k)

        if self.log_level > 0:
            print("[DEBUG] Delete keys normalize")

        return registry_usage, len(registry_usage['read_keys']),\
             len(registry_usage['write_keys']),\
                  len(registry_usage['delete_keys'])

    def __read_instruction_traces(self, json):
        """ Reads instruction traces """
        instruction_traces = []
        instruction_traces_data = []
        read_inst = 0
        write_inst = 0
        delete_inst = 0
        load_inst = 0
        create_inst = 0
        execute_inst = 0
        move_inst = 0
        copy_inst = 0
        findwindow_inst = 0
        start_inst = 0
        modify_inst = 0
        browser_inst = 0

        n_inst = 0
        for i in json['behavior']['enhanced']:
            n_inst += 1
            instruction = i['event']
            instruction_traces.append(instruction)
            """ We only extract first value: file, key, dll name """
            first_key = list(i['data'].keys())[0]
            instruction_traces_data.append(i['data'][first_key])

            if instruction == 'read':
                read_inst += 1
            elif instruction == 'write':
                write_inst += 1
            elif instruction == 'delete':
                delete_inst += 1
            elif instruction == 'load':
                load_inst += 1
            elif instruction == 'create':
                create_inst += 1
            elif instruction == 'execute':
                execute_inst += 1
            elif instruction == 'move':
                move_inst += 1
            elif instruction == 'copy':
                copy_inst += 1
            elif instruction == 'findwindow':
                findwindow_inst += 1
            elif instruction == 'start':
                start_inst += 1
            elif instruction == 'modify':
                modify_inst += 1
            elif instruction == 'browser':
                browser_inst += 1
            else:
                print("[INFO] Unknown instruction {}".format(instruction))

        if self.log_level > 0:
            print("[DEBUG] Instruction traces normalize")

        return instruction_traces, instruction_traces_data,\
            n_inst, read_inst, write_inst, delete_inst, load_inst,\
            create_inst, execute_inst, move_inst, copy_inst, findwindow_inst,\
            start_inst, modify_inst, browser_inst

    def __read_api_call_traces(self, json):
        """ Reads API calls and these categories """

        """ Initialize to 0 API calls categories """
        windows_api_calls = 0
        services_api_calls = 0
        system_api_calls = 0
        synchronization_api_calls = 0
        registry_api_calls = 0
        threading_api_calls = 0
        process_api_calls = 0
        network_api_calls = 0
        misc_api_calls = 0
        hooking_api_calls = 0
        filesystem_api_calls = 0
        device_api_calls = 0
        crypto_api_calls = 0
        com_api_calls = 0
        browser_api_calls = 0

        """ API calls """
        api_call_traces = []
        n_api_calls = 0
        for p in json['behavior']['processes']:
            api_calls = p['calls']
            for call in api_calls:
                api_call_traces.append(call['api'])
                n_api_calls += 1

                category = call['category']
                if category == 'windows':
                    windows_api_calls += 1
                elif category == 'services':
                    services_api_calls += 1
                elif category == 'system':
                    system_api_calls += 1
                elif category == 'synchronization':
                    synchronization_api_calls += 1
                elif category == 'threading':
                    threading_api_calls += 1
                elif category == 'registry':
                    registry_api_calls += 1
                elif category == 'process':
                    process_api_calls += 1
                elif category == 'network':
                    network_api_calls += 1
                elif category == 'misc':
                    misc_api_calls += 1
                elif category == 'hooking':
                    hooking_api_calls += 1
                elif category == 'filesystem':
                    filesystem_api_calls += 1
                elif category == 'device':
                    device_api_calls += 1
                elif category == 'crypto':
                    crypto_api_calls += 1
                elif category == 'com':
                    com_api_calls += 1
                elif category == 'browser':
                    browser_api_calls += 1
                else:
                    print("[INFO] Unknown category {}".format(category))
                    print(category)


        if self.log_level > 0:
            print("[DEBUG] API calls normalize")

        return api_call_traces, n_api_calls, windows_api_calls,\
                services_api_calls, system_api_calls, synchronization_api_calls,\
                    registry_api_calls, threading_api_calls, process_api_calls,\
                        network_api_calls, misc_api_calls, hooking_api_calls,\
                            filesystem_api_calls, device_api_calls, crypto_api_calls,\
                                com_api_calls, browser_api_calls

    def __read_api_seq_details(self, json):
        """ API calls of a sample"""
        api_call_traces = []

        n_api_calls = 0
        process_ids = []
        process_names = []
        call_ids = []
        call_apis, call_timestamps, call_categories, call_statuses, call_returns = [], [], [],[],[]
        call_pretty_returns, call_argument_list, call_repeats = [], [], []

        for p in json['behavior']['processes']: # for each processes
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
    
    def ___read_prompt_print(self, json):
        call_ids, call_apis, call_timestamps, process_ids, process_names,  \
                call_categories, call_statuses, call_returns, call_pretty_returns, \
                call_argument_list, call_repeats = self.__read_api_seq_details(json)

        prompts = []
        for index in range(0, len(call_ids)):
            if call_apis[index] == 'NtWriteFile':
                # NtWriteFile (FileHandle, Handlename, Buffer, Length)
                prompts.append(call_argument_list[index][2]['value'])
        return prompts

    def __read_network_traffic(self, json):
        """ Reads network traffic """
        network_traffic = { 'tcp': [], 'udp': []}
        if 'tcp' in json['network']:
            for t in json['network']['tcp']:
                network_traffic['tcp'].append(t)

        if 'udp' in json['network']:
            for u in json['network']['udp']:
                network_traffic['udp'].append(u)

        if self.log_level > 0:
            print("[DEBUG] Network traffic (TCP and UDP) normalize")

        return network_traffic

    def __read_dynamic_features(self, json):
        """ Reads dynamic features from json file report """
        registry_usage, n_read_keys,\
             n_write_keys, n_delete_keys = self.__read_registers_usage(json)

        instruction_traces, instruction_traces_data, n_inst, read_inst,\
            write_inst, delete_inst, load_inst, create_inst,\
                 execute_inst, move_inst, copy_inst, findwindow_inst,\
                    start_inst, modify_inst, browser_inst\
                         = self.__read_instruction_traces(json)

        api_call_traces, n_api_calls, windows_api_calls, services_api_calls,\
            system_api_calls, synchronization_api_calls, registry_api_calls,\
                threading_api_calls, process_api_calls, network_api_calls,\
                    misc_api_calls, hooking_api_calls, filesystem_api_calls,\
                        device_api_calls, crypto_api_calls, com_api_calls,\
                            browser_api_calls = self.__read_api_call_traces(json)

        network_traffic = self.__read_network_traffic(json)

        """ If you want to extract more dynamic features, please write your
        code below """
        return { 'registry_usage': registry_usage, 
                'n_read_keys': n_read_keys,
                'n_write_keys': n_write_keys,
                'n_delete_keys': n_delete_keys,
                'instruction_traces': instruction_traces, 
                'instruction_traces_data': instruction_traces_data, 
                'n_inst': n_inst,
                'read_inst': read_inst,
                'write_inst': write_inst,
                'delete_inst': delete_inst,
                'load_inst': load_inst,
                'create_inst': create_inst,
                'execute_inst': execute_inst,
                'move_inst': move_inst,
                'copy_inst': copy_inst,
                'findwindow_inst': findwindow_inst,
                'start_inst': start_inst,
                'modify_inst': modify_inst,
                'browser_inst': browser_inst,
                'api_call_traces': api_call_traces,
                'n_api_calls': n_api_calls,
                'windows_api_calls': windows_api_calls,
                'services_api_calls': services_api_calls,
                'system_api_calls': system_api_calls,
                'synchronization_api_calls': synchronization_api_calls,
                'registry_api_calls': registry_api_calls,
                'threading_api_calls': threading_api_calls,
                'process_api_calls': process_api_calls,
                'network_api_calls': network_api_calls,
                'misc_api_calls': misc_api_calls,
                'hooking_api_calls': hooking_api_calls,
                'filesystem_api_calls': filesystem_api_calls,
                'device_api_calls': device_api_calls,
                'crypto_api_calls': crypto_api_calls,
                'com_api_calls': com_api_calls,
                'browser_api_calls': browser_api_calls,
                'network_traffic': network_traffic }

    def get_json_report(self, file):
        """ Reads json report from file and normalize variables """
        if self.log_level > 0:
            print("[DEBUG] Report JSON file {}".format(file))

        with open(file, 'rb') as f:
            json_data = json.load(f)

        metadata = self.__read_metadata(json_data)

        """ Extract good (0) or bad (1) value from filename """
        f_splits = file.split('\\')
        s_splits = f_splits[-1].split('-')
        metadata['classification'] = int(s_splits[-1].split('.')[0])
        
        if self.log_level > 0:
            print("[DEBUG] All binary metadata has been normalized")

        dyn_features = self.__read_dynamic_features(json_data)
        if self.log_level > 0:
            print("[DEBUG] All dynamic features have been normalized")

        sta_features = self.__read_static_features(json_data)
        if self.log_level > 0:
            print("[DEBUG] All static features have been normalized")
        return metadata, dyn_features, sta_features

    def get_prompts(self, file):
        """ Reads json report from file and extract api sequences """
        if self.log_level > 0:
            print("[DEBUG] Report JSON file {}".format(file))

        with open(file, 'rb') as f:
            json_data = json.load(f)
        metadata = self.__read_metadata(json_data)
        prompts = self.___read_prompt_print(json_data)
        
        if self.log_level > 0:
            print("[DEBUG] Extracted API sequences")
        return metadata, prompts

    ### Added feature
    def __read_static_features(self, json):
        signature_list = self.__read_signature(json)
        return {'signatures': signature_list}

    def __read_signature(self, json) :
        signatures = []
        #severity 1 = blue, 2 = yellow, 3 = red
        for s in json['signatures']:
            signatures.append(s)
        return signatures

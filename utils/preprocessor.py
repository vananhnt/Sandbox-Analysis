"""
Author: Luis Fueris
Date: 15/05/2021
"""

import configparser
import json


class Preprocessor:
    """Performs a preprocessed steps of configuration file and json reports """ 
    def __init__(self, conf_file, log_level):
        self.conf_file = conf_file
        self.log_level = log_level
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
        else:
            timestamp = "None"
        
        return {'name': name, 'md5': md5, 
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

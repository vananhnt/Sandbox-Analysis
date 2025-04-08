import matplotlib.pyplot as plt
import numpy as np

class Analysis:
    """ Performs data analysis """
    """ TODO: printing some message by log_level var """
    def __init__(self, log_level, dataset, results_path):
        self.log_level = log_level
        self.dataset = dataset
        self.results_path = results_path

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
        print(ordered_instruction_traces_out)

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
        print(ordered_api_call_traces_out)

        print("[INFO] Saving class result CSV file" +
                " {}.csv".format(self.results_path + category))
        ordered_api_call_traces_out.to_csv(self.results_path + category\
                                                + '_class.csv', index=True)
        #plt.show()

    def signature_category_count(self, category):
        """ List all detected signatures """
        signatures_out = self.dataset\
            .loc[:, ['binary', 'classification', category]]

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
            print(file_binary, serverity_count_1, serverity_count_2, serverity_count_3, sign_sum)
            low.append(serverity_count_1)
            mid.append(serverity_count_2)
            high.append(serverity_count_3)
        signatures_out['low'] = low
        signatures_out['mid'] = mid
        signatures_out['high'] = high
        print("[INFO] Saving raw result CSV file" +
                " {}.csv".format(self.results_path + category))
        signatures_out.to_csv(self.results_path + category\
                                                + 'raw.csv', index=True)
        
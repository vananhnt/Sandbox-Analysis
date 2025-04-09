"""
Author: Luis Fueris
Date: 09/05/2021
"""

import hashlib


class FeatureEngineering:
    def __init__(self, log_level, binaries, column):
        self.log_level = log_level
        self.binaries = binaries
        self.column = column


    def extract_prologue(self, nfirst):
        """ Extract prologue from self.column values. First nfirts values """
        if self.log_level > 0:
            print("[DEBUG] Extracting prologue from" 
                                    + " {}".format(self.column.columns))

        prologue = []
        for _, item in self.column.iterrows():
            chain = ''
            for j in item:
                if len(j) >= nfirst:
                    for k in range(nfirst):
                        chain = chain + ";" + j[k]
                else:   
                    """ If item does not have enough values, result value is null """
                    chain = 'null'

            """ Perform hashing to prologue values """
            b_chain = bytes(chain, 'utf-8')
            md5 = hashlib.md5(b_chain)

            prologue.append(md5.hexdigest())

            id_hash = self.binaries.iloc[[item.name]].binary
            if self.log_level > 0:
                print("[DEBUG] Binary is {}".format(id_hash.values[0]))
                print("[DEBUG] Prologue for"\
                        + " {} binary is {}".format(id_hash.values[0], chain))
                print("[DEBUG] Hashing prologue for"\
                                + " {} is".format(id_hash.values[0])\
                                + " {}".format(md5.hexdigest()))
            
        return prologue 


    def extract_epilogue(self, nlast):
        """ Extract epilogue from instruction traces. First nlast values """
        if self.log_level > 0:
            print("[DEBUG] Extracting epilogue from" 
                                    + " {}".format(self.column.columns))

        epilogue = []
        for _, item in self.column.iterrows():
            chain = ''
            for j in item:
                if len(j) >= nlast:
                    for k in range(nlast):
                        chain = chain + ";" + j[(len(j) - nlast) + k]
                else:   
                    """ If item does not have enough values, result value is null """
                    chain = 'null'

            """ Perform hashing to prologue values """
            b_chain = bytes(chain, 'utf-8')
            md5 = hashlib.md5(b_chain)

            epilogue.append(md5.hexdigest())

            id_hash = self.binaries.iloc[[item.name]].binary
            if self.log_level > 0:
                print("[DEBUG] Binary is {}".format(id_hash.values[0]))
                print("[DEBUG] Epilogue for"\
                        + " {} binary is {}".format(id_hash.values[0], chain))
                print("[DEBUG] Hashing epilogue for"\
                                + " {} is".format(id_hash.values[0])\
                                + " {}".format(md5.hexdigest()))
            
        return epilogue

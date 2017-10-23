import json
from pprint import pprint
import sys, traceback

class aura_attributes():
    def __init__(self):
        with open('/opt/stack/keystone/keystone/common/assigned_attributes.json') as att:
            self.data = json.load(att)
    # print(len(data))

    def get(self, username, key):
        for i in range(len(self.data)):
            if str(self.data[i]["id"])==username:
                #print key
                #print(self.data[i][key])
                return(self.data[i][key])


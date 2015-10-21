import utility
import state

'''Generic Vulnerability Check class to inherit from
implement generic funcationality here that should apply to all vulnerability checks
for example, print functions'''
class VulnerabilityCheck(object):

    def __init__(self):
        self.host = None
        self.port = None
        self.path = None
        self.data = None
        self.name=None
                
    '''This method should be overridden by implementing interfaces'''
    def check(self,ip,port,ssl):
        pass

    def print_message(self,status,host,port=None):
        if status:
            utility.Msg("{0} PASSED on host {1}:{2}".format(self.name,host,port),'SUCCESS')
        else:
            utility.Msg("{0} FAILED on host {1}:{2}".format(self.name,host,port),'ERROR')
            
    def __str__(self):
        return self.name


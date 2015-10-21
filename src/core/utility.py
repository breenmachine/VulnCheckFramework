'''
General multi-purpose code goes here. For example, code to GET or POST HTTP requests,
open raw sockets etc...
'''
import requests
import pkgutil
import sys
from os import listdir,getcwd
from os.path import isfile
from src.modules.http.interfaces import HTTPHeadersFingerprint
import state
from datetime import date, datetime
import xml.etree.ElementTree as ET

def portInRange(port,portRanges):
    portRanges = portRanges.split(',')
    for portRange in portRanges:
        validPorts = portRange.split('-');
        if len(validPorts) == 1:
            validPorts.append(validPorts[0])
        if((int(port)>=int(validPorts[0]) and int(port)<= int(validPorts[1]))):
            return True  
    return False    

def get_checks():
    modules={}
    moduleCategories=[d for d in listdir(getcwd()+'/src/modules/') if not isfile(getcwd()+'/src/modules/'+d)]
    for moduleCategory in moduleCategories:
        modules[moduleCategory]=[]
        fpath = [getcwd()+'/src/modules/'+moduleCategory+'/checks']
        checks = list(pkgutil.iter_modules(fpath))

        for check in checks:
            checkMod = check[0].find_module(check[1]).load_module(check[1]).VCheck()
            modules[moduleCategory].append(checkMod)

    return modules


def print_checks(check_dict):
    for checkCat in check_dict:
        print checkCat
        for check in check_dict[checkCat]:
            print '\t'+str(check)

def requests_get(*args, **kwargs):
    """ Generate a GET request
    """

    (args, kwargs) = build_request(args, kwargs)
    Msg("Making GET request to {0} with arguments {1}".format(args[0], kwargs),'DEBUG')
    return requests.get(*args, **kwargs)


def requests_post(*args, **kwargs):
    """ Generate a POST request
    """

    (args, kwargs) = build_request(args, kwargs)
    Msg("Making POST request to {0} with arguments {1}".format(args[0], kwargs),'DEBUG')
    return requests.post(*args, **kwargs)

def requests_other(*args,**kwargs):
    (args, kwargs) = build_request(args, kwargs)
    Msg("Making {0} request to {1} with args {2}".format(args[0],args[1],kwargs),'DEBUG')
    return requests.request(*args,**kwargs)

def requests_head(*args, **kwargs):
    """ Generate a HEAD request
    """

    (args, kwargs) = build_request(args, kwargs)
    Msg("Making HEAD request to {0} with args {1}".format(args[0], kwargs),'DEBUG')
    return requests.head(*args, **kwargs)


def requests_put(*args, **kwargs):
    """ Generate a PUT request
    """

    (args, kwargs) = build_request(args, kwargs)
    Msg("Making PUT request to {0} with args {1}".format(args[0], kwargs),
                                                  'DEBUG')
    return requests.put(*args, **kwargs)

def build_request(args, kwargs):
    """ This function is used for building requests' objects by adding
    state-wide arguments, such as proxy settings, user agents, and more.
    All requests are built using this function.
    """
    if state.proxy:
        (proxy, server, port) = state.proxy.split(":")
        connection = "{0}:{1}:{2}".format(proxy, server, port)
        if state.proxy_auth:
            (usr, pswd) = state.proxy_auth.split(":")
            connection = "{0}://{1}:{2}@{3}:{4}".format(proxy, usr, pswd, server, port)
        kwargs['proxies'] = dict({proxy:connection})

    if state.random_agent:
        ua = {'User-Agent' : state.random_agent}
        if 'headers' in kwargs:
            kwargs['headers'].update(ua)
        else:
            kwargs['headers'] = ua

    if not 'timeout' in kwargs.keys():
        kwargs['timeout'] = state.timeout

    kwargs['verify'] = False
    return (args, kwargs)

def Msg(string, level='INFO'):
    """ Output a formatted message dictated by the level.  The levels are:
            INFO - Informational message, i.e. progress
            SUCCESS - Action successfully executed/completed, i.e. WAR deployed
            ERROR - An error of some sort has occured
            DEBUG - Debugging output
            UPDATE - Status updates, i.e. host fingerprinting completed
    """
    if level == 'INFO':
        print '\033[32m [%s] %s\033[0m' % (timestamp(), string)
    elif level == 'SUCCESS':
        print '\033[1;33m [%s] %s\033[0m' % (timestamp(), string)
    elif level == 'ERROR':
        print '\033[31m [%s] %s\033[0m' % (timestamp(), string)
    elif level == 'DEBUG':
        if state.isdebug:
            print '\033[34m [%s] %s\033[0m' % (timestamp(), string)
    elif level == 'UPDATE':
        print '\033[33m [%s] %s\033[0m' % (timestamp(), string)


def timestamp():
    """ Returns a timestamp in the format year-month-day time
    """

    return '%s %s' % (date.today().isoformat(),
                            datetime.now().strftime('%I:%M%p'))

def reload_databases():
    credentialFiles = [d for d in listdir(getcwd()+'/credentialDatabase/')]
    loginDataCount = 0
    for credFile in credentialFiles:
        tree = ET.parse(getcwd()+'/credentialDatabase/'+credFile)
        root = tree.getroot()
        for module in root:
            moduleName = ''
            module_src='from src.modules.http.interfaces import HTTPAuthenticationTest\nclass VCheck(HTTPAuthenticationTest):\n\tdef __init__(self):\n\t\tsuper(VCheck, self).__init__()\n\t\tself.loginData=[]\n\t\tself.urls=[]'
            for element in module:
                if(element.tag == 'name'):
                    moduleName = element.text
                    module_src = module_src+'\n\t\t'+'self.name = \''+element.text+'\''
                if(element.tag == 'port_range'):
                    module_src = module_src+'\n\t\t'+'self.port_range = \''+element.text+'\''
                if(element.tag == 'urls'):
                    module_src = module_src+'\n\t\t'+'self.urls.append({'
                    fprintPageUrl=''
                    loginUrl=''
                    for subelem in element:
                        if(subelem.tag == 'fprintPageUrl'):
                            fprintPageUrl = subelem.text
                            module_src = module_src+'\'fprintPageUrl\':\''+fprintPageUrl+'\','
                        elif(subelem.tag == 'loginUrl'):
                            loginUrl = subelem.text
                            module_src = module_src+'\'loginUrl\':\''+loginUrl+'\','
                    module_src=module_src+'})'
                      
                if(element.tag == 'fprintPage'):
                    module_src = module_src+'\n\t\t'+'self.fprintPage = \''+element.text+'\''    
                if(element.tag == 'usernameField'):
                    module_src = module_src+'\n\t\t'+'self.usernameField = \''+element.text+'\''                 
                if(element.tag == 'passwordField'):
                    module_src = module_src+'\n\t\t'+'self.passwordField = \''+element.text+'\''                              
                if(element.tag == 'fprintMethod'):
                    module_src = module_src+'\n\t\t'+'self.fprintMethod = \''+element.text+'\''                    
                if(element.tag == 'checkLoginMethod'):
                    module_src = module_src+'\n\t\t'+'self.checkLoginMethod = \''+element.text+'\''                     
                if(element.tag == 'doAuth'):
                    module_src = module_src+'\n\t\t'+'self.doAuth = '+element.text
                if(element.tag == 'followLoginRedirects'):
                    module_src = module_src+'\n\t\t'+'self.followLoginRedirects = '+element.text                           
                if(element.tag == 'loginData'):
                    module_src = module_src+'\n\t\t'+'self.loginData.append({'
                    for param in element:
                        paramName=''
                        paramValue=''
                        for elem in param:
                            if(elem.tag == 'name'):
                                paramName=elem.text
                            elif(elem.tag == 'value'):
                                paramValue=elem.text
                            if paramValue is None:
                                paramValue = ''
                        module_src = module_src+'\''+paramName+'\':\''+paramValue+'\','
                    module_src=module_src+'})'

                if(element.tag == 'fprintSuccess'):
                    module_src = module_src+'\n\t\t'+'self.fprintSuccess = \''+element.text+'\''                    
                if(element.tag == 'fprintSuccessLocation'):
                    module_src = module_src+'\n\t\t'+'self.fprintSuccessLocation = \''+element.text+'\''                    
                if(element.tag == 'ssl'):
                    module_src = module_src+'\n\t\t'+'self.ssl = \''+element.text+'\''                    
            
            moduleOutFile=open('./src/modules/http/checks/'+moduleName+'.py','w+')
            moduleOutFile.write(module_src)
            moduleOutFile.close()

    Msg("Databases successfully reloaded","SUCCESS")
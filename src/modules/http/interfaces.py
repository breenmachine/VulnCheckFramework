from vulncheck import VulnerabilityCheck
from requests import exceptions
import utility
from requests.auth import HTTPBasicAuth
import state
import copy
import os
from mechanize import ParseFile
from urlparse import urlparse
import StringIO
import random
import string
from requests.exceptions import ConnectionError


'''This module trys to find HTML Forms with password fields and authenticate'''
class AutoHTTPForm(VulnerabilityCheck):
    def __init__(self):
        self.port=80
        self.ssl=None
        self.loginData=[]
        self.foundUrl = ""
        self.foundCreds = []

    def detectUsernameField(self,fieldName):
        if fieldName is None:
            return False
        for field in self.usernameFieldList:
            if fieldName.lower() == field.lower():
                return True
        return False

    def check(self,host,port=None,ssl=None):
        if(port == None):
            port = self.port
        ssl = getSSL(self.ssl,ssl,host,port)
        if ssl == None:
            return False

        if(state.credentials is not None):
            if(os.path.exists(state.credentials)):
                credentialInFile=open(state.credentials,'r')
                for line in credentialInFile.readlines():
                    usernamePassword = line.split(':')
                    self.loginData.append([usernamePassword[0].strip(),usernamePassword[1].strip()])
                credentialInFile.close()
            else:
                usernamePassword = state.credentials.split(':')
                self.loginData.append([usernamePassword[0].strip(),usernamePassword[1].strip()])


        '''Should add code to detect and handle basicauth'''

        '''Grab the page, look for forms'''
        resp = make_request("GET",host,port,ssl,"/",None)
        cookies = resp.cookies
        output = StringIO.StringIO()
        output.write(resp.content)
        output.seek(0)

        forms = ParseFile(output,resp.url,backwards_compat=False)

        for form in forms:
            curFormData = {}
            passwordFieldName = None
            usernameFieldName = None
            for control in form.controls:
                curFormData[control.name] = control.value
                if(control.type == 'password'):
                    passwordFieldName = control.name
                if self.detectUsernameField(control.name):
                    usernameFieldName = control.name

            if passwordFieldName is not None and usernameFieldName is not None:

                utility.Msg("Found potential login form".format(form),'DEBUG')

                invalidLoginFingerprint = self.fingerprintLogin(form.action,curFormData,usernameFieldName,passwordFieldName,cookies,ssl)
                if invalidLoginFingerprint is None:
                    utility.Msg("Could not get a stable fingerprint",'DEBUG')
                    break
                for credential in self.loginData:
                    curFormData[usernameFieldName] = credential[0]
                    curFormData[passwordFieldName] = credential[1]

                    o = urlparse(form.action)
                    resp = make_request("POST",o.hostname,o.port,ssl,o.path+"?"+o.query,curFormData,cookies)

                    if(self.checkValidLogin(invalidLoginFingerprint,resp.content)):
                        self.foundCreds = credential
                        self.foundUrl = form.action
                        return True

        return False

    def checkValidLogin(self,invalidLoginFingerprint,responseContent):
        originalSet = invalidLoginFingerprint[0]
        fingerprint = invalidLoginFingerprint[1]

        newSet = set(responseContent.split())

        newIntersection = originalSet & newSet

        if newIntersection == fingerprint:
            return False
        else:
            return True


    def fingerprintLogin(self,postUrl,formData,usernameFieldName,passwordFieldName,cookies,ssl):
        o = urlparse(postUrl)
        formData[usernameFieldName] = randomword(6)
        formData[passwordFieldName] = randomword(8)
        firstResp = make_request("POST",o.hostname,o.port,ssl,o.path+"?"+o.query,formData,cookies).content
        
        formData[usernameFieldName] = randomword(6)
        formData[passwordFieldName] = randomword(8)
        secondResp = make_request("POST",o.hostname,o.port,ssl,o.path+"?"+o.query,formData,cookies).content

        formData[usernameFieldName] = randomword(6)
        formData[passwordFieldName] = randomword(8)
        thirdResp = make_request("POST",o.hostname,o.port,ssl,o.path+"?"+o.query,formData,cookies).content

        firstList = firstResp.split()
        secondList = secondResp.split()
        thirdList = thirdResp.split()

        firstSet = set(firstList)
        secondSet = set(secondList)
        thirdSet = set(thirdList)

        intersection1 = firstSet & secondSet
        intersection2 = firstSet & thirdSet

        '''Test stability - intersections shoudl be the same'''
        if(intersection1 == intersection2):
            return [firstSet,intersection1]
        else:
            return None


    def print_message(self,status,host,port=None):
        if status:
            utility.Msg("Login Success at {0} with {1}".format(self.foundUrl,self.foundCreds),'SUCCESS')
        else:
            utility.Msg("{0} FAILED on host {1}:{2}".format(self.name,host,port),'DEBUG')


'''This module attempts to authenticate to a login form specified on a target page
First fingerprinting is done to ensure it is the right page, then we attempt to auth'''
class HTTPAuthenticationTest(VulnerabilityCheck):
    def __init__(self):
        self.fprintMethod = 'GET'
        self.urls = [{'fprintPageUrl':'/','loginUrl':'/'}]
        self.fprintPage=None

        self.checkLoginMethod='POST'
        self.fprintSuccess=None
        self.loginData=None
        self.fprintSuccessLocation='text'
        self.followLoginRedirects = False

        self.port=80
        self.ssl = None
        self.foundCreds = None
        self.foundUrl = None

        self.usernameField = 'username'
        self.passwordField = 'password'

        self.doAuth = True

    def check(self,host,port=None,ssl=None):
        if(port == None):
            port = self.port


        '''Check to see if custom credentials have been defined on the CLI. If so
        add them as first to the creds to be checked for each module, if 'nD' flag is set 
        don't check defaults, only specified '''
        if(state.credentials is not None):

            '''set the doAuth flag in the module - we will try to auth with supplied creds'''
            self.doAuth = True
            loginDataTemplate = self.loginData[0]
            if(state.no_defaults):
                self.loginData = []

            if(os.path.exists(state.credentials)):
                credentialInFile=open(state.credentials,'r')
                for line in credentialInFile.readlines():
                    usernamePassword = line.split(':')
                    curCredential = copy.deepcopy(loginDataTemplate)
                    if(self.usernameField is not None and self.usernameField in loginDataTemplate):
                        curCredential[self.usernameField] = usernamePassword[0].strip()
                    if(self.passwordField is not None and self.passwordField in loginDataTemplate):
                        curCredential[self.passwordField] = usernamePassword[1].strip()
                    self.loginData.insert(0,curCredential)
                credentialInFile.close()
            else:
                usernamePassword = state.credentials.split(':')
                curCredential = copy.deepcopy(loginDataTemplate)
                if(self.usernameField is not None and self.usernameField in loginDataTemplate):
                    curCredential[self.usernameField] = usernamePassword[0]
                if(self.passwordField is not None and self.passwordField in loginDataTemplate):
                    curCredential[self.passwordField] = usernamePassword[1]
                self.loginData.insert(0,curCredential)

        #Before attempting to fingerprint or authenticate, make sure the port is within range for this module
        if(utility.portInRange(port,self.port_range)):
            ssl = getSSL(self.ssl,ssl,host,port)
            if ssl == None:
                return False

            for url in self.urls:
                if 'fprintPageUrl' in url:
                    fprintPageUrl = url['fprintPageUrl']
                loginUrl = url['loginUrl']
                if(self.checkLoginMethod == 'BASIC'):
                    return self._doBasicAuth(host,port,ssl,loginUrl)
                else:
                    return self._doHTTPAuth(host,port,ssl,fprintPageUrl,loginUrl)

    def _doHTTPAuth(self,host,port,ssl,fprintPageUrl,loginUrl):
        fingerprintResponse = make_request(self.fprintMethod,host,port,ssl,fprintPageUrl,None)
        if fingerprintResponse == None:
            return False
        utility.Msg("Received login fingerprint response: {0}".format(fingerprintResponse.content),'DEBUG')

        '''If we find the login page fingerprint, continue to auth'''
        if(self.fprintPage in fingerprintResponse.content):
            utility.Msg("Matched {0} fingerprint at: {1}".format(self.name,host+":"+port+fprintPageUrl),'INFO')
            if(self.doAuth):
                for creds in self.loginData:
                    utility.Msg("Authenticating with {0}".format(str(creds)),'DEBUG')
                    loginResponse = make_request(self.checkLoginMethod,host,port,ssl,loginUrl,creds,self.followLoginRedirects)
                    if loginResponse == None:
                        return False
                    utility.Msg("Received authentication response: {0}".format(loginResponse),'DEBUG')
                    responseData = getattr(loginResponse,self.fprintSuccessLocation)

                    '''If the response data is a string, check for the fingerprint'''
                    if(type(responseData).__name__ == 'unicode'):
                        if(self.fprintSuccess in responseData):
                            utility.Msg("Authentication response data: {0}".format(responseData.encode('utf-8')),'DEBUG')                    
                            self.foundCreds = creds
                            self.foundUrl = loginUrl
                            return True
                        else:
                            utility.Msg("Fingerprint \"{0}\" did not match in data {1}".format(self.fprintSuccess,responseData.encode('utf-8')),'DEBUG')                    

                    elif(type(responseData).__name__ == 'CaseInsensitiveDict'):
                        if(self.fprintSuccess in str(responseData)):
                            utility.Msg("Authentication response data: {0}".format(responseData),'DEBUG')                    
                            self.foundCreds = creds
                            self.foundUrl = loginUrl
                            return True
                        else:
                            utility.Msg("Fingerprint \"{0}\" did not match in data {1}".format(self.fprintSuccess,responseData),'DEBUG')                    



                '''If we haven't returned true yet, must be no creds that work'''
                return False
        else:
            utility.Msg("Fingerprint \"{0}\" not found in response".format(self.fprintPage),'DEBUG')

    def _doBasicAuth(self,host,port,ssl,loginUrl):
        for creds in self.loginData:
            utility.Msg("Doing Basic auth to {0} with {1}".format(loginUrl,str(creds)),'DEBUG')
            basicCreds = {'username':creds[self.usernameField],'password':creds[self.passwordField]}
            basicResponse = make_request('BASIC',host,port,ssl,loginUrl,basicCreds,self.followLoginRedirects)
            if basicResponse == None:
                return False
            if(str(basicResponse.status_code) != '401'):
                responseData = getattr(basicResponse,self.fprintSuccessLocation)

                '''If the response data is a string, check for the fingerprint'''
                if(type(responseData).__name__ == 'unicode' and self.fprintSuccess in responseData):
                    utility.Msg("Authentication response data: {0}".format(responseData.encode('utf-8')),'DEBUG')                    
                    self.foundCreds = creds
                    self.foundUrl = loginUrl
                    return True
                elif(type(responseData).__name__ == 'CaseInsensitiveDict' and self.fprintSuccess in str(responseData)):
                    utility.Msg("Authentication response data: {0}".format(responseData),'DEBUG')                   
                    self.foundCreds = creds
                    self.foundUrl = loginUrl
                    return True

            '''If we haven't returned true yet, must be no creds that work'''
        return False   


    def print_message(self,status,host,port=None):
        if status:
            utility.Msg("Login Success at {0} with {1}".format(host+":"+port+self.foundUrl,self.foundCreds),'SUCCESS')
        else:
            utility.Msg("{0} FAILED on host {1}:{2}".format(self.name,host,port),'DEBUG')

'''
Vulnerability checks that do a simple check in the text of an HTTP Response should
implement this
'''
class HTTPResponseFingerprint(VulnerabilityCheck):
    def __init__(self):
        self.method = 'GET'
        self.url = '/'
        self.fprint=None
        self.fprint_type='positive' #positive matches are a match when something in the response matches fprint. negative match when the response doesn't contain fprint
        self.port=80
        self.data=None
        self.ssl = None


    def check(self,host,port=None,ssl=None):
        if(port == None):
            port = self.port

        ssl = getSSL(self.ssl,ssl,host,port)

        response = make_request(self.method,host,port,ssl,self.url,self.data)
        utility.Msg("Received Response: {0}".format(response),'DEBUG')
        if(self.fprint_type == 'positive'):
            if response is not None and self.fprint in response.content:
                return True
            else:
                return False
        else:
            if response is not None and self.fprint not in response.content:
                return True
            else:
                return False

        return False

'''Vulnerability checks that check for a match in HTTP Headers should implement this'''
class HTTPHeadersFingerprint(VulnerabilityCheck):
    def __init__(self):
        self.method = 'GET'
        self.url = '/'
        self.fprint=None
        self.fprint_type='positive' #positive matches are a match when something in the response matches fprint. negative match when the response doesn't contain fprint
        self.port=80
        self.data=None
        self.ssl = None

    def check(self,host,port=None,ssl=None):
        if(port == None):
            port = self.port
        
        ssl = getSSL(self.ssl,ssl,host,port)

        response = make_request(self.method,host,port,ssl,self.url,self.data)
        utility.Msg("Received Response: {0}".format(response),'DEBUG')
        if(self.fprint_type == 'positive'):
            if response is not None and self.fprint in response.headers:
                return True
            else:
                return False
        else:
            if response is not None and self.fprint not in response.headers:
                return True
            else:
                return False

        return False

'''Vulnerability checks that only care about response status code, use this interface'''
class HTTPResponseCode(VulnerabilityCheck):
    def __init__(self):
        self.method = 'GET'
        self.url = '/'
        self.fprint=None
        self.fprint_type='positive' #positive matches are a match when something in the response matches fprint. negative match when the response doesn't contain fprint
        self.port=80
        self.data=None
        self.ssl = None

    def check(self,host,port=None,ssl=None):
        if(port == None):
            port = self.port

        ssl = getSSL(self.ssl,ssl,host,port)

        response = make_request(self.method,host,port,ssl,self.url,self.data)
        utility.Msg("Received Response: {0}".format(response),'DEBUG')
        if(self.fprint_type == 'positive'):
            if response is not None and  self.fprint in str(response.status_code):
                return True
            else:
                return False
        else:
            if response is not None and  self.fprint not in str(response.status_code):
                return True
            else:
                return False

        return False

def make_request(method,host,port,ssl,url,data,cookies=None,allow_redirects=True):
    response = None
    if port == None and ssl:
        port = 443
    if port == None and not ssl:
        port = 80
    try:
        url = "{0}://{1}:{2}{3}".format("https" if ssl else "http",
                                        host, port,url)
        if method == 'GET':
            response = utility.requests_get(url,cookies=cookies)
        elif method == 'BASIC':
            response = utility.requests_get(url,cookies=cookies,auth=(data['username'],data['password']))
        elif method == 'POST':
            response = utility.requests_post(url,data,cookies=cookies,allow_redirects=allow_redirects)
        elif method == 'HEAD':
            response = utility.requests_head(url,cookies=cookies)
        elif method == 'PUT':
            response = utility.requests_put(url,data,cookies=cookies)
        else:
            response = utility.requests_other(method,url,cookies=cookies)

        return response

    except exceptions.Timeout:
        utility.Msg("Timeout to {0}:{1}".format(host,port), 'DEBUG')
    except exceptions.ConnectionError, e:
        utility.Msg("Connection error to {0} ({1})".format(host,port, e),'DEBUG')

def getSSL(selfSSL,paramSSL,host,port):
    '''Use SSL settings from the module by default. If not specified, we profile based 
    on port number, if not a common port, we will try to autodetect'''
    if (state.auto_ssl):
        retSSL = fingerprintSSL(host,port)
        utility.Msg("Fingerprinted SSL as {0} at URL {1}:{2}".format(str(retSSL),host,str(port)),'DEBUG')
        return retSSL
    elif(paramSSL == None):
        if(selfSSL != None):
            return (selfSSL == 'True')
        else:
            if(str(port) in ['80','8080']):
                return False
            elif(str(port) in ['443','8443']):
                return True
            else:
                retSSL = fingerprintSSL(host,port)
                utility.Msg("Fingerprinted SSL as {0} at URL {1}:{2}".format(str(retSSL),host,str(port)),'DEBUG')
                return retSSL

def fingerprintSSL(host,port):
    try:
        response = utility.requests_get('http://'+host+':'+port)
        return False
    except ConnectionError as e:
        if('BadStatusLine' in str(e)):
            return True
        else:
            return False
    except exceptions.Timeout:
        utility.Msg("Timeout to {0}:{1}".format(host,port), 'DEBUG')
        return None


def randomword(length):
   return ''.join(random.choice(string.lowercase) for i in range(length))
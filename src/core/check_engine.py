import re
import utility
import multiprocessing
import Queue

def worker(checkQueue,tout):
    while True:
        #Try to a check from the queue
        try:            
            curCheck = checkQueue.get(timeout=tout)
            utility.Msg(str(checkQueue.qsize())+' checks remaining','DEBUG')
            check = curCheck[0]
            host_port_ssl = curCheck[1]
            check_status=False
            if(len(host_port_ssl)>1):
                check_status = check.check(host_port_ssl[0],host_port_ssl[1],host_port_ssl[2])
                check.print_message(check_status,host_port_ssl[0],host_port_ssl[1])
            else:
                check_status = check.check(host_port_ssl[0])
                check.print_message(check_status,host_port_ssl[0])

        except Queue.Empty:
            utility.Msg('Check queue is empty, worker quitting.','DEBUG')
            return

def run_checks(options,check_dict):
    if options.file:
        inFile = open(options.file,'r')
        hosts = inFile.readlines()
        inFile.close()
    elif options.check:
        hosts = [options.check]
    elif options.gnmap:
        inFile = open(options.gnmap,'r')
        hosts = parseGnmap(inFile,options.gnmap_http,options.use_nmap_ssl)

    '''Fire up worker threads'''
    checkQueue = multiprocessing.Queue()
    workers = []

    for i in range(options.workers):
        p = multiprocessing.Process(target=worker,
                                    args=(checkQueue,options.worker_timeout))
        workers.append(p)
        p.start()


    '''For each host:port combo, run the specified checks'''
    for host in hosts:
        host_port_ssl = host.split(':')
        if(len(host_port_ssl)==2):
            host_port_ssl.append(None)
        elif(host_port_ssl[2].lower() == 'true'):
            host_port_ssl[2] = True
        else:
            host_port_ssl[2] = False

        for category in check_dict:
            category_checks = check_dict[category]
            for check in category_checks:
                for opt_check in options.run_checks:
                    opt_check = opt_check.replace('*','.*')
                    if(re.match('^'+opt_check+'$',check.name)):
                        '''Begin adding checks to the queue'''
                        checkQueue.put([check,host_port_ssl])
    
    '''Finish up with workers'''
    for p in workers:
        p.join()



'''Check to see if a specified gnmap file is of the right type'''
def detectFileType(inFile):
    firstLine = inFile.readline()
    secondLine = inFile.readline()
    thirdLine = inFile.readline()

    #Be polite and reset the file pointer
    inFile.seek(0)

    if (firstLine.find('nmap') != -1 and thirdLine.find('Host:') != -1):
        #Looks like a gnmap file - this wont be true for other nmap output types
        #Check to see if -sV flag was used, if not, warn
        if(firstLine.find('-sV') != -1 or firstLine.find('-A') != -1):
            return 'gnmap'
        else:
            utility.Msg("NMap version detection not used in scan, HTTP service filtering and ssl detection may produce inaccurate results",'INFO')            
            return 'gnmap'
    else:
        return None

'''
Parse a gnmap file into a dictionary. The dictionary key is the ip address or hostname.
Each key item is a list of ports and whether or not that port is https/ssl. For example:
>>> targets
{'127.0.0.1': [[443, True], [8080, False]]}
'''
def parseGnmap(inFile,httpOnly,useNmapSSL):
    if(detectFileType(inFile) == 'gnmap'):
        targets = []
        for hostLine in inFile:
            #Pull out the IP address (or hostnames) and HTTP service ports
            fields = hostLine.split(' ')
            ip = fields[1] #not going to regex match this with ip address b/c could be a hostname
            for item in fields:
                if(httpOnly):
                    #Make sure we have an open port with an http type service on it
                    if item.find('http') != -1 and re.findall('\d+/open',item):
                        port = None
                        https = False
                        '''
                        nmap has a bunch of ways to list HTTP like services, for example:
                        8089/open/tcp//ssl|http
                        8000/closed/tcp//http-alt///
                        8008/closed/tcp//http///
                        8080/closed/tcp//http-proxy//
                        443/open/tcp//ssl|https?///
                        8089/open/tcp//ssl|http
                        Since we want to detect them all, let's just match on the word http
                        and make special cases for things containing https and ssl when we
                        construct the URLs.
                        '''
                        port = item.split('/')[0]

                        if item.find('https') != -1 or item.find('ssl') != -1:
                            https = True
                        #Add the current service item to the currentTarget list for this host
                        if(useNmapSSL):
                            targets.append(ip+":"+port+":"+str(https))
                        else:
                            targets.append(ip+":"+port)
                else:
                    if item.find('tcp') != -1 and re.findall('\d+/open',item):
                        port = None
                        ssl = False
                        port = item.split('/')[0]

                        if item.find('https') != -1 or item.find('ssl') != -1:
                            ssl = True
                        #Add the current service item to the currentTarget list for this host
                        if(useNmapSSL):
                            targets.append(ip+":"+port+":"+str(ssl))
                        else:
                            targets.append(ip+":"+port)

        return targets
    else:
        utility.Msg('Nmap file is not of type gnmap','ERROR')
        return []

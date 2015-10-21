#!/usr/bin/python
import sys
from os import getcwd, mkdir, path
sys.path.insert(0, getcwd() + '/src/core/')
import utility
import argparse
import state
import check_engine


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--timeout",type=int,default=10,help='Time to wait for pageload before killing connections')
    parser.add_argument("-d","--debug",action='store_true',default=False,help='Enable debugging output')
    parser.add_argument("-r","--run_checks",nargs='+',default=None,help='Specify the check (or checks) to run by name, supports * wildcard')
    parser.add_argument("-c","--check",default=None,help="Specify a single host:port:(ssl_true) to run checks on if no port specified, default used, if ssl not specified, default False")
    parser.add_argument("-f","--file",default=None,help="Specify a list of hosts:ports to run checks on, if no port port specified, default used")
    parser.add_argument("-p","--proxy",default=None,help="HTTP Proxy in format http://<host>:<port>")
    parser.add_argument("-g","--gnmap",default=None,help="Specify a gnmap file for parsing - all hosts and ports will be added to the targets list")
    parser.add_argument("-gS","--use_nmap_ssl",action='store_true',help="Set this flag to rely on NMAP SSL detection. Often quite unreliable.")    
    parser.add_argument("-aS","--auto_ssl",action='store_true',help="Set this flag to force auto SSL detection regardless of what is specified in the modules")    
    parser.add_argument("-gH","--gnmap_http",action='store_true',help="Set this flag to only parse HTTP type services from gnmap input")
    parser.add_argument("-rD","--reload_database",action='store_true',help="If this flag is set, all framework databases (default creds, etc) will be reloaded and framework will exit")
    parser.add_argument("-w","--workers",type=int,default=1,help='Number of worker threads to spin up')
    parser.add_argument("-wT","--worker_timeout",type=int,default=5,help='Timeout for threads in seconds')
    parser.add_argument("-nD","--no_defaults",action='store_true',help="Set this flag to disable default credential checking when credentials are specifiedo on the CLI")
    parser.add_argument("-cL","--credential_list",default=None,help="Specify credentials to test in username:password format. Accepts files or single set of credentials.")

    options = parser.parse_args()

    '''
    Todo:
    Set state variables based on options input, e.g: proxy, ssl, timeout, debug...
    '''
    state.isdebug = options.debug
    state.proxy = options.proxy
    state.credentials = options.credential_list
    state.no_defaults = options.no_defaults
    state.auto_ssl = options.auto_ssl

    if(options.reload_database):
        utility.reload_databases()
        utility.Msg("Exiting. Run again without -rD flag for updated content.","INFO")
        sys.exit(0)

    '''Get a dictionary of the currently implemented checks.'''
    check_dict = utility.get_checks()

    '''If there were no --run_checks arguments or hosts provided, print the help and the 
    available vulnerability checks'''
    if((options.check == None and options.file == None and options.gnmap == None) or options.run_checks == None):
        parser.print_help()
        print('\nAvailable vulnerability checks:\n')
        utility.print_checks(check_dict)
        sys.exit(0)

    
    check_engine.run_checks(options,check_dict)


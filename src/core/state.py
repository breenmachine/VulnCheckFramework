'''
Framework wide defaults. These should be changable with CLI options, not all are
implemented as arguments.
'''
# proxy to use for outgoing connections
proxy = None

# if necessary, authentication credentials for the aforementioned
# proxy.  This should be in the format username:password
proxy_auth = None

# credentials to authenticate to the service with.  This should be in
# the form username:password
usr_auth = None

# whether or not we are dumping debug strings
isdebug = True

# connection timeout to remote hosts
timeout = 5.0

# wordlist for brute forcing credentials
bf_wordlist = None

# with a loaded wordlist, use the following user to brute force
bf_user = None

# we don't want to brute force services more than once; resets after
# each service
hasbf = False

# if we're using a random User-Agent for requests, set that here
random_agent = None

# filename for logging to file
flog = None

# restrict http authentication attempts to ports defined in modules
http_login_restrict_ports = True

# User defined list of credentials
credentials = None

# Specify whether to disable default credential checks when credentials are specified
no_defaults = False

# Specify whether to foce auto SSL detection
auto_ssl = False
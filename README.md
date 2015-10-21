=== PWNMeNot ===

PWNMeNot is a python framework for default credential checking and vulnerability verification.

This file serves as documentation and example usage for the framework.

==Basic Usage==

Running ./VulnChecks.py will print the help menu. For sample usages, see the following sections.

==Default Credential Checking==

Currently the most actively developed and unique feature of the framework is the default HTTP credential checking module.

Given a list of hosts/ports or NMAP output as an input, the framework will identify and optionally attempt authentication using known default credentials to all services for which it contains a match.

For example, to run all default credential modules on the results of an NMAP scan, one could use the following command:

./VulnChecks.py -r http_login* -g input.gnmap -w 10

In the event that the user has a set of known credentials and would like to test them on all modules, the following command would add the user specified credentials to be the first set of credentials checked by each module:

./VulnChecks.py -r http_login* -g input.gnmap -w 10 -cL <file>
or
./VulnChecks.py -r http_login* -g input.gnmap -w 10 -cL user:password

To disable default credential checks and only check the user-specified credentials, the -nD flag can be used

==Basic Structure/Architecture==

The framework makes extensive use of plugins for easy scalability. Plugins should contain no code and simply define DATA. Plugins can be found in /src/modules/<type>/checks/. 

Each plugin is associated with an interface. For example, the http_login checks implement the HTTPAuthenticationTest interface, you can see this in the class definition:
    "class VCheck(HTTPAuthenticationTest):"

The interfaces are defined in "interfaces.py" for each category of modules. For example, all HTTP modules share the same "interfaces.py". The interface is where the 'magic' happens, specifically the "check" method of each class in the interface, this is the code that is run to actually conduct the test using the data defined in the modules.

The framework is threaded, each worker thread takes one "check" at a time out of the pool and runs it. A "check" is everything defined in a single module for a single host/port combination. For example, if there are 10 sets of WebSphere default credentials to test, all defined in ONE module, that will be one check and run on one thread. If they are split up by version and defined in different modules, different threads will run the checks. The number of workers can be specified on the CLI.

==Module Development==

Module development has been kept as simple as possible to encourage extensions. Modules should NEVER need to define code, only data. As such, it is possible to generate modules from an XML specification.

XML Module generation is currently only supported for HTTPAuthenticationTest. Any file in the "credentialDatabase" folder will be scanned for module definitions when the framework is run as follows:

./VulnChecks.py -rD

This will regenerate modules given the XML specifications.

The following is an example breakdown of all of the fields currently available:

    <modules> - The root node. Required.

    <module> - Each module must be wrapped in a module tag. Required.

    <name>http_login_wsadmin-8</name> - Module name, a file <module name>.py will be generated using this. Required.

    <port_range>9040-9050,9060-9070</port_range> - The list/range of ports this module applies to. The "fingerprint" check will be run on all hosts with these ports open. Required
    
    <fprintPageUrl>/ibm/console/logon.jsp</fprintPageUrl> - This is the URL where we will do our fingerprint to check if it's the right service before trying to authenticate. Required.

    <fprintPage>WebSphere Integrated Solutions Console</fprintPage> - If this text occurs in the fprintPageUrl response body, then we have a match and will try to authenticate. Required

    <fprintMethod>GET</fprintMethod> - The HTTP method to use for the fingerprint. Optional - default GET.

    <loginUrl>/ibm/console/j_security_check</loginUrl> - The URL where we will post login credentials. Required.

    <usernameField>j_username</usernameField> - The name for the username parameter in the login request. Required.
    
    <passwordField>j_password</passwordField> - The name for the password parameter in the login request. Required. 

    <loginData> - Root node for a set of credentials to test. Required.
        <param> - Root node to start specifying a parameter. Required.
            <name>j_username</name> - Parameter name. Required
            <value>root</value> - Parameter value. Required.
        </param>
        <param>
            <name>j_password</name>
            <value></value>
        </param>
        <param>
            <name>action</name>
            <value>Log+in</value>
        </param>
    </loginData>
    <loginData>
        <param>
            <name>j_username</name>
            <value>root</value>
        </param>
        <param>
            <name>j_password</name>
            <value>root</value>
        </param>
        <param>
            <name>action</name>
            <value>Log+in</value>
        </param>
    </loginData>
                
    <fprintSuccess>LtpaToken2</fprintSuccess> - A string to detect in the login response to know that we authenticated successfully. Required

    <fprintSuccessLocation>headers</fprintSuccessLocation> - Where the fprintSuccess string will be. Optional - defaults to 'text' which is the response body.

    <checkLoginMethod>POST</checkLoginMethod> - HTTP Method to use for authentication. Optional. Default is POST
    
    <ssl>True</ssl> - Should this module use SSL by default? Optional, default False

    <doAuth>True</doAuth> - Should this module be used to test for DEFAULT credentials? This should be set to false if there are no default credentials and only user specified credentials should be used where the module simply defines the parameter names and blank values. Optional. Default True
    
    </module> - Closing tags...
    </modules>


For non-xml supported modules, the fields will need to be defined as dictated by the class in the interfaces.py file.
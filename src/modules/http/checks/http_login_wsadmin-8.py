from src.modules.http.interfaces import HTTPAuthenticationTest
class VCheck(HTTPAuthenticationTest):
	def __init__(self):
		super(VCheck, self).__init__()
		self.loginData=[]
		self.urls=[]
		self.name = 'http_login_wsadmin-8'
		self.port_range = '9040-9050,9060-9070'
		self.urls.append({'fprintPageUrl':'/ibm/console/logon.jsp','loginUrl':'/ibm/console/j_security_check',})
		self.fprintPage = 'WebSphere Integrated Solutions Console'
		self.fprintMethod = 'GET'
		self.usernameField = 'j_username'
		self.passwordField = 'j_password'
		self.loginData.append({'j_username':'root','j_password':'','action':'Log+in',})
		self.loginData.append({'j_username':'root','j_password':'root','action':'Log+in',})
		self.checkLoginMethod = 'POST'
		self.fprintSuccess = 'LtpaToken2'
		self.fprintSuccessLocation = 'headers'
		self.ssl = 'True'
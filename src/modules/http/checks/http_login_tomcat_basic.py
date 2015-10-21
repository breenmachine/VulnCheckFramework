from src.modules.http.interfaces import HTTPAuthenticationTest
class VCheck(HTTPAuthenticationTest):
	def __init__(self):
		super(VCheck, self).__init__()
		self.loginData=[]
		self.urls=[]
		self.name = 'http_login_tomcat_basic'
		self.port_range = '8080'
		self.urls.append({'loginUrl':'/manager/html',})
		self.checkLoginMethod = 'BASIC'
		self.passwordField = 'password'
		self.usernameField = 'username'
		self.loginData.append({'username':'tomcat','password':'tomcat',})
		self.loginData.append({'username':'tomcat','password':'s3cret',})
		self.fprintSuccess = 'Tomcat Web Application Manager'
		self.ssl = 'False'
		self.doAuth = True
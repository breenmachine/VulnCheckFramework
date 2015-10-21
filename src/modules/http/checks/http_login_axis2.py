from src.modules.http.interfaces import HTTPAuthenticationTest
class VCheck(HTTPAuthenticationTest):
	def __init__(self):
		super(VCheck, self).__init__()
		self.loginData=[]
		self.urls=[]
		self.name = 'http_login_axis2'
		self.port_range = '8080'
		self.urls.append({'fprintPageUrl':'/axis2/axis2-admin/','loginUrl':'/axis2/axis2-admin/login',})
		self.fprintPage = 'Welcome to the Axis2 administration console'
		self.fprintMethod = 'GET'
		self.usernameField = 'userName'
		self.passwordField = 'password'
		self.loginData.append({'userName':'admin','password':'axis2','submit':'+Login+',})
		self.checkLoginMethod = 'POST'
		self.fprintSuccess = 'Welcome to Axis2 Web Admin Module'
		self.fprintSuccessLocation = 'text'
		self.ssl = 'False'
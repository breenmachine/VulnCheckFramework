from src.modules.http.interfaces import HTTPAuthenticationTest
class VCheck(HTTPAuthenticationTest):
	def __init__(self):
		super(VCheck, self).__init__()
		self.loginData=[]
		self.urls=[]
		self.name = 'http_login_easy_file_sharing_web_server'
		self.port_range = '80'
		self.urls.append({'fprintPageUrl':'/login.htm','loginUrl':'/forum.ghp',})
		self.fprintPage = 'Login - powered by Easy File Sharing Web Server'
		self.fprintMethod = 'GET'
		self.checkLoginMethod = 'POST'
		self.usernameField = 'Username:'
		self.passwordField = 'Password:'
		self.loginData.append({'frmLogin':'true','frmUserName':'Admin','frmUserPass':'sa123','login':'Login%21',})
		self.fprintSuccess = 'Virtual Folders'
		self.ssl = 'False'
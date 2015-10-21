from src.modules.http.interfaces import HTTPAuthenticationTest
class VCheck(HTTPAuthenticationTest):
	def __init__(self):
		super(VCheck, self).__init__()
		self.loginData=[]
		self.urls=[]
		self.name = 'http_login_phpmyadmin'
		self.port_range = '80'
		self.urls.append({'fprintPageUrl':'/phpmyadmin/index.php','loginUrl':'/phpmyadmin/index.php',})
		self.fprintPage = 'phpMyAdmin'
		self.fprintMethod = 'GET'
		self.checkLoginMethod = 'POST'
		self.usernameField = 'pma_username'
		self.passwordField = 'pma_password'
		self.loginData.append({'pma_username':'root','pma_password':'password',})
		self.fprintSuccess = 'Server charset'
		self.fprintSuccessLocation = 'text'
		self.followLoginRedirects = True
		self.ssl = 'false'
from src.modules.http.interfaces import HTTPAuthenticationTest
class VCheck(HTTPAuthenticationTest):
	def __init__(self):
		super(VCheck, self).__init__()
		self.loginData=[]
		self.urls=[]
		self.name = 'http_login_drupal'
		self.port_range = '80'
		self.urls.append({'fprintPageUrl':'/node?destination=node','loginUrl':'/node?destination=node',})
		self.fprintPage = 'User login'
		self.fprintMethod = 'GET'
		self.checkLoginMethod = 'POST'
		self.usernameField = 'name'
		self.passwordField = 'pass'
		self.loginData.append({'name':'admin','pass':'admin','form_id':'user_login_block','form_build_id':'form_','op':'Log+in',})
		self.followLoginRedirects = True
		self.fprintSuccess = 'My account'
		self.ssl = 'false'
from src.modules.http.interfaces import HTTPAuthenticationTest
class VCheck(HTTPAuthenticationTest):
	def __init__(self):
		super(VCheck, self).__init__()
		self.loginData=[]
		self.urls=[]
		self.name = 'http_login_wordpress'
		self.port_range = '80'
		self.urls.append({'fprintPageUrl':'/wordpress/wp-login.php','loginUrl':'/wordpress/wp-login.php',})
		self.urls.append({'fprintPageUrl':'/wp-login.php','loginUrl':'/wp-login.php',})
		self.fprintPage = 'Log In'
		self.fprintMethod = 'GET'
		self.checkLoginMethod = 'POST'
		self.usernameField = 'log'
		self.passwordField = 'pwd'
		self.loginData.append({'log':'admin','pwd':'admin','wp-submit':'Log+In',})
		self.followLoginRedirects = True
		self.fprintSuccess = 'wordpress_logged_in'
		self.fprintSuccessLocation = 'headers'
		self.ssl = 'false'
from src.modules.http.interfaces import HTTPAuthenticationTest
class VCheck(HTTPAuthenticationTest):
	def __init__(self):
		super(VCheck, self).__init__()
		self.loginData=[]
		self.urls=[]
		self.name = 'http_login_railo-41_web'
		self.port_range = '8888'
		self.urls.append({'fprintPageUrl':'/railo-context/admin/web.cfm','loginUrl':'/railo-context/admin/web.cfm',})
		self.fprintPage = 'Railo Technologies GmbH Switzerland'
		self.fprintMethod = 'GET'
		self.checkLoginMethod = 'POST'
		self.passwordField = 'login_passwordweb'
		self.loginData.append({'login_passwordweb':'','lang':'en',})
		self.fprintSuccess = 'Memory Usage'
		self.ssl = 'False'
		self.doAuth = False
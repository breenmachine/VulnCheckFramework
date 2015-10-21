from src.modules.http.interfaces import AutoHTTPForm

class VCheck(AutoHTTPForm):
    def __init__(self):
        super(VCheck, self).__init__()
        self.name="http_auto_login"
        self.usernameFieldList = ['user','username','userid','login','id','email']

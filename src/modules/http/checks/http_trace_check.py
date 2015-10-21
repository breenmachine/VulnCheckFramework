from src.modules.http.interfaces import HTTPResponseCode

class VCheck(HTTPResponseCode):
    def __init__(self):
        super(VCheck, self).__init__()
        self.method='TRACE'
        self.fprint='405'
        self.name='http_trace_check'
        self.fprint_type='false'

from n4d.client import Client
from n4d.client import CallFailedError

from llxgvagate.base_plugin import BasePlugin
from llxgvagate.error import GvaGateError

class Adi (BasePlugin):
    def __init__(self):
        pass
    
    @property
    def name(self):
        return "adi"

    def authenticate(self, username, password):
        n4d_local = Client("https://localhost:9779")
        try:
            server = n4d_local.get_variable('SRV_IP')
        except Exception:
            return None, GvaGateError.ServerNotFound
        if server is not None:
            n4d_remote = Client("https://"+server+":9779")
            try:
                result = n4d_remote.GvaGate.validate_id_user(username, password)
            except CallFailedError as e:
                if e.code == -10 or e.code == -11 or e.code == -20:                    
                    return None, GvaGateError.Unauthorized 
                else:
                    return None, GvaGateError.InvalidResponse
            except Exception:
                # Adi not found
                return None, GvaGateError.InvalidResponse
        else:
            return None, GvaGateError.ServerNotFound
        return result, GvaGateError.Allowed

from n4d.client import Client
from n4d.client import CallFailedError


class Adi:
    def __init__(self):
        pass

    def auth_adi(self, username, password):
        n4d_local = Client("https://localhost:9779")
        try:
            server = n4d_local.get_variable('SRV_IP')
        except Exception:
            return None, "temporary_unavailable"
        if server is not None:
            n4d_remote = Client("https://"+server+":9779")
            try:
                result = n4d_remote.GvaGate.validate_id_user(username, password)
            except CallFailedError as e:
                if e.code == -10 or e.code == -11 or e.code == -20:                    
                    return None, "invalid_grant"
                else:
                    return None, "invalid_response"
            except Exception:
                # Adi not found
                return None, "invalid_response"
        else:
            return None, "temporary_unavailable"
        return result, None

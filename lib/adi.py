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
            self.process_exit_error("temporary_unavailable")
        if server is not None:
            n4d_remote = Client("https://"+server+":9779")
            try:
                result = n4d_remote.GvaGate.validate_id_user(username, password)
                user = self.populate_user_object(result)
            except CallFailedError as e:
                if e.code == -10:
                    sys.exit(1)
                if e.code == -11:
                    sys.exit(3)
                if e.code == -20:
                    sys.exit(2)
            except Exception:
                # Adi not found
                sys.exit(14)
        print(user)

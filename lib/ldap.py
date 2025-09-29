from pathlib import Path


class Ldap:

    def __init__(self):
        pass

    def load_ldap_config(self):
        credentials_path = Path("/etc/cdc/configuration")
        if credentials_path.exists():
            with credentials_path.open("r") as fd:
                user_bind = fd.readline().strip()
                passwd_bind = fd.readline().strip()
                base_dn = fd.readline().strip()
                ldap_uri = fd.readline().strip()
        else:
            user_bind = ""
            passwd_bind = ""
            base_dn = ""
            ldap_uri = ""
        return {
                "user_bind": user_bind,
                "passwd_bind": passwd_bind,
                "base_dn": base_dn,
                "ldap_uri": ldap_uri
                }

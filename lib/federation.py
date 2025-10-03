from msal import PublicClientApplication
from pathlib import Path
from yaml import safe_load
from llxfederation.user import User, Group
from llxfederation.mapper import SSSDMapper


class Federation:

    group_schemas_name = "https://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid"

    def __init__(self):
        self.config_path = Path("/etc/gvagate/config.yml")
        self.default_user_struc = {"upn": "",
                                   "given_name": "",
                                   "family_name": "",
                                   }

    def load_config(self) -> None:
        '''
        Load default config and replace values with customization on /etc/gvagate/config.yml
        '''
        default_config = {
                       "id_app": "",
                       "url_auth": "",
                       "global_domain": "",
                       "student_domain_prefix": ""
                    }
        aux_config = {}
        if self.config_path.exists():
            with self.config_path.open("r", encoding="utf-8") as fd:
                aux_config = safe_load(fd)
        self.config = default_config | aux_config

    def populate_user_object(self, result):
        s = SSSDMapper()
        data = self.default_user_struc.copy()
        data.update(result)
        user = User(data["upn"].split("@")[0])
        user.name = data["given_name"]
        user.surname = data["family_name"]
        user.uid = s.get_unix_uid_from_sid(result["primarysid"])
        for x in range(0, len(data["group"])):
            try:
                g = Group(data["group"][x])
                g.gid = s.get_unix_uid_from_sid(data[Federation.group_schemas_name][x])
                user.group.append(g)
            except Exception:
                pass
        user.populate_user()
        return user

    def auth_federation(self, username, password):
        self.load_config()
        result = {}
        user = None
        try:
            app = PublicClientApplication(self.config["id_app"],
                                          authority=self.config["url_auth"])
        except Exception:
            return None, "temporary_unavailable"
        try:
            result = app.acquire_token_by_username_password(
                username,
                password,
                scopes=["https://lliurex.login/openid"]
            )
            if "error" in result.keys():
                return None, result["error"]
            if "id_token_claims" in result.keys():
                user = self.populate_user_object(result["id_token_claims"])
            else:
                return None, "invalid_response"
        except Exception:
            return None, "undefined_error"

        return user, None

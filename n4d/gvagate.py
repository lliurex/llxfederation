import bcrypt
import bson
from pathlib import Path
from yaml import safe_load
import n4d.responses
from time import time
from random import randrange
from llxfederation.ad import Ldap
from llxfederation.federation import Federation

class GvaGate:

    USER_NOT_IN_CACHE = -10
    USER_CACHE_EXPIRED = -11
    PASSWORD_INVALID = -20
    WRONG_SAVE = -30
    SERVER_UNREACHABLE = -50

    def __init__(self) -> None:
        self.app = None
        self.config_path = Path("/etc/gvagate/config.yml")
        self.load_config()
        self.cache_path = Path(self.config["cache_path"])

    def load_config(self) -> None:
        '''
        Load default config and replace values with customization
        on /etc/gvagate/config.yml
        '''
        default_config = {
                       "id_app": "",
                       "url_auth": "",
                       "cache_path": "",
                       "expire_time": 72
                    }
        aux_config = {}
        if self.config_path.exists():
            with self.config_path.open("r", encoding="utf-8") as fd:
                aux_config = safe_load(fd)
        self.config = default_config | aux_config

    def validate_id_user(self, username, password) -> n4d.responses:
        user = self.load_user(username.split("@")[0])
        if user is None:
            return n4d.responses.build_failed_call_response(GvaGate.USER_NOT_IN_CACHE)
        if time() > user["expire"]:
            self.remove_entry(user)
            return n4d.responses.build_failed_call_response(GvaGate.USER_CACHE_EXPIRED)
        result = bcrypt.checkpw(password.encode(), user["hash"])
        if result:
            user.pop("hash", None)
            user.pop("expire", None)
            user.pop("refresh_ad", None)
            return n4d.responses.build_successful_call_response(user["info"])
        return n4d.responses.build_failed_call_response(GvaGate.PASSWORD_INVALID)

    def store_id_user(self, username, password, method):
        
        if not self.user_need_update(username, password):
            return n4d.responses.build_successful_call_response(True)

        if method == "id":
            f_provider = Federation()
            user, error = f_provider.auth_federation(username, password)
        else:
            l_provider = Ldap()
            user, error = l_provider.auth_cdc(username, password)

        if user is not None:
            user_info = {}
            user_info['info'] = user
            salt = bcrypt.gensalt()
            pass_hash = bcrypt.hashpw(password.encode(), salt)
            user_info["hash"] = pass_hash
            user_info["expire"] = time() + (60 * 60 * self.config["expire_time"])
            user_info["refresh_ad"] = time() + (60 * 60 * randrange(1, self.config["expire_time"]) )
            if self.save_info(user_info):
                return n4d.responses.build_successful_call_response(True)
            else:
                return n4d.responses.build_failed_call_response(GvaGate.WRONG_SAVE)
        return n4d.responses.build_failed_call_response(error)

    def user_need_update(self, username, password):

        user = self.load_user(username.split("@")[0])
        if user is None:
            return True

        if not bcrypt.checkpw(password.encode(), user["hash"]):
            return True

        if time() > user["refresh_ad"]:
            return True

        user.pop("hash")
        user.pop("expire")
        user.pop("refresh_ad")

        return False

    def save_info(self, info):
        self.exists_or_build_cache()
        try:
            with self.cache_path.open("br") as fd:
                cache = bson.decode(fd.read())
        except Exception:
            cache = {}
        try:
            login = info["info"].login
            patch_info = str(info['info'])
            info["info"] = patch_info 
            cache[login] = info
            with self.cache_path.open("bw") as fd:
                fd.write(bson.encode(cache))
            return True
        except Exception:
            return False

    def remove_entry(self, username):
        self.exists_or_build_cache()
        try:
            with self.cache_path.open("br") as fd:
                cache = bson.decode(fd.read())
            if username in cache:
                del cache[username]
            with self.cache_path.open("bw") as fd:
                fd.write(bson.encode(cache))
            return True
        except Exception:
            return False

    def load_user(self, username):
        if not self.cache_path.exists():
            return None
        if self.cache_path.stat().st_size == 0:
            return None
        with self.cache_path.open("br") as fd:
            cache = bson.decode(fd.read())
        if username in cache:
            return cache[username]
        return None

    def exists_or_build_cache(self):
        if not self.cache_path.parent.exists():
            self.cache_path.parent.mkdir(parents=True,
                                         exist_ok=True,
                                         mode=0o700)
        if not self.cache_path.exists():
            self.cache_path.touch(mode=0o600)
            self._wipe_cache()
        return True

    def wipe_cache(self):
        self.exists_or_build_cache()
        self._wipe_cache()
        return n4d.responses.build_successful_call_response(True)

    def _wipe_cache(self):
        with self.cache_path.open("bw") as fd:
            fd.write(bson.encode({}))

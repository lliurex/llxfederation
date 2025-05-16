from msal import PublicClientApplication
import bcrypt
import bson
from pathlib import Path
from yaml import safe_load
import n4d.responses
from time import time
from random import randrange 
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
        Load default config and replace values with customization on /etc/gvagate/config.yml
        '''
        default_config = { 
                       "id_app": "",
                       "url_auth" :"",
                       "cache_path": "",
                       "expire_time": 72
                    }
        aux_config = {}
        if self.config_path.exists():
            with self.config_path.open("r",encoding="utf-8") as fd:
                aux_config = safe_load(fd)
        self.config = default_config | aux_config

    def connect(self) -> bool:
        '''
        set up connection with federation service with id_app and url_auth
        '''
        try:
            self.app = PublicClientApplication( self.config["id_app"], 
                                                authority = self.config["url_auth"],
                                                timeout=10 )
        except Exception:
            self.app = None
            return False
        return True


    def validate_id_user(self,user, password) -> n4d.responses:
        user = self.load_user(user)
        if user is None:
            return n4d.responses.build_failed_call_response(GvaGate.USER_NOT_IN_CACHE)
        if time() > user["expire"]:
            self.remove_entry(user)
            return n4d.responses.build_failed_call_response(GvaGate.USER_CACHE_EXPIRED)
        result = bcrypt.checkpw(password.encode(), user["hash"])
        if result:
            user.pop("hash",None)
            user.pop("expire",None)
            user.pop("refresh_ad",None)
            return n4d.responses.build_successful_call_response(user)
        return n4d.responses.build_failed_call_response(GvaGate.PASSWORD_INVALID)

    def store_id_user(self, user_info, password, ticket):
    
        if not self.user_need_update(user_info, password):
            return n4d.responses.build_successful_call_response(True)

        if self.app is None:
            if not self.connect():
                return n4d.responses.build_failed_call_response(GvaGate.SERVER_UNREACHABLE)
        try:
            result = self.app.acquire_token_by_refresh_token( ticket, scopes=["https://lliurex.login/openid"] )
        except Exception:
            return n4d.responses.build_failed_call_response(GvaGate.SERVER_UNREACHABLE)

        if "error" not in result.keys():
            ad_user_info = result["id_token_claims"]
            if result["id_token_claims"]["upn"] == user_info["upn"]:
                salt = bcrypt.gensalt()
                pass_hash = bcrypt.hashpw(password.encode(), salt)
                ad_user_info["hash"] = pass_hash
                ad_user_info["expire"] = time() + ( 60 * 60 * self.config["expire_time"] )
                ad_user_info["refresh_ad"] = time() + ( 60 * 60 * randrange( 1 , self.config["expire_time"]) )
            if self.save_info(ad_user_info):
                return n4d.responses.build_successful_call_response(True)
            else:
                return n4d.responses.build_failed_call_response(GvaGate.WRONG_SAVE)
        return n4d.responses.build_failed_call_response(GvaGate.PASSWORD_INVALID)


    def user_need_update(self, user_info, password):

        user = self.load_user(user_info["upn"])
        if user is None:
            return True

        if not bcrypt.checkpw(password.encode(), user["hash"]):
            return True

        if time() > user["refresh_ad"]:
            return True

        user.pop("hash")
        user.pop("expire")
        user.pop("refresh_ad")

        for x in user:
            if user[x] != user_info[x] :
                return True

    

        return False



    def save_info(self, info):
        self.exists_or_build_cache()
        try:
            with self.cache_path.open("br") as fd:
                cache = bson.decode(fd.read())
            cache[info["upn"]] = info
            
            with self.cache_path.open("bw") as fd:
                fd.write(bson.encode(cache))
            return True
        except Exception:
            return False

    def remove_entry(self, entry):
        self.exists_or_build_cache()
        try:
            with self.cache_path.open("br") as fd:
                cache = bson.decode(fd.read())
            if entry in cache:
                del cache[entry]
            
            with self.cache_path.open("bw") as fd:
                fd.write(bson.encode(cache))
            return True
        except Exception:
            return False


    def load_user(self, upn):
        if not self.cache_path.exists():
            return None
        with self.cache_path.open("br") as fd:
            cache = bson.decode(fd.read())
        if upn in cache:
            return cache[upn]
        return None

    def exists_or_build_cache(self):
        if not self.cache_path.parent.exists():
            self.cache_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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


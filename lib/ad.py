from pathlib import Path
import ldap
from llxfederation.user import User, Group
from llxfederation.mapper import SSSDMapper


class Ldap:

    def __init__(self):
        self.conn = None
        self.base_dn = ""
        self.ldap_uri = ""
        self.passwd_bind = ""
        self.user_bind = ""

    def load_config(self) -> None:
        credentials_path = Path("/etc/cdc/configuration")
        if credentials_path.exists():
            with credentials_path.open("r") as fd:
                self.user_bind = fd.readline().strip()
                self.passwd_bind = fd.readline().strip()
                self.base_dn = fd.readline().strip()
                self.ldap_uri = fd.readline().strip()
        else:
            self.user_bind = ""
            self.passwd_bind = ""
            self.base_dn = ""
            self.ldap_uri = ""

    def get_ldap_group_by_sid(self, sid):
        result = {}
        try:
            ldap_result = self.conn.search_s(sid, ldap.SCOPE_BASE)
            result['cn'] = ldap_result[0][1]['cn'][0].decode('utf-8')
            result['sid'] = self.sid_to_str(ldap_result[0][1]["objectSid"][0])
        except Exception:
            result = None
        return result

    def get_ldap_group_by_rid(self, rid):
        result = {}
        try:
            ldap_result = self.conn.search_s(self.base_dn, ldap.SCOPE_BASE)
            base_sid = self.sid_to_str(ldap_result[0][1]['objectSid'][0])
            group_sid = base_sid + "-" + str(rid[0].decode('utf-8'))
            groups_result = self.conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE,
                                               "(objectSid={})".format(group_sid))
            for x in groups_result:
                if x[0] is not None:
                    result['cn'] = x[1]['cn'][0].decode('utf-8')
                    result['sid'] = self.sid_to_str(x[1]["objectSid"][0])
        except Exception:
            result = None
        return result

    def sid_to_str(self, sid_bytes):
        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')
        sub_authorities = [
            int.from_bytes(sid_bytes[8 + i*4:12 + i*4], byteorder='little')
            for i in range(sub_authority_count)
        ]
        return f"S-{revision}-{identifier_authority}-" + "-".join(map(str, sub_authorities))

    def set_user_info_to_ldap_result(self, user_info):
        upn = ""
        for x in ["userPrincipalName", "sAMAccountName"]:
            if x in user_info:
                upn = user_info[x][0].decode('utf-8')
                break
        given_name = ""
        for x in ["givenName", "displayName"]:
            if x in user_info:
                if x == "displayName":
                    given_name = user_info[x][0].decode('utf-8').split(",")[1].strip()
                    break
                if x == "givenName":
                    given_name = user_info[x][0].decode('utf-8')
                    break
        family_name = ""
        for x in ["sn", "displayName"]:
            if x in user_info:
                if x == "displayName":
                    family_name = user_info[x][0].decode('utf-8').split(",")[0].strip()
                    break
                if x == "sn":
                    family_name = user_info[x][0].decode('utf-8')
                    break

        primarysid = self.sid_to_str(user_info["objectSid"][0])
        user = User(upn)
        user.name = given_name
        user.surname = family_name
        user.uid = primarysid
        return user

    def search_user_by_username(self, needle):
        needle = "(sAMAccountName={})".format(needle)
        r = self.conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, needle)
        user_info = None
        for x in r:
            if x[0] is not None:
                user_info = x[1]
        return user_info

    def populate_user(self, user_info):
        user = self.set_user_info_to_ldap_result(user_info)
        group_list = []
        for g_item in user_info["memberOf"]:
            item = self.get_ldap_group_by_sid(g_item.decode('utf-8'))
            if item is not None:
                group_list.append(item)
        if (res := self.get_ldap_group_by_rid(user_info['primaryGroupID'])) is not None:
            group_list.append(res)
        user.populate_user()
        return user

    def auth_cdc(self, user, password):
        self.load_config()
        try:
            self.conn = ldap.initialize(self.ldap_uri)
            self.conn.protocol_version = 3
            self.conn.set_option(ldap.OPT_REFERRALS, 0)
        except Exception:
            return None, "temporary_unavailable"
        try:
            self.conn.simple_bind_s(self.user_bind, self.passwd_bind)
            user_info = self.search_user_by_username(user.split("@")[0])
            if user_info is not None:
                user = self.populate_user(user_info)
                try:
                    self.conn.simple_bind_s(user, password)
                except Exception as e:
                    if e.args[0]['result'] == 49:
                        return None, "invalid_grant"
            else:
                return None, "invalid_grant"
        except Exception:
            # Undefined Error
            return None, "undefined_error"
        return user, None


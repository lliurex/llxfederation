from pathlib import Path
import json
import grp
from functools import reduce
import murmurhash.mrmr as mrmr


class CdcMapper:

    STUDENTS = 1
    TEACHERS = 2
    ADMINS = 4

    def __init__(self) -> None:
        self.groups_folders = [
            Path("/usr/share/cdc-mapper/groups"),
            Path("/etc/cdc-mapper"),
        ]
        self.alu_groups = []
        self.doc_groups = []
        self.adm_groups = []
        self.default_info = {"alu": False, "doc": False, "adm": False}

    def check_json(self, info):
        if "name" not in info.keys():
            return False
        return True

    def get_groups(self, user_mode):
        groups = []
        for folder_path in self.groups_folders:
            if not folder_path.exists():
                continue
            for file_path in folder_path.iterdir():
                try:
                    with file_path.open("r") as fd:
                        temp_info = json.load(fd)
                except Exception:
                    temp_info = None
                if temp_info is not None:
                    # Define default values for info object
                    info = self.default_info.copy()
                    info.update(temp_info)
                    aux = self.process_group(info, user_mode)
                    if aux is not None:
                        groups.append(aux)
        return groups

    def process_group(self, info, mode):
        if not self.check_json(info):
            return None
        args = {"name": info["name"]}
        try:
            args["gid"] = grp.getgrnam(info["name"]).gr_gid
        except Exception:
            if "gid" in info:
                args["gid"] = info["gid"]
            else:
                pass
        if "gid" in info:
            args["default_id"] = info["gid"]
        if "default_gid" in info:
            args["default_gid"] = info["default_gid"]
        if (self.get_mask([info["adm"], info["doc"], info["alu"]]) & mode) > 0:
            return args
        return None

    @staticmethod
    def _f(a, b):
        return (a << 1) | b

    def get_mask(self, user_binary):
        return reduce(CdcMapper._f, user_binary)


class SSSDMapper:
    def __init__(self) -> None:
        self.rangesize = 200000
        self.maxslices = 10000
        self.idmap_lower = 200000

    def get_unix_uid_from_sid(self, sid):
        rid = self.get_rid_from_sid(sid)
        domain_sid = self.get_domain_sid(sid)
        first_rid = self.get_first_rid(self.rangesize, rid)
        aux_domain_sid = domain_sid
        if first_rid != 0:
            aux_domain_sid = domain_sid + "-" + str(first_rid)
        min_range = self.get_min_range(aux_domain_sid,
                                       self.rangesize,
                                       self.maxslices,
                                       self.idmap_lower)
        return min_range + (rid - first_rid)

    def get_rid_from_sid(self, sid):
        return int(sid.split('-')[-1])

    def get_first_rid(self, rangesize, rid):
        return int(rid / rangesize) * rangesize

    def get_domain_sid(self, sid):
        return '-'.join(sid.split('-')[0:-1])

    def get_min_range(self, sid, rangesize, maxslices, idmap_lower):
        hash_value = mrmr.hash(sid, 0xdeadbeef)
        new_slice = int(hash_value % maxslices)
        return (rangesize * new_slice) + idmap_lower


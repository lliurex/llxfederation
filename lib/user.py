from json import dumps
from llxfederation.mapper import CdcMapper


class User:

    def __init__(self, login) -> None:
        self.login = login
        self.name = ""
        self.surname = ""
        self.home = "/home/{}".format(login)
        self.shell = "/bin/bash"
        self.uid = -1
        self.gid = -1
        self.groups = []

    def populate_user(self):
        user_mod = 0
        for x in self.groups:
            group_lower = x.name.lower()
            if "docente" in group_lower:
                user_mod = user_mod | CdcMapper.TEACHERS
            if "alumno" in group_lower:
                user_mod = user_mod | CdcMapper.STUDENTS
            if "admin" in group_lower:
                user_mod = user_mod | CdcMapper.ADMINS
            cdcmapper = CdcMapper()
            aux_group = cdcmapper.get_groups(user_mod)
            for x in aux_group:
                g = Group(x["name"], x["gid"])
                if "default_gid" in x:
                    g.default_gid = x["default_gid"]
                self.groups.append(g)
            max_id = 0
            for x in self.groups:
                if x.default_gid is not None:
                    if x.default_gid > max_id:
                        max_id = x.default_gid
                        self.gid = x

    def __str__(self) -> str:
        return dumps(self.__dict__, indent=4, ensure_ascii=False)


class Group:
    def __init__(self, name, gid) -> None:
        self.name = name
        self.gid = gid
        self.default_gid = None

    def __str__(self) -> str:
        return dumps(self.__dict__, indent=4, ensure_ascii=False)

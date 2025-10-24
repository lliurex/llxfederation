from pathlib import Path
import json


class GvaAuthUpdate:
    def __init__(self)->None:
       self.dest_path = Path("/etc/llx-gva-gate.cfg") 
       self.conf_path = Path("/usr/share/gva-auth-update/conf.d")

    def get_real_config(self)->dict:
        try:
            content = json.loads(self.dest_path.read_text(encoding="utf-8"))
        except Exception:
            content = {"auth_methods":["local"], "expire":72}
        return content

    def get_real_auth_methods(self)->list|None:
        config = self.get_real_config()
        if "auth_methods" in config:
            return self.get_real_config()["auth_methods"]
        return None

    def get_default_configs(self)->list:
        configs = []
        for x in self.conf_path.iterdir():
            configs.append(json.loads(x.read_text(encoding="utf-8")))
        return configs

    def get_ordered_default_configs(self)->list:
        return sorted(self.get_default_configs(),
                      key=lambda x: x["auth_methods"]["priority"],
                      reverse=True)

    def get_ordered_default_auth_methods(self)->list:
        configs_ordered = self.get_ordered_default_configs()
        return [x["auth_methods"]["value"] for x in configs_ordered ]


    def save_real_auth_methods(self, methods)->bool:
        if type(methods) is list:
            config = self.get_real_config()
            config["auth_methods"] = methods
            self.dest_path.write_text( json.dumps(config, indent=4, ensure_ascii=False),
                                      encoding="utf-8")
            return True
        return False

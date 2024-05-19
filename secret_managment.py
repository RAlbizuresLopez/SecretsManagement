from dotenv import set_key, get_key
from Github_secrets import Github
import datetime
import os


class Secret:

    def __init__(self, address: str = ".env"):
        self.address: str = address
        self._string = "__secret_v"
        self._historic = {}
        self._keychain = {}
        self.__env_to_keychain()
        self._git: Github = None
        self.omit: list = []

    def github_login(self, token: str, owner: str, repo_name: str):
        git_object = Github(token, owner, repo_name)
        self._git = git_object

    def __get_env_vars_names(self) -> list:
        if not os.path.exists(self.address):
            raise FileNotFoundError(f"The file/address {self.address} does not exist.")
        keys = []
        with open(self.address, 'r') as file:
            for line in file:
                # Ignore empty lines and comments
                line = line.strip()
                if line and not line.startswith('#'):
                    # Split at the first '=' to get the key
                    key, _ = line.split('=', 1)
                    keys.append(key.strip())
        return keys

    def __get_secrets(self) -> dict:
        historic = {}
        key_list = self.__get_env_vars_names()
        for secret in key_list:
            historic[secret] = get_key(dotenv_path=self.address, key_to_get=secret)
        return historic

    @property
    def keychain(self) -> dict:
        return self._keychain.copy()

    @property
    def historic(self) -> dict:
        return self._historic.copy()

    def __v_timestamp(self) -> str:
        return str(int(float(str(datetime.datetime.utcnow().timestamp()))))

    def __env_to_historic(self) -> None:
        self._historic = self.__get_secrets()

    def __latest_versions(self) -> None:
        keychain = {}
        all_versions = self.historic
        # get root naming based on string
        root = list(set([i[:i.find(self._string)] for i in all_versions]))
        # for each root, get the max key and store value
        for i in root:
            key, value = self.__key_latest_version(i)
            keychain[i] = value
        self._keychain = keychain

    def __key_latest_version(self, name: str) -> tuple:
        if self.__secret_in_historic(name):
            key_name = max([i for i in list(self._historic.keys()) if name in i])
            val = self._historic[key_name]
            return key_name, val
        else:
            return None, None

    def __env_to_keychain(self) -> None:
        self.__env_to_historic()
        self.__latest_versions()

    def __secret_in_keychain(self, name: str) -> bool:
        return name in self._keychain

    def __secret_in_historic(self, name: str) -> bool:
        return any(name in i for i in self._historic)

    def __secret_has_max_value(self, name: str) -> bool:
        if self.__secret_in_keychain(name) and self.__secret_in_historic(name):
            k, val = self.__key_latest_version(name)
            return self._keychain[name] == val

    def __add_secret_to_keychain(self, name: str, val: str) -> None:
        self._keychain[name] = val

    def __add_secret_to_historic(self, name: str, val: str) -> None:
        name = name + self._string + self.__v_timestamp()
        self._historic[name] = val
        self.__add_secret_to_env(name, val)

    def __add_secret_to_env(self, name: str, val: str) -> None:
        set_key(dotenv_path=self.address, key_to_set=name, value_to_set=val)

    def __merge_historic_with_env(self) -> None:
        historic = self._historic
        env = self.__get_secrets()
        merge = {**historic, **env}
        self._historic = merge
        for i in merge:
            self.__add_secret_to_env(i, merge[i])

    def new_secret(self, name: str, val: str) -> None:
        try:
            val = str(val)
        except Exception as e:
            raise ValueError("Invalid parameter val type") from e

        if name in self._keychain:
            h_key, h_val = self.__key_latest_version(name)
            if val == h_val:
                print("This secret already exists and the value is the most recent")
            else:
                self.__add_secret_to_historic(name, val)
        else:
            self.__add_secret_to_keychain(name, val)
            self.__add_secret_to_historic(name, val)

    def import_secrets_from_keychain(self) -> None:
        if self._git.valid:
            for secret in self.keychain:
                if self.omit:
                    if secret not in self.omit:
                        self._git.add_git_secret(secret_name=secret, secret_value=self.keychain[secret])
                else:
                    self._git.add_git_secret(secret_name=secret, secret_value=self.keychain[secret])

    def import_secrets_from_historic(self) -> None:
        if self._git.valid:
            for secret in self.historic:
                if self.omit:
                    for omit_key in self.omit:
                        if secret[:secret.find(self._string)] != omit_key:
                            self._git.add_git_secret(secret_name=secret, secret_value=self.historic[secret])
                else:
                    self._git.add_git_secret(secret_name=secret, secret_value=self.historic[secret])

from nacl.encoding import Base64Encoder
from nacl.public import PublicKey, SealedBox
import requests
import base64


class Github:

    def __init__(self, token, owner, repo_name):
        self.owner = owner
        self.repo_name = repo_name
        self.base_url = f'https://api.github.com/repos/{self.owner}/{self.repo_name}/'
        self.token = token
        self.headers = {'Authorization': f'token {self.token}', 'Accept': 'application/vnd.github.v3+json'}
        self.valid = self.__validate_github_credentials()

    def __validate_github_credentials(self):
        response = requests.get("https://api.github.com/user", headers=self.headers)
        if response.status_code == 200:
            print("Credentials are valid.")
            return True
        else:
            print(f"Failed to validate credentials. Status code: {response.status_code}")
            return False

    def __get_public_key(self):
        response = requests.get(self.base_url + "actions/secrets/public-key", headers=self.headers)
        response.raise_for_status()
        public_key = response.json()
        return public_key

    def __encrypt_secret(self, secret_value: str):
        public_key = self.__get_public_key()
        public_key_bytes = PublicKey(public_key["key"].encode('utf-8'), encoder=Base64Encoder)
        sealed_box = SealedBox(public_key_bytes)
        encrypted = sealed_box.encrypt(secret_value.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    def add_git_secret(self, secret_name, secret_value):
        # This function also works to update a secret
        public_key = self.__get_public_key()
        url = self.base_url + f'actions/secrets/{secret_name}'
        encrypted_value = self.__encrypt_secret(secret_value)
        data = {'encrypted_value': encrypted_value, 'key_id': public_key["key_id"]}
        response = requests.put(url, headers=self.headers, json=data)
        response.raise_for_status()
        print(f'Secret {secret_name} created/updated successfully.')

    def get_secret_list(self):
        url = self.base_url + 'actions/secrets'
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        secrets = response.json()
        return secrets

    def delete_secret(self, secret_name):
        url = self.base_url + f'actions/secrets/{secret_name}'
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()
        print(f'Secret {secret_name} deleted successfully.')

# Example usage:
# github = Github(token='your_github_token', owner='your_owner', repo_name='your_repo')
# github.add_git_secret('MY_SECRET', 'my_secret_value')
# print(github.get_secret_list())
# github.delete_secret('MY_SECRET')

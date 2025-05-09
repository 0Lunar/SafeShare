class SecurityError(Exception):
    def __init__(self, *args):
        super().__init__(*args)
        

class EncryptionFailure(Exception):
    def __init__(self, *args):
        super().__init__(*args)
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, username, role, email=''):
        self.id       = id
        self.username = username
        self.role     = role
        self.email    = email

    @property
    def is_admin(self):
        return self.role == 'admin'
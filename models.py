from app import db

class User(db.Model):
  #Core Identity
  id=db.Column(db.Integer, primary_key=True)
  username=db.Column(db.String(20), unique=True, nullable=False)
  email=db.Column(db.String(120), unique=True, nullable=False)

  #security and Auth
  password_hash=db.Column(db.String(128), nullable=False)
  role=db.Column(db.String(20), nullable=False, default='User')

  #two factor auth 
  totp_secret=db.Column(db.String(32), nullable=True)

  def __repr__(self):
    return f"User('{self.username}', '{self.email}', '{self.role}')"
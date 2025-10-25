# models.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# SQLAlchemy instance
db = SQLAlchemy()

# ────────────── Kullanıcı Modeli ──────────────
class User(db.Model):
    __tablename__ = "users"  # Tablo adı
    
    id = db.Column(db.Integer, primary_key=True)
    kullanici_id = db.Column(db.String(50), unique=True, nullable=False)  # kullanıcı adı
    email = db.Column(db.String(100), unique=True, nullable=False)        # e-posta
    password = db.Column(db.String(200), nullable=False)                   # şifre (hash)
    rol = db.Column(db.String(20), default="kullanici")                   # rol: admin / kullanıcı
    aktif_mi = db.Column(db.Boolean, default=False)                        # hesap aktif mi?

    # ────────────── Şifreyi hashle ──────────────
    def set_password(self, password):
        self.password = generate_password_hash(password)

    # ────────────── Şifre kontrol ──────────────
    def check_password(self, password):
        return check_password_hash(self.password, password)

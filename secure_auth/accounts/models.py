from django.db import models

# Create your models here.
# accounts/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from datetime import timedelta
from django.conf import settings

# Optionnel : définir un seuil et durée dans settings.py
AUTH_LOCKOUT_THRESHOLD = getattr(settings, "AUTH_LOCKOUT_THRESHOLD", 5)
AUTH_LOCKOUT_TIME = getattr(settings, "AUTH_LOCKOUT_TIME", 15)  # minutes

class UserManager(BaseUserManager):
    """
    Manager personnalisé : utilise normalize_email() et supporte
    la création d'utilisateurs/superusers avec email comme identifiant.
    """
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("L'adresse e-mail doit être fournie")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # set_password met le hash correctement
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Le superuser doit avoir is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Le superuser doit avoir is_superuser=True.")
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    User personnalisé :
    - on supprime username (username = None)
    - on utilise email comme USERNAME_FIELD (unique)
    - champs pour sécurité/audit demandés
    """
    username = None  # on retire le username fourni par AbstractUser
    email = models.EmailField(_("email address"), unique=True)

    # Champs demandés
    failed_login_attempts = models.PositiveIntegerField(
        default=0,
        help_text="Nombre d'échecs consécutifs de connexion"
    )
    account_locked_until = models.DateTimeField(
        null=True, blank=True,
        help_text="Date/heure jusqu'à laquelle le compte est verrouillé"
    )
    last_password_change = models.DateTimeField(
        null=True, blank=True,
        help_text="Horodatage de la dernière modification du mot de passe"
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # email suffit pour createsuperuser

    def __str__(self):
        return self.email

    def set_password(self, raw_password):
        """
        Surcharge pour mettre à jour la date de changement de mot de passe.
        Note : on n'appelle pas .save() ici — l'appelant (create_user, admin, form) fera user.save().
        """
        super().set_password(raw_password)
        self.last_password_change = timezone.now()

    def check_login(self, raw_password):
        """
        Vérifie le mot de passe et gère le verrouillage du compte.
        Retourne True si connexion réussie, False sinon.
        """
        now = timezone.now()

        # Vérifie si le compte est verrouillé
        if self.account_locked_until and self.account_locked_until > now:
            return False

        # Vérifie le mot de passe
        if not self.check_password(raw_password):
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= AUTH_LOCKOUT_THRESHOLD:
                self.account_locked_until = now + timedelta(minutes=AUTH_LOCKOUT_TIME)
            self.save()
            return False

        # Mot de passe correct
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save()
        return True


# accounts/signals.py
from django.contrib.auth.signals import user_login_failed, user_logged_in
from django.dispatch import receiver
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model
import datetime

User = get_user_model()

# paramètres configurables (on les mettra dans settings)
LOCKOUT_THRESHOLD = getattr(settings, "AUTH_LOCKOUT_THRESHOLD", 5)  # échecs avant lock
LOCKOUT_PERIOD_SECONDS = getattr(settings, "AUTH_LOCKOUT_PERIOD", 15 * 60)  # 15 min

@receiver(user_login_failed)
def handle_login_failed(sender, credentials, request, **kwargs):
    """
    Quand une tentative échoue, si l'email existe : incrémente et lock si besoin.
    credentials contient par défaut 'username' (ici l'email).
    """
    email = credentials.get("username") or credentials.get("email")
    if not email:
        return
    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        return

    # Si déjà locké et pas encore expiré, on ne change rien
    now = timezone.now()
    if user.account_locked_until and user.account_locked_until > now:
        return

    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= LOCKOUT_THRESHOLD:
        user.account_locked_until = now + datetime.timedelta(seconds=LOCKOUT_PERIOD_SECONDS)
    user.save(update_fields=["failed_login_attempts", "account_locked_until"])


@receiver(user_logged_in)
def handle_login_success(sender, user, request, **kwargs):
    """
    Reset du compteur sur connexion réussie.
    """
    user.failed_login_attempts = 0
    user.account_locked_until = None
    user.save(update_fields=["failed_login_attempts", "account_locked_until"])

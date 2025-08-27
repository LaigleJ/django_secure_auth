# accounts/forms.py
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils import timezone

class LockedAccountAuthenticationForm(AuthenticationForm):
    """
    - Rend le champ 'username' de type EmailField (label Email)
    - Vérifie account_locked_until dans confirm_login_allowed()
    """
    username = forms.EmailField(widget=forms.EmailInput(attrs={"autofocus": True}), label="Email")

    def confirm_login_allowed(self, user):
        # si verrou actif -> on refuse la connexion avec message clair
        if user.account_locked_until and user.account_locked_until > timezone.now():
            remaining = int((user.account_locked_until - timezone.now()).total_seconds())
            minutes = remaining // 60
            seconds = remaining % 60
            raise forms.ValidationError(
                f"Compte temporairement verrouillé. Réessayez dans {minutes} min {seconds} s.",
                code="account_locked",
            )
        # conserve le comportement standard (is_active, etc.)
        super().confirm_login_allowed(user)


import hashlib
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    ADMIN = 'ADMIN'
    ANALYST = 'SECURITY_ANALYST'
    USER = 'USER'
    ROLE_CHOICES = [(ADMIN, 'Admin'), (ANALYST, 'Analyst'), (USER, 'User')]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=USER)
    trust_score = models.IntegerField(default=100)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    device_hash = models.CharField(max_length=255, null=True, blank=True)
    otp_required = models.BooleanField(default=False)
    otp_secret = models.CharField(max_length=32, null=True, blank=True)

class UserDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    device_hash = models.CharField(max_length=255)
    name = models.CharField(max_length=100)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    trusted = models.BooleanField(default=False)

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=255)
    data = models.JSONField()
    timestamp = models.DateTimeField(auto_now_add=True)
    previous_hash = models.CharField(max_length=64)
    current_hash = models.CharField(max_length=64)

    def save(self, *args, **kwargs):
        if not self.previous_hash:
            last_log = AuditLog.objects.order_by('-timestamp').first()
            self.previous_hash = last_log.current_hash if last_log else "0" * 64
        
        payload = f"{self.user_id}{self.action}{self.timestamp}{self.previous_hash}"
        self.current_hash = hashlib.sha256(payload.encode()).hexdigest()
        super().save(*args, **kwargs)

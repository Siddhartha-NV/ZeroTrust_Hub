
import time
from django.utils import timezone
from .models import LoginAttempt, RiskEvent, UserDevice

PENALTIES = {
    'NEW_DEVICE': -30,
    'NEW_IP': -20,
    'UNUSUAL_HOUR': -25,
    'BRUTE_FORCE': -40
}

def calculate_trust_score(user, ip_address, user_agent, device_hash):
    """
    Main logic for adaptive Zero Trust risk scoring.
    """
    total_penalty = 0
    now = timezone.now()
    
    # 1. Check Device Identity
    device_exists = UserDevice.objects.filter(user=user, device_hash=device_hash).exists()
    if not device_exists:
        total_penalty += abs(PENALTIES['NEW_DEVICE'])
        RiskEvent.objects.create(user=user, type='NEW_DEVICE', value=PENALTIES['NEW_DEVICE'])

    # 2. Check IP Context
    if user.last_login_ip != ip_address:
        total_penalty += abs(PENALTIES['NEW_IP'])
        RiskEvent.objects.create(user=user, type='NEW_IP', value=PENALTIES['NEW_IP'])

    # 3. Check Unusual Access Time (1 AM - 5 AM)
    if 1 <= now.hour <= 5:
        total_penalty += abs(PENALTIES['UNUSUAL_HOUR'])
        RiskEvent.objects.create(user=user, type='UNUSUAL_HOUR', value=PENALTIES['UNUSUAL_HOUR'])

    # 4. Check Failed Attempts (Redis logic simplified here)
    failed_count = LoginAttempt.objects.filter(
        user=user, 
        success=False, 
        timestamp__gte=now - timezone.timedelta(minutes=5)
    ).count()
    if failed_count > 5:
        total_penalty += abs(PENALTIES['BRUTE_FORCE'])
        RiskEvent.objects.create(user=user, type='BRUTE_FORCE', value=PENALTIES['BRUTE_FORCE'])

    # Final Score Calculation
    trust_score = max(0, 100 - total_penalty)
    user.trust_score = trust_score
    user.save()

    return {
        'score': trust_score,
        'requires_step_up': trust_score < 50,
        'blocked': trust_score < 20
    }

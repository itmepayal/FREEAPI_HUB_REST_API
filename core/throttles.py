from rest_framework import throttling

# -----------------------------
# THROTTLES
# -----------------------------
class FreeAnonThrottle(throttling.AnonRateThrottle):
    rate = '50/day'  

class FreeUserThrottle(throttling.UserRateThrottle):
    rate = '1000/day'
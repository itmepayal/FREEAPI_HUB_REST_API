# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from django.conf import settings
# from django.apps import apps

# @receiver(post_save, sender=apps.get_model("accounts", "User"))
# def create_user_relations(sender, instance, created, **kwargs):
#     if not created:
#         return

#     UserSecurity = apps.get_model("accounts", "UserSecurity")
#     UserPresence = apps.get_model("accounts", "UserPresence")

#     UserSecurity.objects.get_or_create(user=instance)
#     UserPresence.objects.get_or_create(user=instance)

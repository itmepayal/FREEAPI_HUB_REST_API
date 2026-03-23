import factory
from django.utils import timezone
from todo.models import Todo
from accounts.models import User
from core.constants import PRIORITY_MEDIUM

# =============================================================
# USER FACTORY
# =============================================================
class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User
        django_get_or_create = ("username",)
        skip_postgeneration_save = True
    username = factory.Sequence(lambda n: f"user_{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@example.com")
    password = factory.PostGenerationMethodCall("set_password", "testpass123")

# =============================================================
# TODO FACTORY
# =============================================================
class TodoFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Todo
    title = factory.Sequence(lambda n: f"Test Todo {n}")
    description = factory.Faker("sentence", nb_words=6)
    completed = False
    priority = PRIORITY_MEDIUM
    expire_at = None
    owner = factory.SubFactory(UserFactory)
    due_date = factory.LazyFunction(lambda: timezone.now() + timezone.timedelta(days=7))

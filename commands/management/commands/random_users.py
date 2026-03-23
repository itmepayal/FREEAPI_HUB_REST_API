"""
===================================================================
User Data Generator
===================================================================
Usage Example: python manage.py random_user --count 50
===================================================================
"""

import json
import random
import uuid
import logging
from pathlib import Path
from faker import Faker
from django.core.management.base import BaseCommand

# ============================================================
# LOGGER CONFIGURATION
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ============================================================
# FAKER INSTANCE
# ============================================================
fake = Faker()

# ============================================================
# PATH CONFIGURATION
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = (BASE_DIR / "../../../data").resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# CORE DATA GENERATION LOGIC
# ============================================================
def generate_user(user_id: int | None = None) -> dict:
    """
    Generate a single fake user object with structured and nested details.

    Args:
        user_id (int | None): Optional ID override for consistent indexing.

    Returns:
        dict: Structured user record ready for JSON serialization.
    """
    gender = random.choice(["male", "female"])
    first_name = fake.first_name_male() if gender == "male" else fake.first_name_female()
    last_name = fake.last_name()

    user = {
        "gender": gender,
        "name": {
            "title": "Mr" if gender == "male" else "Ms",
            "first": first_name,
            "last": last_name,
        },
        "location": {
            "street": {
                "number": fake.building_number(),
                "name": fake.street_name(),
            },
            "city": fake.city(),
            "state": fake.state(),
            "country": fake.country(),
            "postcode": fake.postcode(),
            "coordinates": {
                "latitude": str(fake.latitude()),
                "longitude": str(fake.longitude()),
            },
            "timezone": {
                "offset": fake.timezone(),
                "description": fake.sentence(nb_words=4),
            },
        },
        "email": fake.email(),
        "login": {
            "uuid": str(uuid.uuid4()),
            "username": fake.user_name(),
            "password": fake.password(),
            "salt": fake.lexify(text="????????"),
            "md5": fake.md5(raw_output=False),
            "sha1": fake.sha1(raw_output=False),
            "sha256": fake.sha256(raw_output=False),
        },
        "dob": {
            "date": fake.date_of_birth(tzinfo=None, minimum_age=18, maximum_age=80).isoformat(),
            "age": random.randint(18, 80),
        },
        "registered": {
            "date": fake.date_time_this_decade().isoformat(),
            "age": random.randint(1, 10),
        },
        "phone": fake.phone_number(),
        "cell": fake.phone_number(),
        "id": user_id or fake.random_int(min=1, max=99999),
        "picture": {
            "large": fake.image_url(width=256, height=256),
            "medium": fake.image_url(width=128, height=128),
            "thumbnail": fake.image_url(width=64, height=64),
        },
        "nat": fake.country_code(),
    }
    return user

# ============================================================
# BULK USER GENERATION
# ============================================================
def generate_users(n: int = 500) -> list[dict]:
    """
    Generate multiple fake user records.

    Args:
        n (int): Number of users to generate (default: 500).

    Returns:
        list[dict]: List of generated user objects.
    """
    logger.info(f"Generating {n} fake users with structured and detailed info...")
    return [generate_user(i) for i in range(1, n + 1)]

# ============================================================
# JSON FILE WRITER
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    """
    Serialize the generated user data to a JSON file.

    Args:
        filename (str): Target filename (e.g., 'users.json').
        data (list[dict]): The list of user dictionaries to write.

    Raises:
        Exception: Propagates any file write or permission errors.
    """
    try:
        path = DATA_DIR / filename
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logger.info(f"Successfully wrote {len(data)} records → {path}")
    except Exception as e:
        logger.exception(f"Failed to write {filename}: {e}")
        raise

# ============================================================
# DJANGO MANAGEMENT COMMAND
# ============================================================
class Command(BaseCommand):
    """
    Django management command for generating and exporting fake user data.

    Example:
        python manage.py random_user --count 20
    """

    help = "Generate structured fake user data and export it to 'users.json'."

    def add_arguments(self, parser):
        """
        Define supported CLI arguments for the command.

        Args:
            parser: Django's argument parser instance.
        """
        parser.add_argument(
            "--count",
            type=int,
            default=500,
            help="Number of fake users to generate (default: 500)",
        )

    def handle(self, *args, **options):
        """
        Main command execution entry point.

        Steps:
            1. Log the process start.
            2. Generate fake users.
            3. Write the output to a JSON file.
            4. Log completion.
        """
        count = options["count"]
        users = generate_users(count)
        write_json("users.json", users)
        logger.info("User generation completed successfully!")

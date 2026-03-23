"""
===================================================================
Cat Data Generator
===================================================================
Usage Example: python manage.py random_cat --count 100
===================================================================
"""

import json
import random
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
# CONSTANTS
# ============================================================
COUNTRIES = [
    ("US", "United States"),
    ("RU", "Russia"),
    ("JP", "Japan"),
    ("GB", "United Kingdom"),
    ("FR", "France"),
    ("CN", "China"),
    ("IN", "India"),
    ("EG", "Egypt"),
    ("TR", "Turkey"),
    ("CA", "Canada"),
]

TEMPERAMENT_TRAITS = [
    "Independent", "Affectionate", "Intelligent", "Playful", "Gentle",
    "Curious", "Loyal", "Social", "Energetic", "Quiet", "Trainable",
    "Friendly", "Adventurous", "Alert", "Calm", "Graceful", "Mischievous"
]

# Example images
IMAGE_BASE_URL = "https://cdn2.thecatapi.com/images/"
IMAGE_IDS = [fake.lexify(text="??????") for _ in range(100)]

# ============================================================
# PATH CONFIGURATION
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = (BASE_DIR / "../../../data").resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# CORE DATA GENERATION
# ============================================================
def generate_cat(cat_id: int) -> dict:
    """
    Generate a single fake cat breed record.
    """
    country_code, origin = random.choice(COUNTRIES)
    name = fake.word().capitalize() + random.choice([" Cat", " Bobtail", " Shorthair", " Longhair", " Breed"])
    temperament = ", ".join(random.sample(TEMPERAMENT_TRAITS, k=random.randint(5, 8)))
    image_id = random.choice(IMAGE_IDS)
    life_span = f"{random.randint(10, 15)} - {random.randint(16, 22)}"
    description = (
        f"The {name.strip()} is {fake.sentence(nb_words=10).lower()} "
        f"They are known to be {random.choice(['loving', 'curious', 'alert', 'social', 'independent'])} "
        f"and often {fake.sentence(nb_words=5).lower()}"
    )

    cat = {
        "id": cat_id,
        "name": name.strip(),
        "weight": {
            "imperial": f"{random.randint(6, 15)} - {random.randint(10, 20)}",
            "metric": f"{random.randint(3, 6)} - {random.randint(6, 9)}"
        },
        "temperament": temperament,
        "origin": origin,
        "country_codes": country_code,
        "country_code": country_code,
        "description": description.capitalize(),
        "life_span": life_span,
        "indoor": random.randint(0, 1),
        "adaptability": random.randint(1, 5),
        "affection_level": random.randint(1, 5),
        "child_friendly": random.randint(1, 5),
        "dog_friendly": random.randint(1, 5),
        "energy_level": random.randint(1, 5),
        "grooming": random.randint(1, 5),
        "health_issues": random.randint(1, 5),
        "intelligence": random.randint(1, 5),
        "shedding_level": random.randint(1, 5),
        "social_needs": random.randint(1, 5),
        "stranger_friendly": random.randint(1, 5),
        "vocalisation": random.randint(1, 5),
        "experimental": random.randint(0, 1),
        "hairless": random.randint(0, 1),
        "natural": random.randint(0, 1),
        "rare": random.randint(0, 1),
        "rex": random.randint(0, 1),
        "suppressed_tail": random.randint(0, 1),
        "short_legs": random.randint(0, 1),
        "hypoallergenic": random.randint(0, 1),
        "vetstreet_url": f"http://www.vetstreet.com/cats/{name.replace(' ', '-').lower()}",
        "wikipedia_url": f"https://en.wikipedia.org/wiki/{name.replace(' ', '_')}",
        "image": f"{IMAGE_BASE_URL}{image_id}.jpg"
    }

    return cat

# ============================================================
# BULK GENERATOR
# ============================================================
def generate_cats(n: int = 500) -> list[dict]:
    logger.info(f"Generating {n} fake cat breed records...")
    return [generate_cat(i) for i in range(1, n + 1)]

# ============================================================
# WRITE TO JSON
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    try:
        path = DATA_DIR / filename
        with path.open("w", encoding="utf-8") as f:
            json.dump({"data": data}, f, indent=4, ensure_ascii=False)
        logger.info(f"Successfully wrote {len(data)} cat records → {path}")
    except Exception as e:
        logger.exception(f"Failed to write {filename}: {e}")
        raise

# ============================================================
# DJANGO MANAGEMENT COMMAND
# ============================================================
class Command(BaseCommand):
    help = "Generate fake cat breed data similar to TheCatAPI."

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=50,
            help="Number of fake cat breeds to generate (default: 50)",
        )

    def handle(self, *args, **options):
        count = options["count"]
        cats = generate_cats(count)
        write_json("cats.json", cats)
        logger.info("Cat data generation completed successfully!")

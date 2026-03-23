#!/usr/bin/env python3
"""
===================================================================
Dog Data Generator
===================================================================
Usage Example: python manage.py random_dog --count 50
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
BREED_GROUPS = [
    "Herding", "Working", "Toy", "Hound", "Terrier", "Sporting", "Non-Sporting"
]

TEMPERAMENT_TRAITS = [
    "Friendly", "Loyal", "Playful", "Protective", "Alert", "Gentle", "Curious",
    "Affectionate", "Energetic", "Calm", "Smart", "Independent", "Brave"
]

ORIGINS = [
    "Germany", "France", "England", "Japan", "United States", "Scotland", "China", "India"
]

IMAGE_BASE_URL = "https://cdn2.thedogapi.com/images/"

# ============================================================
# PATH CONFIGURATION
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = (BASE_DIR / "../../../data").resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# HELPER: RANDOM HEIGHT/WEIGHT
# ============================================================
def random_range(min_val: float, max_val: float, unit: str) -> str:
    return f"{min_val} - {max_val} {unit}"

# ============================================================
# CORE DATA GENERATOR
# ============================================================
def generate_dog(dog_id: int) -> dict:
    """
    Generate a single fake dog breed record.
    """
    breed_name = fake.word().capitalize() + random.choice(["dog", "hound", "terrier", "retriever", "shepherd", "pup"])
    image_id = fake.lexify(text="???????").upper()

    dog = {
        "id": dog_id,
        "name": breed_name,
        "bred_for": fake.sentence(nb_words=4).replace(".", ""),
        "breed_group": random.choice(BREED_GROUPS),
        "life_span": f"{random.randint(8, 15)} - {random.randint(10, 18)} years",
        "temperament": ", ".join(random.sample(TEMPERAMENT_TRAITS, k=random.randint(4, 7))),
        "origin": random.choice(ORIGINS),
        "weight": {
            "imperial": random_range(random.randint(5, 40), random.randint(40, 100), "lbs"),
            "metric": random_range(random.randint(3, 20), random.randint(20, 45), "kg")
        },
        "height": {
            "imperial": random_range(round(random.uniform(8, 24), 1), round(random.uniform(25, 32), 1), "in"),
            "metric": random_range(round(random.uniform(20, 30), 1), round(random.uniform(35, 50), 1), "cm")
        },
        "reference_image_id": image_id,
        "image": {
            "id": image_id,
            "width": random.choice([800, 1024, 1280, 1600]),
            "height": random.choice([600, 768, 900, 1199]),
            "url": f"{IMAGE_BASE_URL}{image_id}.jpg"
        }
    }
    return dog

# ============================================================
# BULK GENERATOR
# ============================================================
def generate_dogs(n: int = 50) -> list[dict]:
    """
    Generate a list of fake dog records.
    """
    logger.info(f"Generating {n} fake dog breed records...")
    return [generate_dog(i) for i in range(1, n + 1)]

# ============================================================
# WRITE TO JSON FILE
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    """
    Write data to a JSON file.
    """
    try:
        path = DATA_DIR / filename
        with path.open("w", encoding="utf-8") as f:
            json.dump({"data": data}, f, indent=4, ensure_ascii=False)
        logger.info(f"Successfully wrote {len(data)} dog records → {path}")
    except Exception as e:
        logger.exception(f"Failed to write {filename}: {e}")
        raise

# ============================================================
# DJANGO MANAGEMENT COMMAND
# ============================================================
class Command(BaseCommand):
    help = "Generate fake dog breed data similar to TheDogAPI."

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=500,
            help="Number of fake dog breeds to generate (default: 50)",
        )

    def handle(self, *args, **options):
        count = options["count"]
        dogs = generate_dogs(count)
        write_json("dogs.json", dogs)
        logger.info("Dog data generation completed successfully!")

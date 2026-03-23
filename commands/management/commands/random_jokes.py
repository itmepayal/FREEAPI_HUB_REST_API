"""
===================================================================
Joke Data Generator
===================================================================
Usage Example: python manage.py random_joke --count 100
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
CATEGORIES = [
    "general", "animal", "science", "technology", "politics",
    "sports", "career", "education", "relationship", "dad-jokes"
]

# ============================================================
# PATH CONFIGURATION
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = (BASE_DIR / "../../../data").resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# CORE DATA GENERATION LOGIC
# ============================================================
def generate_joke(joke_id: int | None = None) -> dict:
    """
    Generate a single fake joke record with realistic attributes.

    Args:
        joke_id (int | None): Optional ID override for consistent indexing.

    Returns:
        dict: Structured joke record ready for JSON serialization.
    """
    category = random.choice(CATEGORIES)
    joke_content = fake.sentence(nb_words=random.randint(8, 16))

    joke = {
        "id": joke_id or fake.random_int(min=1000, max=9999),
        "categories": [category],
        "content": joke_content,
        "author": fake.first_name(),
        "length": len(joke_content),
        "likes": random.randint(0, 5000),
        "dislikes": random.randint(0, 1000),
        "dateAdded": fake.date_this_year().isoformat(),
        "dateModified": fake.date_this_month().isoformat()
    }
    return joke

# ============================================================
# BULK JOKE GENERATION
# ============================================================
def generate_jokes(n: int = 500) -> list[dict]:
    """
    Generate multiple fake joke records.

    Args:
        n (int): Number of jokes to generate (default: 500).

    Returns:
        list[dict]: List of generated joke objects.
    """
    logger.info(f"Generating {n} fake joke records (with categories and metadata)...")
    return [generate_joke(i) for i in range(1, n + 1)]

# ============================================================
# JSON FILE WRITER
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    """
    Serialize the generated joke data to a JSON file.

    Args:
        filename (str): Target filename (e.g., 'jokes.json').
        data (list[dict]): The list of joke dictionaries to write.
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
    Django management command for generating and exporting fake joke data.

    Example:
        python manage.py random_joke --count 100
    """

    help = "Generate structured fake joke data and export it to 'jokes.json'."

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=500,
            help="Number of fake jokes to generate (default: 500)",
        )

    def handle(self, *args, **options):
        count = options["count"]
        jokes = generate_jokes(count)
        write_json("jokes.json", jokes)
        logger.info("Joke data generation completed successfully!")

"""
===================================================================
Quote Data Generator
===================================================================
Usage Example:
    python manage.py random_quotes --count 200
===================================================================
"""

import json
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
def generate_quote(quote_id: int | None = None) -> dict:
    """
    Generate a single fake quote record.

    Args:
        quote_id (int | None): Optional ID for consistent indexing.

    Returns:
        dict: Structured quote data.
    """
    author = fake.name()
    content = fake.sentence(nb_words=12)
    tags = fake.words(nb=3)

    quote = {
        "id": quote_id or fake.random_int(min=1000, max=9999),
        "author": author,
        "authorSlug": "-".join(author.lower().split()),
        "content": content,
        "length": len(content),
        "tags": tags,
        "dateAdded": fake.date_this_decade().isoformat(),
        "dateModified": fake.date_this_year().isoformat(),
    }
    return quote

# ============================================================
# BULK QUOTE GENERATION
# ============================================================
def generate_quotes(n: int = 500) -> list[dict]:
    """
    Generate multiple fake quote records.

    Args:
        n (int): Number of quotes to generate (default: 500).

    Returns:
        list[dict]: List of generated quote dictionaries.
    """
    logger.info(f"Generating {n} fake quotes...")
    return [generate_quote(i + 1) for i in range(n)]

# ============================================================
# JSON FILE WRITER
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    """
    Write generated data to JSON file.

    Args:
        filename (str): Target file name (e.g., 'quotes.json')
        data (list[dict]): List of records to write.
    """
    try:
        path = DATA_DIR / filename
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logger.info(f"Successfully wrote {len(data)} quotes → {path}")
    except Exception as e:
        logger.exception(f"Failed to write {filename}: {e}")
        raise

# ============================================================
# DJANGO MANAGEMENT COMMAND
# ============================================================
class Command(BaseCommand):
    """
    Django management command for generating fake quotes.
    """

    help = "Generate structured fake quote data and export it to 'quotes.json'."

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=500,
            help="Number of fake quotes to generate (default: 500)",
        )

    def handle(self, *args, **options):
        count = options["count"]
        quotes = generate_quotes(count)
        write_json("quotes.json", quotes)
        logger.info("Quote generation completed successfully!")

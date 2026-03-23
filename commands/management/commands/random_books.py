"""
===================================================================
Book Data Generator
===================================================================
Usage Example: python manage.py random_book --count 100
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
    "Science", "Technology", "Fiction", "History", "Biography",
    "Programming", "Education", "Health", "Travel", "Philosophy"
]

PUBLISHERS = [
    "O'Reilly Media", "Addison-Wesley", "Apress", "Manning Publications",
    "Packt Publishing", "Pearson", "Wiley", "Springer", "No Starch Press"
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
def generate_book(book_id: int | None = None) -> dict:
    """
    Generate a single fake book record with realistic attributes.

    Args:
        book_id (int | None): Optional ID override for consistent indexing.

    Returns:
        dict: Structured book record ready for JSON serialization.
    """
    title = fake.catch_phrase()
    author = fake.name()
    publisher = random.choice(PUBLISHERS)
    category = random.choice(CATEGORIES)
    year = random.randint(1980, 2025)
    isbn_10 = str(fake.random_int(min=1000000000, max=9999999999))
    isbn_13 = "978" + str(fake.random_int(min=100000000000, max=999999999999))
    thumb_id = fake.uuid4()[:8]

    book = {
        "kind": "books#volume",
        "id": book_id or fake.random_int(min=1, max=9999),
        "etag": fake.lexify(text="????????????"),
        "volumeInfo": {
            "title": title,
            "subtitle": fake.bs().capitalize(),
            "authors": [author],
            "publisher": publisher,
            "publishedDate": str(year),
            "description": fake.paragraph(nb_sentences=5),
            "industryIdentifiers": [
                {"type": "ISBN_10", "identifier": isbn_10},
                {"type": "ISBN_13", "identifier": isbn_13}
            ],
            "readingModes": {"text": False, "image": True},
            "pageCount": random.randint(100, 800),
            "printType": "BOOK",
            "categories": [category],
            "maturityRating": "NOT_MATURE",
            "allowAnonLogging": bool(random.getrandbits(1)),
            "contentVersion": f"preview-{random.randint(1, 5)}.0.0",
            "panelizationSummary": {
                "containsEpubBubbles": False,
                "containsImageBubbles": False
            },
            "imageLinks": {
                "smallThumbnail": f"http://books.google.com/books/content?id={thumb_id}&printsec=frontcover&img=1&zoom=5&source=gbs_api",
                "thumbnail": f"http://books.google.com/books/content?id={thumb_id}&printsec=frontcover&img=1&zoom=1&source=gbs_api"
            },
            "language": "en",
            "previewLink": f"http://books.google.co.in/books?id={thumb_id}&hl=&cd=2&source=gbs_api",
            "infoLink": f"http://books.google.co.in/books?id={thumb_id}&hl=&source=gbs_api",
            "canonicalVolumeLink": f"https://books.google.com/books/about/{title.replace(' ', '_')}.html?hl=&id={thumb_id}"
        }
    }
    return book

# ============================================================
# BULK BOOK GENERATION
# ============================================================
def generate_books(n: int = 500) -> list[dict]:
    """
    Generate multiple fake book records.

    Args:
        n (int): Number of books to generate (default: 500).

    Returns:
        list[dict]: List of generated book objects.
    """
    logger.info(f"Generating {n} fake book records (Google Books-style)...")
    return [generate_book(i) for i in range(1, n + 1)]

# ============================================================
# JSON FILE WRITER
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    """
    Serialize the generated book data to a JSON file.

    Args:
        filename (str): Target filename (e.g., 'books.json').
        data (list[dict]): The list of book dictionaries to write.
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
    Django management command for generating and exporting fake book data.

    Example:
        python manage.py random_book --count 100
    """

    help = "Generate structured fake book data and export it to 'books.json'."

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=500,
            help="Number of fake books to generate (default: 500)",
        )

    def handle(self, *args, **options):
        count = options["count"]
        books = generate_books(count)
        write_json("books.json", books)
        logger.info("Book data generation completed successfully!")

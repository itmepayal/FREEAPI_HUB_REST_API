"""
===================================================================
Product Data Generator
===================================================================
Usage Example: python manage.py random_product --count 100
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
    "mens-watches", "womens-dresses", "laptops", "smartphones",
    "fragrances", "groceries", "home-decoration", "skincare",
    "furniture", "automotive", "sports-accessories"
]

# Example image base URLs (dummyjson-like)
BASE_IMAGE_URLS = [
    "https://cdn.dummyjson.com/product-images/1/",
    "https://cdn.dummyjson.com/product-images/2/",
    "https://cdn.dummyjson.com/product-images/3/",
    "https://cdn.dummyjson.com/product-images/4/",
    "https://cdn.dummyjson.com/product-images/5/",
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
def generate_product(product_id: int | None = None) -> dict:
    """
    Generate a single fake product record with realistic attributes.

    Args:
        product_id (int | None): Optional ID override for consistent indexing.

    Returns:
        dict: Structured product record ready for JSON serialization.
    """
    category = random.choice(CATEGORIES)
    title = fake.catch_phrase()
    base_url = random.choice(BASE_IMAGE_URLS)
    num_images = random.randint(2, 4)

    product = {
        "id": product_id or fake.random_int(min=1000, max=9999),
        "title": title,
        "description": fake.paragraph(nb_sentences=3),
        "category": category,
        "price": round(random.uniform(10, 1500), 2),
        "discountPercentage": round(random.uniform(5, 25), 2),
        "rating": round(random.uniform(2.5, 5.0), 2),
        "stock": random.randint(10, 500),
        "brand": fake.company(),
        "thumbnail": f"{base_url}thumbnail.jpg",
        "images": [f"{base_url}{i+1}.jpg" for i in range(num_images)],
        "sku": f"SKU-{fake.random_int(min=100000, max=999999)}",
        "warranty": f"{random.randint(6, 24)} months warranty",
        "shipping": {
            "weight": f"{round(random.uniform(0.2, 5.0), 2)} kg",
            "dimensions": {
                "width": round(random.uniform(10, 50), 2),
                "height": round(random.uniform(10, 50), 2),
                "depth": round(random.uniform(5, 30), 2)
            }
        },
        "dateAdded": fake.date_this_year().isoformat(),
        "dateModified": fake.date_this_month().isoformat()
    }
    return product

# ============================================================
# BULK PRODUCT GENERATION
# ============================================================
def generate_products(n: int = 500) -> list[dict]:
    """
    Generate multiple fake product records.

    Args:
        n (int): Number of products to generate (default: 500).

    Returns:
        list[dict]: List of generated product objects.
    """
    logger.info(f"Generating {n} fake product records (with categories, prices, and images)...")
    return [generate_product(i) for i in range(1, n + 1)]

# ============================================================
# JSON FILE WRITER
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    """
    Serialize the generated product data to a JSON file.

    Args:
        filename (str): Target filename (e.g., 'products.json').
        data (list[dict]): The list of product dictionaries to write.

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
    Django management command for generating and exporting fake product data.

    Example:
        python manage.py random_product --count 100
    """

    help = "Generate structured fake product data and export it to 'products.json'."

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=500,
            help="Number of fake products to generate (default: 500)",
        )

    def handle(self, *args, **options):
        count = options["count"]
        products = generate_products(count)
        write_json("products.json", products)
        logger.info("Product data generation completed successfully!")

"""
===================================================================
Meal Data Generator
===================================================================
Usage Example: python manage.py random_meal --count 50
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
    "Chicken", "Seafood", "Dessert", "Beef", "Vegetarian",
    "Side", "Vegan", "Pasta", "Breakfast", "Lamb", "Goat"
]

AREAS = [
    "Indian", "Italian", "Japanese", "Jamaican", "Mexican",
    "French", "Thai", "Chinese", "American", "British"
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
def generate_meal(meal_id: int | None = None) -> dict:
    """
    Generate a single fake meal object with structured and nested details.

    Args:
        meal_id (int | None): Optional ID override for consistent indexing.

    Returns:
        dict: Structured meal record ready for JSON serialization.
    """
    ingredients = [fake.word().capitalize() for _ in range(random.randint(5, 12))]
    measures = [
        f"{random.randint(1, 5)} {random.choice(['tsp', 'tbsp', 'g', 'ml', 'cup'])}"
        for _ in range(len(ingredients))
    ]

    category = random.choice(CATEGORIES)
    area = random.choice(AREAS)

    meal = {
        "id": str(meal_id or fake.random_int(min=10000, max=99999)),
        "strMeal": fake.sentence(nb_words=3).replace(".", ""),
        "strCategory": category,
        "categoryDetails": {
            "idCategory": CATEGORIES.index(category) + 1,
            "strCategoryThumb": fake.image_url(),
            "strCategoryDescription": fake.paragraph(nb_sentences=3),
        },
        "strArea": area,
        "areaDetails": {
            "region": area,
            "description": fake.paragraph(nb_sentences=2),
            "popularDish": fake.sentence(nb_words=3),
        },
        "strInstructions": fake.paragraph(nb_sentences=10),
        "strMealThumb": fake.image_url(),
        "strTags": ",".join(fake.words(nb=3)),
        "strYoutube": f"https://www.youtube.com/watch?v={fake.lexify(text='???????????')}",

        **{f"strIngredient{i+1}": ingredients[i] for i in range(len(ingredients))},
        **{f"strMeasure{i+1}": measures[i] for i in range(len(measures))},

        "strSource": fake.url(),
        "dateModified": fake.date(),
    }
    return meal

# ============================================================
# BULK MEAL GENERATION
# ============================================================
def generate_meals(n: int = 500) -> list[dict]:
    """
    Generate multiple fake meal records.

    Args:
        n (int): Number of meals to generate (default: 500).

    Returns:
        list[dict]: List of generated meal objects.
    """
    logger.info(f"Generating {n} fake meals (with category and area details)...")
    return [generate_meal(i) for i in range(1, n + 1)]

# ============================================================
# JSON FILE WRITER
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    """
    Serialize the generated meal data to a JSON file.

    Args:
        filename (str): Target filename (e.g., 'meals.json').
        data (list[dict]): The list of meal dictionaries to write.

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
    Django management command for generating and exporting fake meal data.

    Example:
        python manage.py random_meal --count 20
    """

    help = "Generate structured fake meal data and export it to 'meals.json'."

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
            help="Number of fake meals to generate (default: 500)",
        )

    def handle(self, *args, **options):
        """
        Main command execution entry point.

        Steps:
            1. Log the process start.
            2. Generate fake meals.
            3. Write the output to a JSON file.
            4. Log completion.
        """
        count = options["count"]
        meals = generate_meals(count)
        write_json("meals.json", meals)
        logger.info("Meal generation completed successfully!")

"""
===================================================================
Stock Data Generator
===================================================================
Usage Example: python manage.py random_stock --count 100
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
SECTORS = [
    "Technology", "Finance", "Energy", "Healthcare", "Automobile",
    "Real Estate", "Retail", "Telecom", "Pharmaceuticals", "Entertainment"
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
def generate_stock(stock_id: int | None = None) -> dict:
    """
    Generate a single fake stock object with realistic attributes.

    Args:
        stock_id (int | None): Optional ID override for consistent indexing.

    Returns:
        dict: Structured stock record ready for JSON serialization.
    """
    company_name = fake.company()
    symbol = "".join(word[0].upper() for word in company_name.split()[:2])[:6]
    market_cap = round(random.uniform(1_000, 50_000), 2)
    current_price = round(random.uniform(100, 3000), 2)
    change_percent = round(random.uniform(-5, 5), 2)
    volume = random.randint(10_000, 1_000_000)

    stock = {
        "id": stock_id or fake.random_int(min=10000, max=99999),
        "symbol": symbol,
        "companyName": company_name,
        "sector": random.choice(SECTORS),
        "details": {
            "marketCap": f"₹ {market_cap:,.2f} Cr",
            "currentPrice": f"₹ {current_price:,.2f}",
            "changePercent": change_percent,
            "volume": volume,
            "peRatio": round(random.uniform(10, 50), 2),
            "dividendYield": f"{round(random.uniform(0.5, 5.0), 2)}%",
        },
        "priceHistory": {
            "oneDay": f"{round(random.uniform(-3, 3), 2)}%",
            "oneWeek": f"{round(random.uniform(-5, 5), 2)}%",
            "oneMonth": f"{round(random.uniform(-10, 10), 2)}%",
            "oneYear": f"{round(random.uniform(-30, 30), 2)}%",
        },
        "lastUpdated": fake.date(),
    }
    return stock

# ============================================================
# BULK STOCK GENERATION
# ============================================================
def generate_stocks(n: int = 500) -> list[dict]:
    """
    Generate multiple fake stock records.

    Args:
        n (int): Number of stocks to generate (default: 500).

    Returns:
        list[dict]: List of generated stock objects.
    """
    logger.info(f"Generating {n} fake stock records (with details and price history)...")
    return [generate_stock(i) for i in range(1, n + 1)]

# ============================================================
# JSON FILE WRITER
# ============================================================
def write_json(filename: str, data: list[dict]) -> None:
    """
    Serialize the generated stock data to a JSON file.

    Args:
        filename (str): Target filename (e.g., 'stocks.json').
        data (list[dict]): The list of stock dictionaries to write.

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
    Django management command for generating and exporting fake stock data.

    Example:
        python manage.py random_stock --count 100
    """

    help = "Generate structured fake stock market data and export it to 'stocks.json'."

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
            help="Number of fake stocks to generate (default: 500)",
        )

    def handle(self, *args, **options):
        """
        Main command execution entry point.

        Steps:
            1. Log the process start.
            2. Generate fake stock data.
            3. Write the output to a JSON file.
            4. Log completion.
        """
        count = options["count"]
        stocks = generate_stocks(count)
        write_json("stocks.json", stocks)
        logger.info("Stock data generation completed successfully!")

"""
South African Public Holidays Calculator
Handles both fixed and moveable public holidays including Easter-based dates
"""

from datetime import date, timedelta
from typing import List, Dict


def calculate_easter(year: int) -> date:
    """
    Calculate Easter Sunday using Computus algorithm (Anonymous Gregorian algorithm)

    Args:
        year: Year to calculate Easter for

    Returns:
        date: Easter Sunday date
    """
    a = year % 19
    b = year // 100
    c = year % 100
    d = b // 4
    e = b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i = c // 4
    k = c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = ((h + l - 7 * m + 114) % 31) + 1

    return date(year, month, day)


def get_sa_public_holidays(year: int) -> Dict[date, str]:
    """
    Get all South African public holidays for a given year

    Args:
        year: Year to get holidays for

    Returns:
        dict: Dictionary mapping date to holiday name
    """
    holidays = {}

    # Fixed holidays
    holidays[date(year, 1, 1)] = "New Year's Day"
    holidays[date(year, 3, 21)] = "Human Rights Day"
    holidays[date(year, 4, 27)] = "Freedom Day"
    holidays[date(year, 5, 1)] = "Workers' Day"
    holidays[date(year, 6, 16)] = "Youth Day"
    holidays[date(year, 8, 9)] = "National Women's Day"
    holidays[date(year, 9, 24)] = "Heritage Day"
    holidays[date(year, 12, 16)] = "Day of Reconciliation"
    holidays[date(year, 12, 25)] = "Christmas Day"
    holidays[date(year, 12, 26)] = "Day of Goodwill"

    # Easter-based moveable holidays
    easter_sunday = calculate_easter(year)
    holidays[easter_sunday - timedelta(days=2)] = "Good Friday"
    holidays[easter_sunday + timedelta(days=1)] = "Family Day"

    # Handle Sunday rule: If a public holiday falls on a Sunday,
    # the following Monday becomes a public holiday
    sunday_holidays = [d for d in holidays.keys() if d.weekday() == 6]  # 6 = Sunday
    for sunday_date in sunday_holidays:
        monday_date = sunday_date + timedelta(days=1)
        if monday_date not in holidays:
            holidays[monday_date] = f"{holidays[sunday_date]} (observed)"

    return holidays


def is_public_holiday(check_date: date) -> bool:
    """
    Check if a given date is a South African public holiday

    Args:
        check_date: Date to check

    Returns:
        bool: True if public holiday, False otherwise
    """
    holidays = get_sa_public_holidays(check_date.year)
    return check_date in holidays


def get_holiday_name(check_date: date) -> str:
    """
    Get the name of the public holiday for a given date

    Args:
        check_date: Date to check

    Returns:
        str: Holiday name or empty string if not a holiday
    """
    holidays = get_sa_public_holidays(check_date.year)
    return holidays.get(check_date, "")


def get_holidays_in_range(start_date: date, end_date: date) -> List[Dict[str, any]]:
    """
    Get all public holidays within a date range

    Args:
        start_date: Start of date range
        end_date: End of date range (inclusive)

    Returns:
        list: List of dictionaries with 'date' and 'name' keys
    """
    result = []

    # Get all years in the range
    years = set()
    current = start_date
    while current <= end_date:
        years.add(current.year)
        current = date(current.year + 1, 1, 1)

    # Get holidays for all years
    for year in years:
        holidays = get_sa_public_holidays(year)
        for holiday_date, name in holidays.items():
            if start_date <= holiday_date <= end_date:
                result.append({
                    'date': holiday_date,
                    'name': name,
                    'day_of_week': holiday_date.strftime('%A')
                })

    # Sort by date
    result.sort(key=lambda x: x['date'])

    return result


# Example usage and testing
if __name__ == "__main__":
    print("South African Public Holidays 2025:")
    print("=" * 60)

    holidays_2025 = get_sa_public_holidays(2025)
    for holiday_date in sorted(holidays_2025.keys()):
        print(f"{holiday_date.strftime('%d/%m/%Y (%A)')}: {holidays_2025[holiday_date]}")

    print("\n" + "=" * 60)
    print(f"Total: {len(holidays_2025)} public holidays")

"""Packaged baseline content, used only when initializing the database."""
import json
from importlib.resources import files


def seed_document():
    return json.loads(files(__package__).joinpath('data/seed.json').read_text(encoding='utf-8'))

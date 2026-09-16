"""Run schema migrations as an explicit deployment step."""
from alembic import command
from alembic.config import Config


if __name__ == "__main__":
    command.upgrade(Config("alembic.ini"), "head")

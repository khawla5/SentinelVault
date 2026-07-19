from app.database.connection import engine
from app.database.base import Base

from app.models.user import User


def init_db():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
    print("Database created successfully!")
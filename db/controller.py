import hashlib
import re
from typing import List, Optional

from sqlalchemy import create_engine
from sqlalchemy import select, update, insert, or_, and_, delete, exists, desc
from sqlalchemy.orm import sessionmaker

from .db import User, Country, Base, Friendship, Post


def calculate_sha256(data):
    if isinstance(data, str):
        data = data.encode()
    sha256_hash = hashlib.sha256(data).hexdigest()
    return sha256_hash


class DatabaseController:
    Base()

    def __init__(self, connection_string: str):
        self.engine = create_engine(
            connection_string, echo=False
        )
        self.session = sessionmaker(autoflush=False, bind=self.engine)

    def get_countries(self, regions: Optional[List[str]]) -> list:
        with self.session() as session:
            if regions:
                print()
                conditions = [Country.region == i for i in regions]
                query = select(Country.name, Country.alpha2, Country.alpha3, Country.region).where(or_(*conditions))
            else:
                query = select(Country.__table__)
            print(query)
            data = session.execute(query).mappings().fetchall()
            return data

    def get_countries_by_code(self, code: str) -> list:
        with self.session() as session:
            query = select(Country.name, Country.alpha2, Country.alpha3, Country.region).where(Country.alpha2 == code)
            data = session.execute(query).mappings().fetchall()
            return data

    def user_uniqueness_check(self, login: str = None, phone: str = '', email: str = '', user_login: str = '') -> bool:
        with self.session() as session:
            login_exists = session.query(exists().where(and_(User.login == login, User.login != user_login))).scalar()

            email_exists = session.query(exists().where(and_(User.email == email, User.login != user_login))).scalar()

            phone_exists = session.query(exists().where(and_(User.phone == phone, User.login != user_login))).scalar()
            print(login_exists, email_exists, phone_exists)
            if login_exists or email_exists or phone_exists:
                return False
            return True

    def get_user_by_login(self, login: str) -> dict:
        with self.session() as session:
            query = select(User.login, User.email, User.countryCode, User.isPublic, User.phone, User.image).where(
                User.login == login)
            data = session.execute(query).mappings().fetchall()
            if not data:
                return None
            return dict(data[0])

    def get_user_by_password(self, login: str, password: str) -> dict:
        with self.session() as session:
            query = select(User.login, User.email, User.countryCode, User.isPublic, User.phone, User.image).where(
                User.login == login, User.password == hashlib.sha256(password.encode('utf-8')).hexdigest())
            data = session.execute(query).mappings().fetchall()
            print(query)
            if not data:
                return None
            return dict(data[0])

    def get_user(self, login: str) -> Optional[dict]:
        with self.session() as session:
            query = select(User.__table__).where(User.login == login)
            data = session.execute(query).mappings().fetchall()
            if not data:
                return None
            return dict(data[0])

    def update_password(self, old_password: str, new_password: str, login: str) -> bool:
        with self.session() as session:
            user_data = self.get_user(login)
            if user_data["password"] != hashlib.sha256(old_password.encode('utf-8')).hexdigest():
                return False
            query = update(User).where(User.login == login).values(
                password=hashlib.sha256(new_password.encode('utf-8')).hexdigest()
            )
            session.execute(query)
            session.commit()
            return True



    def update_user(self, login: str, country_code: str, image: str, phone: str, is_public: bool) -> dict:
        with self.session() as session:
            query = update(User).where(or_(User.login == login)).values(countryCode=country_code, image=image,
                                                                        phone=phone, isPublic=is_public)
            session.execute(query)
            session.commit()
            return self.get_user_by_login(login)

    def check_password_reliability(self, password):
        min_length = 6

        has_uppercase = bool(re.search(r'[A-Z]', password))

        has_lowercase = bool(re.search(r'[a-z]', password))

        has_digit = bool(re.search(r'\d', password))

        is_long_enough = len(password) >= min_length

        is_reliable = all([has_uppercase, has_lowercase, has_digit, is_long_enough])

        return is_reliable

    def create_user(self, user_info: dict) -> dict:
        with self.session() as session:
            user = User(**user_info)
            session.add(user)
            session.commit()
            return {"profile": self.get_user_by_login(user.login)}

    def add_friend(self, friend_login: str, user_login: str) -> None:
        with self.session() as session:
            print(friend_login, user_login)
            query = select(Friendship.__table__).where(
                and_(
                    Friendship.user_login == user_login,
                    Friendship.friend_login == friend_login
                )
            )
            friendship = session.execute(query).scalar_one_or_none()
            if friendship is not None:
                return
            query = insert(Friendship).values(user_login=user_login, friend_login=friend_login)
            # print(" friend inserted ")
            session.execute(query)
            session.commit()
    def remove_friend(self, friend_login: str, user_login: str) -> None:
        with self.session() as session:
            query = select(Friendship.__table__).where(
                or_(
                    and_(Friendship.user_login == user_login, Friendship.friend_login == friend_login),
                    and_(Friendship.friend_login == user_login, Friendship.user_login == friend_login),
                )
            )
            friendship = session.execute(query).fetchall()
            if not friendship:
                return

            query = delete(Friendship).where(Friendship.user_login == user_login)
            session.execute(query)
            session.commit()

    def get_friends(self, login: str, limit: int, offset: int) -> List[dict]:
        with self.session() as session:
            query = select(Friendship).where(Friendship.user_login == login).order_by(desc(Friendship.addedAt))
            friends_page = session.execute(query.offset(offset).limit(limit)).fetchall()
            return [{"login": friend[0].friend_login, "email": friend[0].addedAt} for friend in friends_page]

    def create_post(self, content: str, tags: list, login: str) -> int:
        with self.session() as session:
            new_post = Post(content=content, tags=tags, author=login)
            query = insert(Post).values(
                content=new_post.content,
                tags=new_post.tags,
                author=new_post.author
            ).returning(Post.id)
            res = session.execute(query)
            new_post_id = res.scalar_one()
            session.commit()
            return self.get_post_by_id(new_post_id)

    def get_post_by_id(self, post_id: int) -> dict:
        with self.session() as session:
            query = select(Post.id, Post.content, Post.author, Post.tags, Post.createdAt, Post.likesCount, Post.dislikesCount).where(Post.id == post_id)
            post = session.execute(query).mappings().fetchall()
            if not post:
                return None
            return dict(post[0])
# test = DatabaseController("postgresql://user@localhost/user")
# test.get_countries(regions=["Asia", "Europe"])
# print(calculate_sha256("password"), type(calculate_sha256("password")))

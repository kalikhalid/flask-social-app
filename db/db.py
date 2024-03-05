from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, ARRAY
from sqlalchemy.orm import DeclarativeBase, relationship, backref
import datetime

class Base(DeclarativeBase): pass


class Country(Base):
    __tablename__ = 'countries'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    alpha2 = Column(String)
    alpha3 = Column(String)
    region = Column(String)



class User(Base):
    __tablename__ = 'users'
    login = Column(String, primary_key=True)
    password = Column(String)
    email = Column(String)
    countryCode = Column(String)
    isPublic = Column(Boolean, default=True)
    phone = Column(String)
    image = Column(String)


class Friendship(Base):
    __tablename__ = 'friendships'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_login = Column(String, ForeignKey('users.login'))
    friend_login = Column(String, ForeignKey('users.login'))
    addedAt = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    user = relationship("User", back_populates="friends", foreign_keys=[user_login])
    friend = relationship("User", back_populates="friends", foreign_keys=[friend_login])

User.friends = relationship("Friendship", back_populates="user", foreign_keys=[Friendship.user_login])


class Post(Base):
    __tablename__ = 'posts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    tags = Column(ARRAY(String))
    content = Column(String)
    author = Column(String, ForeignKey('users.login'))
    createdAt = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    likesCount = Column(Integer, default=0)
    dislikesCount = Column(Integer, default=0)
    def __init__(self, tags, content, author):
        self.tags = tags
        self.content = content
        self.author = author
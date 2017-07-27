import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
	__tablename__ = 'user'
	name = Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	email = Column(String(80), nullable = False)


class School(Base):
	__tablename__ = 'school'
	name = Column(
		String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	branch = Column(String(80))
	city = Column(String(80))
	website = Column(String(250))
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		# Returns school data in easily serializable format
		return {
			'name': self.name,
			'branch': self.branch,
			'city': self.city,
			'website': self.website,
		}


class Subject(Base):
	__tablename__ = 'subject'
	name = Column(
		String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	level = Column(String(8), nullable = False)
	teacher = Column(String(80), nullable = False)
	textbook = Column(String(80))
	school_id = Column(
		Integer, ForeignKey('school.id'))
	school = relationship(School)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		# Returns subject data in easily serailizable format
		return {
			'name': self.name,
			'level': self.level,
			'teacher': self.teacher,
			'textbook': self.textbook,
		}


#######insert at end of file #######

engine = create_engine('sqlite:///subjects.db')

Base.metadata.create_all(engine)
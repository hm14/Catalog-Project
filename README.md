#Subjective, a Catalog Project

A program to create, read, update and delete school and subject entries by users. Read is accessible to all, create is accessible to all logged in users, and update and delete are only accessible to creators of subjects and schools.

The program is built using python and sqlalchemy, and can be run using terminal. The program creates and writes output to localhost:5000.

##Installation

Install [Python](https://www.python.org/downloads/)

##Configuration
1) Make sure that the subjects.db file is in the same directory as the one in which you run the project.py python file.
2) Run the following commands:
    i) python project.py (to access existing database entries)
    or
    ii) python database_setup.py to set up a fresh subjects.db
    	followed by python project.py

##Code Layout

Database set up is in database_setup.py

Helper functions are in utilities.py

All handlers are in project.py

All html files are in the templates directory

Style file is in static directory

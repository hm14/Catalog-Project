from flask import Flask, render_template, request, redirect, url_for
from flask import make_response, flash, jsonify
from flask import session as login_session

from database_setup import Base, User, School, Subject
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from utilities import createUser, getUserId, getUserInfo

import httplib2
import json
import requests
import random
import string

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Subjective"

# Create session and connect to database
engine = create_engine('sqlite:///subjects.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create a state token to prevent request forgery
# Store it in the session for later validation
@app.route('/login')
def showLogin():
    # Creates random string of 32 uppercase letters and digits
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Login for GPlus
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter!'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
        credentials = credentials.to_json()
        credentials = json.loads(credentials)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials['access_token']
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials['id_token']['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials['access_token'], 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = getUserId(login_session['email'])

    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!<br> Email :'
    output += login_session['email']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 300px; height: 300px;
                border-radius: 150px;-webkit-border-radius: 150px;
                -moz-border-radius: 150px;"> '''
    flash("You are now logged in as %s" % login_session['username'])
    return output


# Logout for GPlus
@app.route("/gdisconnect")
def gdisconnect():
    access_token = login_session['access_token']
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider when other providers are available
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        del login_session['credentials']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showSchools'))
    else:
        flash("You were not logged in.")
        return redirect(url_for('showSchools'))


# Makes API Endpoints (GET Request)
@app.route('/schools/JSON')
def schoolsJSON():
    schools = session.query(School)
    return jsonify(Schools=[school.serialize for school in schools])


@app.route('/schools/<int:school_id>/subjects/JSON')
def schoolSubjectJSON(school_id):
    school = session.query(School).filter_by(id=school_id).first()
    subjects = session.query(Subject).filter_by(school_id=school_id)
    return jsonify(Subjects=[subject.serialize for subject in subjects])


@app.route('/schools/<int:school_id>/subjects/<int:subject_id>/JSON')
def subjectJSON(school_id, subject_id):
    subject = session.query(Subject).filter_by(id=subject_id).first()
    return jsonify(Subject=subject.serialize)


@app.route('/')
@app.route('/schools/')
def showSchools():
    schools = session.query(School).order_by('name').all()
    # Checks if user is logged in
    if 'username' in login_session:
        logged_in_user = True
        current_user = getUserId(login_session['email'])
        current_user_schools = session.query(School)\
                            .filter_by(user_id=current_user).all()
        # Checks if logged in user is the creator of a school
        if current_user_schools:
            schools_to_edit = []
            for school in current_user_schools:
                schools_to_edit.append(school.name)
            return render_template('schools.html',
                                    schools=schools,
                                    logged_in_user=logged_in_user,
                                    schools_to_edit=schools_to_edit)
        return render_template('schools.html',
                                schools=schools,
                                logged_in_user=logged_in_user)
    return render_template('schools.html', schools=schools)


@app.route('/schools/new/', methods=['GET', 'POST'])
def newSchool():
    # Redirect to login page if user not logged in
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newSchool = School(name=request.form['name'],
                           branch=request.form['branch'],
                           city=request.form['city'],
                           website=request.form['website'],
                           user_id=login_session['user_id'],)
        session.add(newSchool)
        session.commit()
        flash("New School Created")
        return redirect(url_for('showSchools'))

    else:
        return render_template('newschool.html')


@app.route('/schools/<int:school_id>/edit/',
            methods=['GET', 'POST'])
def editSchool(school_id):
    # Redirect to login page if user not logged in
    if 'username' not in login_session:
        return redirect('/login')
    else:
        current_user = getUserId(login_session['email'])
        school_to_edit = session.query(School).\
                         filter_by(id=school_id).first()
        # Check if school requested for editing exists
        if school_to_edit:
            # Match school's creator with currently logged in user
            if school_to_edit.user_id == current_user:
                if request.method == 'POST':
                    edited_school = session.query(School).\
                                    filter_by(id=school_id).first()
                    edited_school.name = request.form['name']
                    edited_school.branch = request.form['branch']
                    edited_school.city = request.form['city']
                    edited_school.website = request.form['website']
                    session.add(edited_school)
                    session.commit()
                    # Inform user of successful editing
                    flash("School Edited")
                    return redirect(url_for('showSchools'))
                else:
                    edited_school = session.query(School).\
                                    filter_by(id=school_id).first()
                    # Show editschool form populated with current entries
                    return render_template('editschool.html',
                                            school_id=school_id,
                                            name=edited_school.name,
                                            branch=edited_school.branch,
                                            city=edited_school.city,
                                            website=edited_school.website)
        else:
            # Inform user that school requested for editing does not exist
            flash('The school you are trying to edit does not exist!')
            return redirect(url_for('showSchools'))
        # Error for user trying to bypass editing authorization
        error = 'You are not authorized to perform this action!'
        return render_template('editschool.html',
                                school_id=school_id,
                                error=error)


@app.route('/schools/<int:school_id>/delete/',
            methods=['GET', 'POST'])
def deleteSchool(school_id):
    # Redirect to login page if user not logged in
    if 'username' not in login_session:
        return redirect('/login')
    else:
        current_user = getUserId(login_session['email'])
        school_to_delete = session.query(School)\
                           .filter_by(id=school_id).first()
        # Check if school requested for deletion exists
        if school_to_delete:
            # Match school's creator with currently logged in user
            if school_to_delete.user_id == current_user:
                if request.method == 'POST':
                    deletedSchool = session.query(School).\
                                    filter_by(id=school_id).first()
                    session.delete(deletedSchool)
                    session.commit()
                    # Inform user of successful deletion
                    flash("School Deleted")
                    return redirect(url_for('showSchools'))
                else:
                    school_to_delete = session.query(School)\
                                       .filter_by(id=school_id).first()
                    return render_template('deleteschool.html',
                                            school_id=school_id)
        else:
            # Inform user that school requested for deletion does not exist
            flash('The school you are trying to delete does not exist')
            return redirect(url_for('showSchools'))
        # Error for user trying to bypass deletion authorization
        error = 'You are not authorized to perform this action!'
        return render_template('deleteschool.html',
                                school_id=school_id,
                                error=error)


@app.route('/schools/<int:school_id>/')
def showSubjects(school_id):
    school = session.query(School).\
             filter_by(id=school_id).first()
    # Check if school exists
    if school:
        subjects = session.query(Subject).\
                filter_by(school_id=school_id)
        # Check if there is a currently logged in user
        if 'username' in login_session:
            subject_creator = school.user_id
            current_user = getUserId(login_session['email'])
            # Match subject creator with currently logged in user
            if current_user == subject_creator:
                authorized_user = True
                return render_template('subjects.html',
                                        school=school,
                                        subjects=subjects,
                                        authorized_user=authorized_user)
        return render_template('subjects.html',
                                school=school,
                                subjects=subjects)
    # Redirect user to homepage if school does not exist
    else:
        flash('The school you are trying to look up does not exist')
        return redirect(url_for('showSchools'))


@app.route('/subjectsearch/',
            methods=['GET', 'POST'])
def searchBySubject():
    if request.method == 'POST':
        subject_sought = request.form['name']
        level_sought = request.form['level']
        matched_schools = session.query(School.name, School.id).join(Subject).\
                                        filter(Subject.school_id==School.id).\
                                        filter(Subject.name==subject_sought).\
                                        filter(Subject.level==level_sought)
        for matched_school in matched_schools:
            if matched_school[0]:
                return render_template('allsubjects.html',
                    subject_sought = subject_sought,
                    level_sought = level_sought,
                    matched_schools=matched_schools)
        flash('Sorry, no school is currently offering that subject.')
        return redirect(url_for('showSchools'))
    else:
        return render_template('allsubjects.html')


@app.route('/schools/<int:school_id>/new/',
            methods=['GET', 'POST'])
def newSubject(school_id):
    school = session.query(School).filter_by(id=school_id).first()
    if school:
        # Redirect to login page if user not logged in
        if 'username' not in login_session:
            return redirect('/login')
        else:
            school_creator = school.user_id
            current_user = getUserId(login_session['email'])
            if current_user == school_creator:
                if request.method == 'POST':
                    newSubject = Subject(name=request.form['name'],
                                      level=request.form['level'],
                                      teacher=request.form['teacher'],
                                      textbook=request.form['textbook'],
                                      school_id=school_id,
                                      user_id=current_user)
                    session.add(newSubject)
                    session.commit()
                    flash("New Subject Created")
                    return redirect(url_for('showSubjects',
                                             school_id=school_id))
                else:
                    return render_template('newsubject.html',
                                            school_id=school_id)
            else:
                # Error for trying to bypass subject creation authorization
                error = 'You are not authorized to perform this action'
                return render_template('newsubject.html',
                                        school_id=school_id,
                                        error=error)
    else:
        flash('The school you are trying to add a subject to does not exist')
        return redirect(url_for('showSchools'))


@app.route('/schools/<int:school_id>/<int:subject_id>/edit/',
            methods=['GET', 'POST'])
def editSubject(school_id, subject_id):
    school = session.query(School).\
             filter_by(id=school_id).first()
    subject_to_edit = session.query(Subject).\
                      filter_by(id=subject_id).first()
    # Check if the requested subject and school exist
    if school and subject_to_edit:
        # Redirect to login page if user not logged in
        if 'username' not in login_session:
            return redirect('/login')
        else:
            school_creator = school.user_id
            current_user = getUserId(login_session['email'])
            # Match subject creator and currently logged in user
            if school_creator == current_user:
                if request.method == 'POST':
                    subject_to_edit.name = request.form['name']
                    subject_to_edit.teacher = request.form['teacher']
                    subject_to_edit.level = request.form['level']
                    subject_to_edit.textbook = request.form['textbook']
                    session.add(subject_to_edit)
                    session.commit()
                    flash("Subject Item Edited")
                    return redirect(url_for('showSubjects',
                                    school_id=school_id))
                else:
                    return render_template('editsubject.html',
                                            school_id=school_id,
                                            subject_id=subject_id,
                                            subject_to_edit=subject_to_edit)
            # Error for user trying to bypass edit subject authorization
            else:
                error = 'You are not authorized to perform this action!'
                return render_template('editsubject.html',
                                        school_id=school_id,
                                        subject_id=subject_id,
                                        subject_to_edit=subject_to_edit,
                                        error=error)
    # Inform and redirect user if requested subject does not exist
    else:
        flash('The subject you are trying to edit does not exist')
        return redirect(url_for('showSchools'))


@app.route('/schools/<int:school_id>/<int:subject_id>/delete/',
            methods=['GET', 'POST'])
def deleteSubject(school_id, subject_id):
    school = session.query(School).\
             filter_by(id=school_id).first()
    subject_to_delete = session.query(Subject).\
                        filter_by(id=subject_id).first()
    # Check if the requested subject and school exist
    if school and subject_to_delete:
            # Redirect to login page if user not logged in
            if 'username' not in login_session:
                return redirect('/login')
            else:
                school_creator = school.user_id
                current_user = getUserId(login_session['email'])
                # Match subject creator and currently logged in user
                if school_creator == current_user:
                    if request.method == 'POST':
                        session.delete(subject_to_delete)
                        session.commit()
                        flash('Subject Deleted')
                        return redirect(url_for('showSubjects',
                                                 school_id=school_id))
                    else:
                        return render_template('deletesubject.html',
                                                school_id=school_id,
                                                subject_id=subject_id)
                # Error for user trying to bypass delete subject authorization
                else:
                    error = "You are not authorized to make this deletion!"
                    return render_template('deletesubject.html',
                                            school_id=school_id,
                                            subject_id=subject_id,
                                            error=error)
    # Inform and redirect user if requested subject does not exist
    else:
        flash('The subject you are trying to delete does not exist')
        return redirect(url_for('showSchools'))


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

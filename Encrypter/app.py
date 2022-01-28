from os import waitpid
import re
from cryptography import fernet
from flask import Flask, redirect, url_for, render_template, request, flash, Response
from flask.helpers import make_response
from flask.sessions import NullSession
from flask.templating import render_template_string
import cx_Oracle
import hashlib
import base64
import bcrypt
from datetime import datetime
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from flask_wtf import FlaskForm
from werkzeug.wrappers import response 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash


# Create an instance of the Flask class that is the WSGI application.
# The first argument is the name of the application module or package,
# typically __name__ when using a single module.
app = Flask(__name__)
app.config['SECRET_KEY'] = '757-551-518'
# Flask route decorators map / and /hello to the hello function.
# To add other resources, create functions that generate the page contents
# and add decorators to define the appropriate resource locators for them.


@app.route('/')
@app.route('/welcome')
def welcome():
    # Render the page
 #   return render_template('imageupload.html')
    return render_template('signup.html')

@app.route('/signuppage')
def signuppage():
    return render_template('signup.html')

@app.route('/loginpage')
def loginpage():
    return render_template('login.html')

@app.route('/imageuploadpage')
def imguploadpade():
    return render_template('imageupload.html')

@app.route('/account_settings')
def accountsettings():
    return render_template('accountsettings.html')

@app.route('/changepasswordpage')
def changepasswordpage():
    return render_template('changepassword.html')

@app.route('/dashboardpage')
def dashboardpage():
    first_name = request.cookies.get('first_name')
    last_name = request.cookies.get('last_name')
    email = request.cookies.get('email_id')
    if first_name == None or last_name == None or email == None:
        resp = make_response(redirect('/loginpage'))
        return resp
    else:
        #Get First Name and Last Name to display on the webpage
        mylist = [first_name, last_name]

        #Get Images from the database
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """SELECT Image_Id,Img_Name, Upload_Date FROM User_Images WHERE email = :email ORDER BY upload_date ASC"""
        cursor.execute(execute, {'email':email})
        result = cursor.fetchall()

        return render_template('dashboard.html', mylist=mylist, result = result)

@app.route('/signup' , methods = ['POST'])
def signup():
    #first_name = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")
    email = request.form.get("email_id")
    password = request.form.get("password")
    #return render_template('imgpin.html')
    img_password = request.form.get("img_pass")

    #Encryption with MD5 Method
    encryptedpass = hashlib.md5(password.encode())
    encryptedpass = encryptedpass.hexdigest()

    #Encryption with Bcrypt Method - Didn't Work
    #salt = bcrypt.gensalt()
    #str(salt, "utf-8")
    #encryptedpass = bcrypt.hashpw(password.encode('utf-8'), bytes(salt))

    try:
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """INSERT INTO User_Info VALUES (:first_name, :last_name, :email, :encryptedpass, :img_password)"""
        cursor.execute(execute, {'first_name':first_name, 'last_name':last_name, 'email':email, 'encryptedpass':encryptedpass, 'img_password':img_password})
        connect.commit()
    except cx_Oracle.IntegrityError:
        return "Email Already Exists"
    except:
        return "An Error Ocurred"
    
    resp = make_response(redirect('/loginpage'))
    return resp

    
@app.route('/login', methods = ['POST'])
def login():
    email = request.form.get("email_id")
    password = request.form.get("password")

    #Encryption with MD5 Method
    encryptedpass = hashlib.md5(password.encode())
    encryptedpass = encryptedpass.hexdigest()

    #Encryption with Bcrypt Method - Didn't Work
    #salt = bcrypt.gensalt()
    #str(salt, "utf-8")
    #encryptedpass = bcrypt.hashpw(password.encode('utf-8'), bytes(salt))
    #encryptedpass = str(encryptedpass, 'UTF-8')

    try:
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """SELECT * FROM User_Info WHERE email = :email"""
        cursor.execute(execute, {'email':email})
        for fname, lname, db_email, db_password, imgpass in cursor:
            str_val = str(imgpass)

            if db_password == encryptedpass:
                resp = make_response(redirect('/dashboardpage'))
                resp.set_cookie('email_id', db_email)
                resp.set_cookie('first_name', fname)
                resp.set_cookie('last_name', lname)
                resp.set_cookie('img_pass', str_val)
                return resp
            elif db_password != password:
                return "Incorrect Password"
            else:
                return "Some Other Error Ocurred"
    except:
        return "Login Error Email or Password Error"
    return "Successful"

@app.route('/logout')
def logout():
    try:
        resp = make_response(redirect('/loginpage'))
        resp.set_cookie('email_id', expires=0)
        resp.set_cookie('first_name', expires=0)
        resp.set_cookie('last_name', expires=0)
        resp.set_cookie('img_pass', expires=0)
        return resp
    except:
        return "An Error Ocurred"

@app.route('/deleteaccount')
def deleteaccount():
    email = request.cookies.get('email_id')
    if email == None:
        return make_response(redirect('/loginpage'))
    else:
        try:
            connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
            cursor = connect.cursor()
            execute = """DELETE FROM User_Info WHERE email = :email"""
            cursor.execute(execute, {'email':email})
            connect.commit()
            execute = """DELETE FROM User_Images WHERE email = :email"""
            cursor.execute(execute, {'email':email})
            connect.commit()
        except:
            return "An Error Ocurred"

@app.route('/changepassword')
def changepassowrd():
    email = request.cookies.get('email_id')
    if email == None:
        return make_response(redirect('/loginpage'))
    else:
        try:
            connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
            cursor = connect.cursor()
            execute = """SELECT password FROM User_Info WHERE email = :email"""
            cursor.execute(execute, {'email':email})
            result = cursor.fetchall()
        except:
            return "An Error Ocurred"


@app.route('/deleteimage/<image_id>', methods = ['GET' , 'POST'])
def deleteimage(image_id):
    try:
        email = request.cookies.get('email_id')
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """DELETE FROM User_Images WHERE image_id = :image_id and email = :email"""
        cursor.execute(execute, {'image_id':image_id, 'email':email})
        connect.commit()
        return make_response(redirect('/dashboardpage'))
    except:
        return "An Error Ocurred"

@app.route('/downloadimage/<image_id>' , methods = ['GET' , 'POST'])
def downloadimage(image_id):
    try:
        return "Download Image"
        email = request.cookies.get('email_id')
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """SELECT * FROM User_Images WHERE image_id = :image_id and email = :email"""
        cursor.execute(execute, {'image_id':image_id, 'email':email})

    except:
        return "An Error Ocurred"

@app.route('/imageupload' , methods = ['POST'])
def imageupload():
    try:
        uploaded_image = request.files['uploaded_image']
#        open(uploaded_image, "rb")
        b64string = base64.b64encode(uploaded_image.read())
        encryption_pin = request.form.getlist('check')
        if encryption_pin == ['default']:
            img_pass = request.cookies.get('img_pass')
        else:
            img_pass = request.form.get('encryption_key')
        image_name = request.form.get('image_name')
        
        email = request.cookies.get('email_id')

        date = datetime.now()

        reverse_img_pass = img_pass[::-1]
        
        b64string = b64string.decode("utf-8")
        #image_string = img_pass + b64string + reverse_img_pass
        checksum = img_pass + reverse_img_pass
        checksum = hashlib.md5(checksum.encode())
        checksum = checksum.hexdigest()
        image_string = checksum + b64string

        image_id = ''
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """INSERT INTO User_Images VALUES (:image_id, :email, :img_name, :encrypted_string, :upload_date)"""
        cursor.execute(execute, {'image_id':image_id,'email':email, 'img_name':image_name, 'encrypted_string':image_string, 'upload_date':date})
        connect.commit()

        return make_response(redirect('/dashboardpage'))

    except:
        return "An Error Ocurred"
        


if __name__ == '__main__':
    # Run the app server on localhost:4449
    app.run('localhost', 4449)

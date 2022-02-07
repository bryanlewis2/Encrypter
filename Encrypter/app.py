from os import waitpid
import re
from typing import IO
from cryptography import fernet
from flask import Flask, redirect, url_for, render_template, request, flash, Response, Blueprint
from flask.helpers import make_response, send_file
from io import BytesIO
from flask.sessions import NullSession
from flask.templating import render_template_string
import cx_Oracle
import hashlib
import base64
import bcrypt
import re
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
app = Flask(__name__, static_url_path='/static')
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

@app.route('/downloadimagepage/<image_id>')
def downloadimagepage(image_id):
    return render_template('imagepasswordpage.html', image_id = image_id)

@app.route('/viewimagepage/<image_id>')
def viewimagepage(image_id):
    return render_template('viewimagepasswordpage.html', image_id = image_id)

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
    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")
    email = request.form.get("email_id")
    password = request.form.get("password")
    #return render_template('imgpin.html')
    img_password = request.form.get("img_pass")

    #Encryption with MD5 Method
    encryptedpass = hashlib.md5(password.encode())
    encryptedpass = encryptedpass.hexdigest()

    try:
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """INSERT INTO User_Info VALUES (:first_name, :last_name, :email, :encryptedpass, :img_password)"""
        cursor.execute(execute, {'first_name':first_name, 'last_name':last_name, 'email':email, 'encryptedpass':encryptedpass, 'img_password':img_password})
        connect.commit()
        flash('Account Created Successfully')
        resp = make_response(redirect('/loginpage'))
        return resp
    except cx_Oracle.IntegrityError:
        flash('This Email already Exists')
        resp = make_response(redirect('/signuppage'))
        return resp
    except:
        flash('An Error Ocurred')
        resp = make_response(redirect('/signuppage'))
        return resp
    
    

    
@app.route('/login', methods = ['POST'])
def login():
    email = request.form.get("email_id")
    password = request.form.get("password")

    #Encryption with MD5 Method
    encryptedpass = hashlib.md5(password.encode())
    encryptedpass = encryptedpass.hexdigest()

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
                flash('Incorrect Password')
                return make_response(redirect('/loginpage'))
            else:
                flash('Some Other Error Ocurred')
                return make_response(redirect('/loginpage'))
    except:
       flash('Incorrect Email or Password')
    

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
       flash('An Error Ocurred')

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
            flash('Account Deleted Successfully')
            return make_response(redirect('/signuppage'))
        except:
            flash('An Error Ocurred')

@app.route('/changepassword', methods = ['POST'])
def changepassword():
    email = request.cookies.get('email_id')
    oldpassword = request.form.get('oldpassword')
    newpassword = request.form.get('newpassword1')
    if email == None:
        return make_response(redirect('/loginpage'))
    else:
        try:
            connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
            cursor = connect.cursor()
            execute = """SELECT password FROM User_Info WHERE email = :email"""
            cursor.execute(execute, {'email':email})
            result = cursor.fetchone()
            for db_password in result:
                string = ''
                string = string + db_password
            oldencryptedpass = hashlib.md5(oldpassword.encode())
            oldencryptedpass = oldencryptedpass.hexdigest()

            if string == oldencryptedpass:
                try:
                    newencryptedpass = hashlib.md5(newpassword.encode())
                    newencryptedpass = newencryptedpass.hexdigest()
                    execute = """ UPDATE User_Info SET password = :password WHERE email = :email  """
                    cursor.execute(execute, {'password': newencryptedpass, 'email': email})
                    connect.commit()
                    flash('Password Changed Successfully')
                    return make_response(redirect('/dashboardpage'))
                except:
                    flash('Some Error Ocurred')
        except:
            flash('An Error Ocurred')


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
        flash('An Error Ocurred')

@app.route('/viewimage' , methods = ['POST'])
def viewimage():
    try:
        image_id = request.form.get('image_id')
        image_pass = request.form.get('image_pass')

        email = request.cookies.get('email_id')
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """SELECT encrypted_string FROM User_Images WHERE image_id = :image_id and email = :email"""
        cursor.execute(execute, {'image_id':image_id, 'email':email})
        result = cursor.fetchone()
        
        for item in result:
            string = ''
            string = string + item
        
        reverse_image_pass = image_pass[::-1]
        checksum = image_pass + reverse_image_pass
        checksum = hashlib.md5(checksum.encode())
        checksum = checksum.hexdigest()

        x = re.search(checksum, string)

        if(x!= None):
            image_string = string.replace(checksum, '')
            imagedata = base64.b64decode(image_string)
            return render_template('viewimage.html' , image_string = image_string)
    except:
        flash('An Error Ocurred')

@app.route('/downloadimage' , methods = ['POST'])
def downloadimage():
    try:
        #return "Download Image"
        image_id = request.form.get('image_id')
        image_pass = request.form.get('image_pass')

        email = request.cookies.get('email_id')
        connect = cx_Oracle.connect("admin" , "adminpass" , "localhost:1521/xe")
        cursor = connect.cursor()
        execute = """SELECT encrypted_string FROM User_Images WHERE image_id = :image_id and email = :email"""
        cursor.execute(execute, {'image_id':image_id, 'email':email})
        result = cursor.fetchone()
        for item in result:
            str1 = ''
            str1 = str1 + item
        reverse_image_pass = image_pass[::-1]
        checksum = image_pass + reverse_image_pass
        checksum = hashlib.md5(checksum.encode())
        checksum = checksum.hexdigest()

        x = re.search(checksum, str1)

        if(x!= None):
            image_string = str1.replace(checksum, '')
            imagedata = base64.b64decode(image_string)

            return send_file(BytesIO(imagedata), mimetype='image/jpeg', as_attachment=True, attachment_filename= 'image.jpg')
        else:
            flash('Incorrect Image Password')

    except:
        flash('An Error Ocurred')

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
        flash('An Error Ocurred')
        


if __name__ == '__main__':
    # Run the app server on localhost:4449
    app.run('localhost', 4449)

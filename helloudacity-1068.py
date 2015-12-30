import webapp2
import os
import jinja2
import re
import hmac
import hashlib
import random
import string
import urllib2
import datetime
import logging
import time

from xml.dom import minidom

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = "True")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

		  
IP_URL = "http://ip-api.com/xml/"
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
SECRET = "australia"
def check_username_unique(username):
	q = db.GqlQuery("SELECT * FROM User WHERE username = '%s'" % username)
	return q.get()

def make_salt():
	return ''.join(random.choice(string.letters) for i in xrange(5))

def make_password_hash(password, salt = ""):
	if salt == "":
		salt = make_salt()
	return "%s|%s" % (hmac.new(str(salt), str(password), hashlib.sha256).hexdigest(), salt)
def verify_password(password, password_hash):
	return password_hash == make_password_hash(password, password_hash.split("|")[1])
def make_valid_cookie(val):
	return "%s|%s" % (val, hashlib.sha256(val + SECRET).hexdigest())

def verify_cookie(cookie):
	val = cookie.split("|")[0]
	hash_val = cookie.split("|")[1]
	return hashlib.sha256(val + SECRET).hexdigest() == hash_val

class User(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.EmailProperty()

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a,**kw)
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

class MainPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write('Hello, World!')

class Welcome(Handler):
	def get (self):
		user_id_cookie = self.request.cookies.get('user_id')
		if user_id_cookie and verify_cookie(user_id_cookie):
			user = User.get_by_id(int(user_id_cookie.split("|")[0]))
			self.render("welcome.html", username = str(user.username))
		else:
			self.redirect("/blog/signup")

class SignUp(HandlerWithCookie):
	def write_form(self, username="", error_username="", error_password="", error_verify="", email="", error_email=""):
		self.render("signup.html", username = username, 
								   error_username = error_username, 
								   error_password = error_password, 
								   error_verify = error_verify, 
								   email = email, 
								   error_email = error_email)
	def get(self):
		self.write_form()
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")

		error_username = "That's not a valid username."
		error_password = "That wasn't a valid password."
		error_verify = ""
		error_email = "That's not a valid email."

		if USER_RE.match(username):
			error_username = ""
		if PASS_RE.match(password):
			error_password = ""
			if password != verify:
				error_verify = "Your passwords didn't match."
		
		if email:
			if EMAIL_RE.match(email):
				error_email = ""
		else:
			error_email = ""
		if error_username or error_password or error_verify or error_email:
			self.write_form(username = username, error_username = error_username, error_password = error_password, 
					error_verify = error_verify, email = email, error_email = error_email)
		elif check_username_unique(username):
			self.write_form(error_username = "That user already exists.")
		else:
			password_hash = make_password_hash(password)
			if email:
				user = User(username = username, password_hash = password_hash, email = email)			
			else:
				user = User(username = username, password_hash = password_hash)			
			user.put()
			self.set_cookie_valid(user)
			self.redirect("/blog/welcome")

class Login(HandlerWithCookie):
	def write_form(self, invalid_login = False):
		self.render("login.html", invalid_login = invalid_login)
	def get(self):
		self.write_form()
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")

		if username:
			user = check_username_unique(username)
			if user and password and verify_password(password, user.password_hash):
				self.set_cookie_valid(user)
				self.redirect("/blog/welcome")
			else:
				self.write_form(invalid_login = True)
		else:
			self.write_form(invalid_login = True)

class Logout(HandlerWithCookie):
	def get(self):
		self.set_cookie_empty()
		self.redirect("/blog/signup")				

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', SignUp),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout)], 
    debug=True)
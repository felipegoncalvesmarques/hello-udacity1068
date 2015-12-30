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

def gmaps_img(points):
    markers = '&'.join('markers=%s,%s' % (p.lat,p.lon) for p in points)
    return GMAPS_URL + markers

def get_coord(ip):
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except urllib2.URLError:
		return

	if content:
		d = minidom.parseString(content)
   		if d.getElementsByTagName("status")[0].childNodes[0].nodeValue == "success":
   			return db.GeoPt(d.getElementsByTagName("lat")[0].childNodes[0].nodeValue,
   							d.getElementsByTagName("lon")[0].childNodes[0].nodeValue)

def top_arts(art = None):
	key = 'top'
	arts = memcache.get(key)
	if (arts is None) or art:
		if arts is None:
			logging.error("DB QUERY")
			arts = list(db.GqlQuery("SELECT * FROM Art ORDER BY created DESC"))
		if art:
			arts.insert(0, art)
		memcache.set(key, arts)
	return arts
last_time_cache = time.time()
last_time_cache_post = {}
def get_post(post_id):
	global last_time_cache_post
	post = memcache.get(post_id)
	if post is None:
		post = Entry.get_by_id(int(post_id))
		if post:
			last_time_cache_post[post_id] = time.time()
			logging.error("Caching ok %.0f" % last_time_cache_post[post_id])
			memcache.set(post_id, post)
		else:
			return
	return post
def top_post(post = None):
	global last_time_cache
	key = 'post'
	posts = memcache.get(key)
	if (posts is None) or post:
		if posts is None:
			last_time_cache = time.time()
			logging.error("DB QUERY")
			posts = list(db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC"))
		if post:
			posts.insert(0, post)
		memcache.set(key, posts)
	return posts
class Blog(db.Model):
	name = db.StringProperty()
class User(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.EmailProperty()

class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.StringProperty(required = True, multiline = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords = db.GeoPtProperty()

class Entry(db.Model):
	title = db.StringProperty(required = True)
	content = db.StringProperty(required = True, multiline = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a,**kw)
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))
class HandlerPost(Handler):
	def render_posts(self, posts):
		posts_rendered = ""
		for post in posts:
			posts_rendered = posts_rendered + self.render_str("post.html", post = post, 
				time = post.last_modified.strftime("%a %b %d %H:%M:%S %Y"))
		return posts_rendered
class HandlerWithCookie(Handler):
	def set_cookie_valid(self, user):
		val_cookie = make_valid_cookie(str(user.key().id()))
		self.set_cookie(val_cookie)
	def set_cookie_empty(self):
		self.set_cookie("")
	def set_cookie(self,val):
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % ("user_id", val))
		
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

class Ascii(Handler):
	def write_form(self, title="", error_title="", content="", error_art=""):
		arts = top_arts()
		points = filter(None, (a.coords for a in arts))
		img_url = ""
		if points:
			img_url = gmaps_img(points)		
		self.render("ascii.html", arts = arts, title=title, error_title=error_title,
								 content = content, error_art=error_art, img_url = img_url)
	def get(self):
		self.write_form()
	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")

		error_title = "Insert a title."
		error_art = "Insert an Art"

		if title:
			error_title = ""
		if art:
			error_art = ""

		if error_title or error_art:
			self.write_form(title = title, error_title = error_title, content = art, error_art = error_art)
		else:
			art = Art(title = title, art = art)
			coords = get_coord(self.request.remote_addr)
			if coords:
				art.coords = coords
			art.put()
			logging.error("Added to the DB")
			top_arts(art = art)
			self.redirect("/ascii")

class NewPost(Handler):
	
	def get(self):
		self.render("newpost.html")
	
	def post(self):
		title = self.request.get("subject")
		content = self.request.get("content")
		
		if title and content:
			entry = Entry(title = title, content = content)
			entry.put()
			top_post(post = entry)
			self.redirect("/blog/%s" % (entry.key().id()))
		else:
			self.render("newpost.html", title = title, content = content, error_message = "Insert both title and content!")
class Post(HandlerPost):
	def get(self, post_id):
		global last_time_cache_post
		post = get_post(post_id)
		if post:
			posts_rendered = self.render_posts([post])
			self.render("blog.html", posts = posts_rendered, time = time.time() - last_time_cache_post[post_id])
		else:
			self.error(404)
			return
class Blog(HandlerPost):
	def get(self):
		posts = top_post()
		posts_rendered = self.render_posts(posts)
		self.render("blog.html", posts = posts_rendered, time = time.time() - last_time_cache)
class BlogJson(Handler):
	def render_post(self, post):
		if post:
			return self.render_str("postJ.html", post = post, time_created = post.created.strftime("%a %b %d %H:%M:%S %Y"),
								time_last = post.last_modified.strftime("%a %b %d %H:%M:%S %Y"))
	def get(self):
		self.response.headers['Content-Type'] = 'application/json: charset=UTF-8'
		posts = list(Entry.all().order('-created'))
		json = "["
		for post in posts[0:len(posts) - 2]:
			json = json + self.render_post(post) + ", "
		json = json + self.render_post(posts[-1]) + "]"
		self.write(json)

class PostJson(Handler):
	def get(self, post_id):
		self.response.headers['Content-Type'] = 'application/json: charset=UTF-8'
		post = Entry.get_by_id(int(post_id))
		if post:
			self.render("postJ.html", post = post, time_created = post.created.strftime("%a %b %d %H:%M:%S %Y"),
								time_last = post.last_modified.strftime("%a %b %d %H:%M:%S %Y"))
		else:
			self.error(404)
			return

class Flush(webapp2.RequestHandler):
	def get(self):
		memcache.flush_all()
		self.redirect("/blog")
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/signup', SignUp),
    ('/blog/welcome', Welcome),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)', Post),
    ('/blog/([0-9]+).json', PostJson),
    ('/blog/', Blog),
    ('/blog', Blog),
    ('/blog/.json', BlogJson),
    ('/ascii', Ascii),
    ('/blog/flush', Flush)], 
    debug=True)
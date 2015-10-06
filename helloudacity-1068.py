import os

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class Entry(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

class MyBlogPage(Handler):
	def render_front(self, subject="", content=""):
		entries = db.GqlQuery("SELECT * FROM Entry "
							"ORDER BY created DESC")
		self.render("blog.html", subject = subject, content = content, entries = entries)

	def get(self):
		self.render_front()

class NewPostPage(Handler):
	def get(self):
		self.write("Hello!")

app = webapp2.WSGIApplication([('/myblog', MyBlogPage),
							   ('/myblog/newpost', NewPostPage)
							   ],
							   debug=True)
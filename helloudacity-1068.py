import os
import webapp2

class Handler(webapp2):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

class MainPage(Handler):
	def get(self):
		self.write("Hello, Udacity!!!")

app = webapp2.WSGIApplication([('/', MainPage)
							   ],
							   debug=True)
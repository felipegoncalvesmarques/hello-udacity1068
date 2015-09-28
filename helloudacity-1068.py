import webapp2
import string
import cgi
import re
alph = 'abcdefghijklmnopqrstuvwxyz'
rot13Dict = dict()
for i in range(0,26):
	rot13Dict[alph[i]] = alph[(i+13)%26]
	rot13Dict[alph[i].upper()] = alph[(i+13)%26].upper()
def rot13(word):
	word = list(word)
	for i in range(0,len(word)):
		if rot13Dict.get(word[i]):
			word[i] = rot13Dict.get(word[i])
	return "".join(word)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def  valid_username(username):
	return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return EMAIL_RE.match(email)

def escape_html(s):
	return cgi.escape(s, quote = True)

form_SignUp = """
<form method="post">
	<p><b>Signup</b></p>
	<p>
	<label>
		Username
		<input type="text" name="username" value="%(username)s">
		%(errorUsername)s
	</label>
	<br>
	<label>
		Password
		<input type="password" name="password">
		%(errorPassword)s
	</label>
	<br>
	<label>
		Verify Password
		<input type="password" name="verify">
		%(errorVerify)s
	</label>
	<br>
	<label>
		Email(optional)
		<input type="text" name="email" value="%(email)s">
		%(errorEmail)s
	</label>
	<br>
	<input type="submit">
	</p>
</form>
"""
form_Rot13 = """
<form method="post">
	<label>
		<b>Enter some text to Rot13</b>
		<br>	
		<textarea rows= "6" colums = "50" name="text">%(text)s</textarea>
	</label>
	<br>
	<input type="submit">
</form>
"""
class SignUpPage(webapp2.RequestHandler):
    def write_form(self, errorUsername = "", username="", errorPassword = "", errorVerify = "", errorEmail= "", email=""):
    	self.response.out.write(form_SignUp % {"errorUsername": errorUsername,
    									"username": username, 
    									"errorPassword": errorPassword,
    									"errorVerify": errorVerify,
    									"errorEmail": errorEmail,
    									"email": email})
    def get(self):
        self.write_form()
    def post(self):
    	user_username = self.request.get("username")
    	user_password = self.request.get("password")
    	user_verify = self.request.get("verify")
    	user_email = self.request.get("email")


    	errorUsername = ""
    	errorPassword = ""
    	errorVerify = ""
    	errorEmail = ""
    	
    	if not (valid_username(user_username)):
    		errorUsername = "That's not a valid username."
    	if not (valid_password(user_password)):
    		errorPassword = "That wasn't a valid password."
    	if not (user_password == user_verify):
    		errorVerify = "Your passwords didn't match."
    	if (user_email and not valid_email(user_email)):
    		errorEmail = "That's not a valid email"
    	if not (errorUsername or errorPassword or errorVerify or errorEmail):
    		self.redirect("/unit2/welcome?username=%s" %user_username)
    	else:
    		self.write_form(errorUsername, escape_html(user_username),errorPassword, errorVerify, errorEmail, escape_html(user_email))


class WelcomePage(webapp2.RequestHandler):
	def get(self):
		username = self.request.get("username")
		self.response.out.write("<b>Welcome, %s!</b>"%username)

class Rot13Page(webapp2.RequestHandler):
	def write_form(self,text=""):
		self.response.out.write(form_Rot13 % {'text': text})
	def get(self):
		self.write_form()
	def post(self):
		new_word = self.request.get('text')
		new_word = rot13(new_word)
		self.write_form(escape_html(new_word))

app = webapp2.WSGIApplication([
    ('/unit2/signup', SignUpPage),
    ('/unit2/welcome', WelcomePage),
    ('/unit2/rot13', Rot13Page)
 ], debug=True)
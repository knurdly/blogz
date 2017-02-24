#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2


from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t= jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def blog_key(name = 'default'):
        return db.Key.from_path('blogs', name)

class Home (Handler):
    def get(self, subject="", post="", created="", id =""):
        entry = db.GqlQuery("SELECT * FROM Entry ORDER By created DESC")
        self.render("frontpage.html", subject = subject, post = post, created = created, entry=entry, id = id)

class Blog(Handler):
    def get(self, subject="", post="", created="", id=""):
        entry = db.GqlQuery("SELECT * FROM Entry ORDER By created DESC limit 5")
    #    link = "/blog/" + entry.key().id()
        self.render("blog.html", subject = subject, post = post, created = created, entry=entry, id = id)

class ViewPostHandler(Handler):
    def get(self, id):
        single_entry = Entry.get_by_id(int(id))

        if single_entry:
            self.render("permalink.html", single_entry = single_entry)
        else:
            error = "Something went wrong."
            self.render("permalink.html", error = error)


class Entry(db.Model):
    subject = db.StringProperty(required = True)
    post = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class NewPost(Handler):

    def get(self):
        self.render('newpost.html')

    def post(self):

        subject = self.request.get("subject")
        post = self.request.get("post")


        if subject and post:
            e = Entry(subject = subject, post = post)
            e.put()
            self.redirect("/blog/%s" % e.key().id())

        else:

            error = "Both Subject and New Post must be filled out!"
            self.render('newpost.html', error = error, post = post, subject = subject)

app = webapp2.WSGIApplication([
    ('/', Home),
    ('/blog', Blog),
    webapp2.Route('/blog/<id:\d+>', ViewPostHandler),
    ('/newpost', NewPost),
], debug=True)

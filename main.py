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
import jinja2
import webapp2
import re
import random
import string
import hashlib
import hmac
import logging

import models

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "UElMsOPfxYrvaz2w"
BASE_LIKES = 0

def log(str):
    logging.info(str)

# Helper functions
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_salt(length = 5):
    return "".join(random.choice(string.letters) for x in xrange(length))

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Deprecated cookie functions
def make_user_id_hash(user_id, salt=None):
    if not salt:
        salt = make_salt()
    hash = hashlib.sha256(str(user_id) + salt).hexdigest()
    return '%s|%s' % (hash, salt)

def validate_user_id(user_id, hash):
    salt = hash.split('|')[-1]
    return hash == make_user_id_hash(user_id, salt)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def is_valid_username(username):
    """Returns True if the username is valid and False otherwise."""
    return username and USER_RE.match(username)

def get_username_error(username):
    """
    If the username is invalid, returns an error related to how it's
    invalid. Otherwise, does nothing.
    """
    if not username:
        return "Please enter a username."
    elif not USER_RE.match(username):
        return ("Please enter a username of between 3 to 20 alphanumeric"
                " characters.")

PASS_RE = re.compile(r"^.{3,20}$")
def is_valid_password(password):
    return password and PASS_RE.match(password)

def get_password_error(password):
    """
    If the password is invalid, returns an error related to how it's
    invalid. Otherwise, does nothing.
    """
    if not password:
        return "Please enter a password."
    elif not PASS_RE.match(password):
        return "Please enter a password of between 3 to 20 characters."

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def is_valid_email(email):
    return not email or EMAIL_RE.match(email)


# User functions
def make_pw_hash(username, password, salt=None):
    if not salt:
        salt = make_salt()
    hsh = hashlib.sha256(username + password + salt).hexdigest()
    return '%s|%s' % (hsh, salt)

def validate_password(username, password, hsh):
    salt = hsh.split('|')[1]
    return hsh == make_pw_hash(username, password, salt)

# Page handlers
class Handler(webapp2.RequestHandler):
    """Base Handler class. Has writing and rendering basics."""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class BlogHandler(Handler):
    """
    Base class for handling requests. Contains functions that would
    otherwise be duplicated in individual handlers.
    """
    def set_secure_cookie(self, name, val):
        """Adds the cookie with the given name and value."""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Validates the cookie and returns it's value."""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def page_login(self, user):
        """Sets the user's cookie."""
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """Removes the users's cookie."""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def get_previous_page(self):
        """
        Checks if there's a previous page cookie set. If so, returns
        it. Otherwise, returns an empty string.
        """
        previous_page = self.read_secure_cookie("page")

        if not previous_page:
            previous_page = "/"

        return previous_page

    def edit_post_redirect(self,
                           edit_post,
                           delete_post,
                           add_comment,
                           page,
                           post_id):
        """
        If edit_post, delete_post, or add_comment exist, will redirect
        the user to those pages while setting the requisite cookies.
        Otherwise, does nothing.
        """

        if edit_post or delete_post or add_comment:
            self.set_secure_cookie('post_id', str(post_id))
            self.set_secure_cookie('page', page)
            if edit_post:
                self.redirect('/editpost')
            if delete_post:
                self.redirect('/deletepost')
            if add_comment:
                self.redirect('/newcomment')
        else:
            pass

    def edit_comment_redirect(self,
                              edit_comment,
                              delete_comment,
                              comment_id,
                              page):
        """
        If edit_comment or delete_comment exist, will direct the user
        to those pages while setting the requisite cookies.
        Otherwise, does nothing.
        """
        if edit_comment or delete_comment:
            self.set_secure_cookie('comment_id', str(comment_id))
            self.set_secure_cookie('page', page)
            if edit_comment:
                self.redirect('/editcomment')
            if delete_comment:
                self.redirect('/deletecomment')
        else:
            pass

    def check_cancel_edit(self):
        """
        Performs cancelling edit logic.

        Checks if cancel was sent. If so, gets the previous page, then
        redirects to it.
        """
        cancel = self.request.get("cancel")

        if cancel:
            self.redirect(str(self.get_previous_page()))

    def get_post_data(self):
        """Gets the data in the post needed for"""

        data = {
            "like" : self.request.get("Likes"),
            "dislike" : self.request.get("Dislikes"),
            "post_id" : self.request.get("post_id"),
            "user_id" : self.request.get("user_id"),
            "edit_post" : self.request.get("edit_post"),
            "delete_post" : self.request.get("delete_post"),
            "add_comment" : self.request.get("add_comment"),
            "edit_comment" : self.request.get("edit_comment"),
            "delete_comment" : self.request.get("delete_comment")
        }

        return data

    def initialize(self, *args, **kwargs):
        """If user is logged in allows the handler to call the user."""
        webapp2.RequestHandler.initialize(self, *args, **kwargs)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and models.Users.by_id(int(uid))

class BlogFrontPageHandler(BlogHandler):
    """Handler for './blog'. """
    def render_front(self, error=""):
        """Gets the 10 most recent posts and sends them blog_front."""
        posts = models.BlogPosts.all().ancestor(models.blog_key()).order(
            '-created').fetch(limit=10)

        self.render("blog_front.html",
                    user=self.user,
                    posts=posts,
                    error=error)

    def get(self):
        """Called when the page loads. Calls render_front."""
        self.render_front()

    def post(self):
        """
        Gets the data sent by the f/e, then checks whether to add
        likes/dislikes, edit/ delete the post, add/ edit/ delete
        comments.
        """
        data = self.get_post_data()

        error = {}

        if data["like"] or data["dislike"]:
            error = models.BlogPosts.add_like_or_dislike(
                like=data["like"], dislike=data["dislike"],
                post_id=data["post_id"], user_id=data["user_id"])
            self.render_front(error)
        elif data["edit_post"] or data["delete_post"] or data["add_comment"]:
            self.edit_post_redirect(edit_post=data["edit_post"],
                                    delete_post=data["delete_post"],
                                    add_comment=data["add_comment"],
                                    page="blog",
                                    post_id=data["post_id"])
        elif data["edit_comment"] or data["delete_comment"]:
            comment_id = self.request.get("comment_id")
            self.edit_comment_redirect(edit_comment=data["edit_comment"],
                                       delete_comment=data["delete_comment"],
                                       comment_id=comment_id,
                                       page="blog")

class NewPostPageHandler(BlogHandler):
    """Handler for './newpost'."""
    def render_new_post(self, subject="", content="", error=""):
        """Renders the new post page."""
        self.render("new_post.html", 
                    subject=subject, 
                    content=content, 
                    error=error,
                    user=self.user)

    def get(self):
        """
        If the user is logged in renders the new post page. Otherwise
        redirects the user to sign up.
        """
        if self.user:
            self.render_new_post()
        else:
            self.redirect('/signup')

    def post(self):
        """
        Takes the subject and content strings. If there's data in
        both, creates the post and navigates to the static post page.
        Otherwise, renders the page with the error.
        """
        subject = self.request.get("subject")
        content = self.request.get("content")

        self.check_cancel_edit()

        if subject and content:
            post = models.BlogPosts(parent = models.blog_key(),
                                    subject = subject,
                                    content = content,
                                    created_user_id = (
                                        str(self.user.key().id())))
            post.put()

            self.redirect("/%s" % post.key().id())
        else:
            error = "We need both a subject and some content!"
            self.render_new_post(subject, content, error)

class StaticPostPageHandler(BlogHandler):
    """Handler for individual post pages."""
    def render_static_page(self, post_id, error=""):
        """
        Checks that the post exists. If it does, renders the page.
        If the page does not renders the page with a simple 404
        message.
        """
        post = models.BlogPosts.by_id(int(post_id))
        if post == None:
            error = {
                "text" : "Sorry, we can't find that post.",
                "code" : "404"
            }
        self.render('static_post.html',
                    post=post,
                    user=self.user,
                    error=error,
                    is_static=True)

    def get(self, post_id):
        """Renders static page on page load."""
        self.render_static_page(post_id=post_id)

    def post(self, post_id):
        """
        Gets the posted data, then check whether the to add a like/
        dislike, edit/ delete the post, or add/ edit/ delete a comment.
        """
        data = self.get_post_data()

        error = {}

        if data["like"] or data["dislike"]:
            error = models.BlogPosts.add_like_or_dislike(
                like=data["like"], dislike=data["dislike"],
                post_id=data["post_id"], user_id=data["user_id"])
            self.render_static_page(post_id=data["post_id"], error = error)
        elif data["edit_post"] or data["delete_post"] or data["add_comment"]:
            self.edit_post_redirect(edit_post=data["edit_post"],
                                    delete_post=data["delete_post"],
                                    add_comment=data["add_comment"],
                                    page=str(data["post_id"]),
                                    post_id=data["post_id"])
        elif data["edit_comment"] or data["delete_comment"]:
            comment_id = self.request.get("comment_id")
            self.edit_comment_redirect(edit_comment=data["edit_comment"],
                                       delete_comment=data["delete_comment"],
                                       comment_id=comment_id,
                                       page=str(data["post_id"]))

class UserSignUpHandler(BlogHandler):
    """Handler for './signup'."""
    def get(self):
        """
        Checks if the user is logged in. If so, redirects to the
        welcome page. Otherwise, renders the signup form.
        """
        if self.user:
            self.redirect('/welcome')
        else:
            self.render('signup.html')

    def post(self):
        """
        Gets all the users. Then validates the inputs. If they're
        valid, create the user and redirect the user to the welcome
        page. Otherwise, render the page with errors.
        """
        # Create users db
        users = models.db.GqlQuery("SELECT * FROM Users "
                                   "ORDER BY created DESC ")

        # Get user info
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify_password = self.request.get('verify')
        self.email = self.request.get('email')
        are_errors = False

        params = dict(username = self.username,
                      email = self.email)

        # Check the user's input
        if not is_valid_username(self.username):
            params['username_error'] = get_username_error(self.username)
            are_errors = True
            
        if not is_valid_password(self.password):
            params['password_error'] = get_password_error(self.password)
            are_errors = True
        elif self.password != self.verify_password:
            params['verify_password_error'] = (
                "Please enter a matching password.")
            are_errors = True
        else:
            # hash the password as soon as we decide it's valid
            self.hashed_password = make_pw_hash(self.username, self.password)

        if self.email:
            if not is_valid_email(self.email):
                params['email_error'] = "That's not a valid email."
                are_errors = True

        if are_errors:
            self.render('signup.html', **params)
        else:
            # Check if the username entered already exists
            user = models.Users.by_name(self.username)
            if user:
                params['username_error'] = "That user already exists."
                self.render('signup.html', **params)
            else:
                # Create the user in the db
                user = models.Users.register(self.username,
                                             self.hashed_password,
                                             self.email)
                user.put()

                self.page_login(user)
                self.redirect('/welcome')

class WelcomePageHandler(BlogHandler):
    """Handler for './welcome'."""
    def get(self):
        """
        Checks whether the user is logged in. If so, renders the
        welcome page. If not, redirects the user to the signup page.
        """
        if self.user:
            self.render('welcome.html', user = self.user)
        else:
            self.redirect('/signup')

class MyPostsPageHandler(BlogHandler):
    """Handler for './myposts'."""
    def render_my_posts(self, error = ""):
        """Gets the users posts, then renders the my posts page."""
        user = self.user
        posts = self.user.get_users_posts(self.user.key().id())
        self.render('my_posts.html', user = user, posts = posts, error = error)

    def get(self):
        """
        Checks if the user is logged in. If so, renders the my posts
        page. Otherwise, redirects to the signup page.
        """
        if self.user:
            self.render_my_posts()
        else:
            self.redirect('/signup')

    def post(self):
        """
        Gets the posted data, then checks whether to edit/delete a
        post, or add/ edit/ delete a comment.
        """
        data = self.get_post_data()
        
        if data["edit_post"] or data["delete_post"] or data["add_comment"]:
            self.edit_post_redirect(edit_post=data["edit_post"],
                                    delete_post=data["delete_post"],
                                    add_comment=data["add_comment"],
                                    page="myposts",
                                    post_id=data["post_id"])
        elif data["edit_comment"] or data["delete_comment"]:
            comment_id = self.request.get("comment_id")
            self.edit_comment_redirect(edit_comment=data["edit_comment"],
                                       delete_comment=data["delete_comment"],
                                       comment_id=comment_id,
                                       page="myposts")

class DeletePostPage(BlogHandler):
    """Handler for './deletepost'."""

    def render_delete_post_page(self):
        """
        Renders the delete post page.

        Checks if the post exists. If it does, checks if the user
        created the post. If so, renders the delete post page.
        Otherwise, redirects to the previous page.
        """
        post_id = self.read_secure_cookie("post_id")
        previous_page = self.get_previous_page()

        if post_id:
            post = models.BlogPosts.by_id(int(post_id))
            if not str(self.user.key().id()) == str(post.created_user_id):
                self.redirect('/')
            self.render('deletepost.html', user = self.user, post_id = post_id)
        else:
            self.redirect('/%s' % previous_page)

    def get(self):
        """
        Checks if the user is logged in. If so, renders the delete
        post page. Otherwise, redirects the user to signup page.
        """
        if self.user:
            self.render_delete_post_page()
        else:
            self.redirect('/signup')

    def post(self):
        """
        Gets the post data, then checks if the response was yes. If
        so, deletes the page. Otherwise redirects to the previous page.
        """
        post_id = self.request.get("post_id")
        resp_yes = self.request.get("yes")
        previous_page = self.get_previous_page()

        if resp_yes:
            # If the user came from the post page, redirect to the front page
            if previous_page == post_id:
                previous_page = "/"
            post = models.BlogPosts.by_id(int(post_id))
            post.delete()

        # delete previous cookies
        self.set_secure_cookie('page', "")
        self.set_secure_cookie('post_id', "")
        self.redirect('/%s' % previous_page) 

class EditPageHandler(BlogHandler):
    """Handler for './editpost'."""
    def render_edit_page(self, subject = "", content = "", error = ""):
        """
        Renders the edit post page.

        Gets the post id, then checks that,
        if subject or content hasn't been sent. If either hasn't, then
        checks if the post id has data. If it does, checks that is was
        created by the current user. If it wasn't, then the user is
        redirected to the previous page. If it was, then sets the
        subject and content for the post and renders the page.
        Otherwise, redirects the user to previous page.
        """
        post_id = self.read_secure_cookie("post_id")
        previous_page = self.get_previous_page()

        if not subject or not content:
            if post_id:
                post = models.BlogPosts.by_id(int(post_id))
                if not str(self.user.key().id()) == str(post.created_user_id):
                    self.redirect('/%s' % previous_page)
                else:
                    subject = post.subject
                    content = post.content
            else:
                self.redirect('/%s' % previous_page)
        self.render('edit_post.html',
                    user = self.user,
                    subject = subject,
                    content = content,
                    error = error)

    def get(self):
        """
        For the first time rendering the page. Checks if the user is
        logged in. If so, renders the edit page. Otherwise, redirects
        to the signup page.
        """
        if self.user:
            self.render_edit_page()
        else:
            self.redirect('/signup')

    def post(self):
        """
        Gets the posted/ cookie data, then checks if both subject
        and content have data. If they do, edits the post, deletes
        the cookies, and redirects to the previous page. Otherwise,
        renders the page with the error.
        """
        subject = self.request.get("subject")
        content = self.request.get("content")
        post_id = self.read_secure_cookie("post_id")
        previous_page = self.get_previous_page()

        self.check_cancel_edit()

        if subject and content:
            if post_id:
                post = models.BlogPosts.by_id(int(post_id))
                post.subject = subject
                post.content = content
                post.put()

                self.set_secure_cookie("post_id", "")
                self.set_secure_cookie("page", "")
                self.redirect('/%s' % previous_page)
            else:
                error = "We need both a subject and some content!"
                self.render_edit_page(subject, content, error)
        else:
            error = "We need both a subject and some content!"
            self.render_edit_page(subject, content, error)

class NewCommentPageHandler(BlogHandler):
    """Handler for the './newcomment' page."""

    def render_new_comment_page(self, subject="", content="", error=""):
        """Renders the new comment page with the given content."""
        post_id = self.read_secure_cookie("post_id")
        if post_id:
            post = models.BlogPosts.by_id(int(post_id))
            if not post:
                self.redirect('/')
            else:
                self.render("new_comment.html", 
                            subject=subject,
                            content=content,
                            error=error,
                            user=self.user)
        else:
            self.redirect('/')

    def get(self):
        """
        Checks if the user is signed it. If so, renders the new
        comment page. Otherwise, redirects to the sign up page.
        """
        if self.user:
            self.render_new_comment_page()
        else:
            self.redirect('/signup')

    def post(self):
        """
        Gets the submitted data, then checks if both subject and
        content exist. If so, adds the comment, deletes the cookies,
        and redirects to the previous page. Otherwise, renders the
        page with errors.
        """
        subject = self.request.get("subject")
        content = self.request.get("content")
        post_id = self.read_secure_cookie("post_id")
        previous_page = self.get_previous_page()

        self.check_cancel_edit()

        if subject and content:
            models.Comments.add_comment(subject=subject,
                                        content=content,
                                        post_id=post_id,
                                        user_id=str(self.user.key().id()))

            self.set_secure_cookie("post_id", "")
            self.set_secure_cookie("page", "")
            self.redirect("/%s" % previous_page)
        else:
            error = "We need both a subject and some content!"
            self.render_new_comment_page(subject, content, error)

class EditCommentHandler(BlogHandler):
    """Handler for the './editcomment' page."""

    def render_edit_comment(self, subject = "", content = "", error = ""):
        """
        Renders the edit comments page.

        Checks if theres a subject
        or content. If neither then checks if there's a comment id.
        If there's not, redirects to the the previous page. If there
        is, gets the comment from the db, then checks that the user
        created the comment. If not, redirects to the previous page.
        If so, sets the comment subject and content, then renders
        the edit comment page.
        """
        comment_id = self.read_secure_cookie("comment_id")
        previous_page = self.get_previous_page()
        
        if not subject or not content:
            if comment_id:
                comment = models.Comments.by_id(int(comment_id))
                if comment:
                    if not str(self.user.key().id()) == str(
                        comment.created_user_id):
                        self.redirect('/%s' % previous_page)
                    else:
                        subject = comment.subject
                        content = comment.content
                else:
                    self.redirect('/%s' % previous_page)
            else:
                self.redirect('/%s' % previous_page)
        self.render('edit_comment.html',
                    user = self.user,
                    subject = subject,
                    content = content,
                    error = error)

    def get(self):
        """
        Checks if the user is signed it. If so, renders the edit
        comment page. Otherwise, redirects to the sign up page.
        """
        if self.user:
            self.render_edit_comment()
        else:
            self.redirect('/signup')

    def post(self):
        """
        Gets the submitted data, then checks if subject and content
        have data. If so, edits the comment, delets the comment_id
        and page cookies, then redirects to the previous page.
        Otherwise, renders the page with the error.
        """
        subject = self.request.get("subject")
        content = self.request.get("content")
        comment_id = self.read_secure_cookie("comment_id")
        previous_page = self.get_previous_page()

        self.check_cancel_edit()

        error = "We need both a subject and some content!"

        if subject and content:
            if comment_id:
                comment = models.Comments.by_id(int(comment_id))
                comment.subject = subject
                comment.content = content
                comment.put()

                self.set_secure_cookie("comment_id", "")
                self.set_secure_cookie("page", "")
                self.redirect('/%s' % previous_page)
            else:
                self.render_edit_comment(subject, content, error)
        else:
            self.render_edit_comment(subject, content, error)

class DeleteCommentPageHandler(BlogHandler):
    """Handler for './deletecomment' page."""

    def render_delete_comment_page(self):
        """
        Renders the delete comment page.

        Gets the cookies, checks that the comment with the comment id
        exists and was created by the user. If it was, renders the
        delete comment page. Otherwise, redirects the user to the
        previous page.
        """
        comment_id = self.read_secure_cookie("comment_id")
        previous_page = self.get_previous_page()

        if comment_id:
            comment = models.Comments.by_id(int(comment_id))
            if comment:
                if not (
                    str(self.user.key().id()) == str(comment.created_user_id)):
                    self.redirect('/%s' % previous_page)
                self.render('delete_comment.html',
                             user=self.user,
                             comment_id=comment_id)
            else:
                self.redirect('/%s' % previous_page)    
        else:
            self.redirect('/%s' % previous_page)

    def get(self):
        """
        Checks if the user is logged in. If so, renders the delete
        comment page. Otherwise, renders the delete comment page.
        """
        if self.user:
            self.render_delete_comment_page()
        else:
            self.redirect('/signup')

    def post(self):
        comment_id = self.request.get("comment_id")
        resp_yes = self.request.get("yes")
        resp_no = self.request.get("no")
        previous_page = self.get_previous_page()

        if resp_yes:
            comment = models.Comments.by_id(int(comment_id))
            comment.delete()

        # delete previous cookies
        self.set_secure_cookie('page', "")
        self.set_secure_cookie('post_id', "")
        self.redirect('/%s' % previous_page)        

class LoginPageHandler(BlogHandler):
    """Handler for the login page, './login'."""
    def render_login_page(self, password_error=""):
        """Renders the login page."""
        self.render('login.html', password_error=password_error)

    def get(self):
        """
        Checks if the user is logged in. If so, redirects to the
        welcome page. Otherwise, renders the login page.
        """
        if self.user:
            self.redirect('/welcome')
        else:
            self.render_login_page()

    def post(self):
        """
        Gets the posted data, then attempts to log the user in. If
        it's successful, redirect the user to the welcome page.
        Otherwise, render the login page with the error.
        """
        self.username = self.request.get('username')
        self.password = self.request.get('password')

        user = models.Users.user_login(self.username, self.password)
        
        if self.username and self.password:
            if user:
                self.page_login(user)
                self.redirect('/welcome')
            else:
                self.render_login_page(password_error = "Invalid Login")
        else:
            self.render_login_page(password_error = "Invalid Login")

class LogoutHandler(BlogHandler):
    """
    Handler for './logout'. Deletes the user cookie and redirects to
    the front page.
    """
    def get(self):
        self.logout()
        self.redirect('/blog')

class HomePageHandler(BlogHandler):
    """
    Handler for the base url. Redirects the user to the blog
    front page.
    """
    def get(self):
        self.redirect('/blog')       

      
app = webapp2.WSGIApplication([('/blog', BlogFrontPageHandler),
                               ('/newpost', NewPostPageHandler),
                               ('/(\d+)', StaticPostPageHandler),
                               ('/signup', UserSignUpHandler),
                               ('/welcome', WelcomePageHandler),
                               ('/login', LoginPageHandler),
                               ('/logout', LogoutHandler),
                               ('/', HomePageHandler),
                               ('/myposts', MyPostsPageHandler),
                               ('/deletepost', DeletePostPage),
                               ('/editpost', EditPageHandler),
                               ('/newcomment', NewCommentPageHandler),
                               ('/editcomment', EditCommentHandler),
                               ('/deletecomment', DeleteCommentPageHandler)
                               ],
                               debug=True)

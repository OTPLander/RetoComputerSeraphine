import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()  # Load .env file
A=os.getenv("SMTP2GO_PASSWORD")



print(A)
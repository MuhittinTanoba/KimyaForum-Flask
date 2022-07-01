from flask import Flask, render_template, flash, redirect, url_for, session, logging, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, DataRequired
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/muhit/Desktop/çalışma/forum.db'
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
bootstrap = Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'girisyap'
login_manager.login_message = "Bu sayfayı görüntüleyebilmek için giriş yapınız."
login_manager.login_message_category = "danger"

class LoginForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[InputRequired(), Length(min=4, max=30), DataRequired(message="Bu alan boş bırakılamaz.")])
    password = PasswordField('Şifre', validators=[InputRequired(), Length(min=6, max=30)])
    remember = BooleanField("Beni hatırla")

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(message="Bu alan boş bırakılamaz."), Email(message="Lütfen geçerli bir mail adresi giriniz.")])
    username = StringField('Kullanıcı Adı', validators=[DataRequired(message="Bu alan boş bırakılamaz."), Length(min=4, max=30, message="Girdiğiniz kullanıcı adının karakter sayısı 4'den fazla 20'den az olmalıdır.")])
    password = PasswordField('Şifre', validators=[InputRequired(message="Bu alan boş bırakılamaz."), Length(min=6, max=30, message="Belirlediğiniz şifrenin karakter sayısı 6'dan fazla 30'dan az olmalıdır.")])

#db
class Bilgiler(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(20), unique=False, nullable=False)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    return Bilgiler.query.get(int(user_id))

@app.route('/forum')
@login_required
def forum():
    return render_template("forum.html", name = current_user.username)

@app.route('/kayit', methods = ["GET","POST"])
def kayit():
    form = RegisterForm()
    if "logged_in" in session:
        flash("Zaten giriş yapmışsınız.","danger")
        return redirect(url_for("forum"))
    
    if form.validate_on_submit():
        user = Bilgiler.query.filter_by(username=form.username.data).first()
        mail_check = Bilgiler.query.filter_by(email=form.email.data).first()
        if user or mail_check:
            flash("Kullanıcı adı veya mail adresi daha önce kullanılmış.","danger")
            redirect(url_for("kayit"))
        else:
            hashed_password = generate_password_hash(form.password.data, method="sha256")
            yeniveri = Bilgiler(username = form.username.data, email = form.email.data, password = hashed_password )
            db.session.add(yeniveri)
            db.session.commit()


            flash("Başarıyla kayıt oldunuz, giriş yapabilirsiniz.", "success")
            return redirect(url_for('girisyap'))
    
    
    return render_template("kayit.html", form=form)

@app.route('/giris', methods = ["GET","POST"])
def girisyap():
    form = LoginForm()
    if "logged_in" in session:
        flash("Zaten giriş yapmışsınız.","danger")
        return redirect(url_for("forum"))
    if form.validate_on_submit():
        user = Bilgiler.query.filter_by(username=form.username.data).first()
        if user:  
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                
                session["logged_in"] = True

                flash("Başarıyla giriş yaptınız.","success")
                return redirect(url_for("forum"))
            else:
                flash("Yanlış şifre girdiniz tekrar deneyiniz.","danger")                    
                return redirect(url_for("girisyap"))
        else:
            flash("Böyle bir kullanıcı bulunamadı.","danger")
            return redirect(url_for("girisyap"))

    return render_template("girisyap.html", form = form)


@app.route('/home')
@app.route('/')
def anasayfa():
    return render_template("anasayfa.html")

@app.route('/hakkimizda')
def hakkimizda():
    return render_template("hakkimizda.html")

@app.route('/rp_nedir')
@login_required
def rp_nedir():
    return render_template("rp_nedir.html")


@app.route('/cikis')
@login_required
def cikis():
    session.clear()
    logout_user()
    return redirect(url_for('anasayfa'))



#sınıflar
@app.route('/9sinif')
def dokuzsinif():
    return render_template("9sinif.html")
@app.route('/10sinif')
def onsinif():
    return render_template("10sinif.html")
@app.route('/11sinif')
def onbirsinif():
    return render_template("11sinif.html")
@app.route('/12sinif')
def onikisinif():
    return render_template("12sinif.html")
@app.route('/TYT')
def tytsinav():
    return render_template("tyt.html")
@app.route('/AYT')
def aytsinav():
    return render_template("ayt.html")





if __name__ == "__main__" :
    db.create_all()
    app.run(debug=True)
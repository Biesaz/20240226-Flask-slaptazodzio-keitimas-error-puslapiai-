# https://github.com/DonatasNoreika/Python-pamokos/wiki/Flask:-slapta%C5%BEod%C5%BEio-keitimas,-error-puslapiai

# Flask: slaptažodžio keitimas, error puslapiai
# DonatasNoreika edited this page on Mar 24, 2021 · 13 revisions

# Slaptažodžio keitimas
# Tam, kad vartotojas galėtų pasikeisti pamirštą slaptažodį, sukursime jam laikinai veikiančią nuorodą ir išsiųsime el. paštu. Paspaudęs nuorodą, jis pateks į puslapį, kur pagal savo žetoną (token), galės atnaujinti slaptažodį.

# Į prisijungimo html failą įdedame nuorodą į slaptažodžio pakeitimo funkciją:
# {% extends "base.html" %}
# {% block content %}
#     <div class="content-section">
#         <form method="POST" action="">
#             {{ form.hidden_tag() }}
#             <fieldset class="form-group">
#                 <legend class="border-bottom mb-4">Prisijunkite</legend>
#                 <div class="form-group">
#                     {{ form.el_pastas.label(class="form-control-label") }}
#                     {% if form.el_pastas.errors %}
#                         {{ form.el_pastas(class="form-control form-control-lg is-invalid") }}
#                         <div class="invalid-feedback">
#                             {% for error in form.el_pastas.errors %}
#                                 <span>{{ error }}</span>
#                             {% endfor %}
#                         </div>
#                     {% else %}
#                         {{ form.el_pastas(class="form-control form-control-lg") }}
#                     {% endif %}
#                 </div>
#                 <div class="form-group">
#                     {{ form.slaptazodis.label(class="form-control-label") }}
#                     {% if form.slaptazodis.errors %}
#                         {{ form.slaptazodis(class="form-control form-control-lg is-invalid") }}
#                         <div class="invalid-feedback">
#                             {% for error in form.slaptazodis.errors %}
#                                 <span>{{ error }}</span>
#                             {% endfor %}
#                         </div>
#                     {% else %}
#                         {{ form.slaptazodis(class="form-control form-control-lg") }}
#                     {% endif %}
#                 </div>
#                 <div class="form-check">
#                     {{ form.prisiminti(class="form-check-input") }}
#                     {{ form.prisiminti.label(class="form-check-label") }}
#                 </div>
#             </fieldset>
#             <div class="form-group">
#                 {{ form.submit(class="btn btn-outline-info") }}
#                 <small class="text-muted ml-2">
#                     <a href="{{ url_for('reset_request') }}">Pamiršote slaptažodį?</a>
#                 </small>
#             </div>
#         </form>
#     </div>
#     <div class="border-top pt-3">
#         <small class="text-muted">
# <!--            Already Have An Account? <a class="ml-2" href="{{ url_for('index') }}">Sign In</a>-->
#         </small>
#     </div>
# {% endblock content %}
# Eilutėje Pamiršote slaptažodį? nukreipiama į Flask funkciją reset_request

# Pridedame slaptažodžio atnaujinimo Flask funkciją:
# @app.route("/reset_password", methods=['GET', 'POST'])
# def reset_request():
#     if current_user.is_authenticated:
#         return redirect(url_for('home'))
#     form = forms.UzklausosAtnaujinimoForma()
#     if form.validate_on_submit():
#         user = Vartotojas.query.filter_by(el_pastas=form.el_pastas.data).first()
#         send_reset_email(user)
#         flash('Jums išsiųstas el. laiškas su slaptažodžio atnaujinimo instrukcijomis.', 'info')
#         return redirect(url_for('prisijungti'))
#     return render_template('reset_request.html', title='Reset Password', form=form)
# Paaiškinimai:

# Funkcija atidaro reset_request.html failą, iš kurio pasiima įvestą vartotojo el. pašto adresą.
# Tam sukuriama papildoma flask-wtf forma.
# Patvirtinus formą, kviečiama sent_reset_email funkcija su paduotu vartotoju ir jam išsiunčiamas el. laiškas.
# Parodoma flash žinutė ir gražinama į prisijungimo langą.
# Slaptažodžio atnaujinimo nuorodos html
# (kur vartotojas įveda savo el. pašto adresą): reset_request.html failas:

# {% extends "base.html" %}
# {% block content %}
#     <div class="content-section">
#         <form method="POST" action="">
#             {{ form.hidden_tag() }}
#             <fieldset class="form-group">
#                 <legend class="border-bottom mb-4">Slaptažodžio pakeitimas</legend>
#                 <div class="form-group">
#                     {{ form.el_pastas.label(class="form-control-label") }}
#                     {% if form.el_pastas.errors %}
#                         {{ form.el_pastas(class="form-control form-control-lg is-invalid") }}
#                         <div class="invalid-feedback">
#                             {% for error in form.el_pastas.errors %}
#                                 <span>{{ error }}</span>
#                             {% endfor %}
#                         </div>
#                     {% else %}
#                         {{ form.el_pastas(class="form-control form-control-lg") }}
#                     {% endif %}
#                 </div>
#             </fieldset>
#             <div class="form-group">
#                 {{ form.submit(class="btn btn-outline-info") }}
#             </div>
#         </form>
#     </div>
# {% endblock content %}
# Slaptažodžio atnaujinimo nuorodos forma
# class UzklausosAtnaujinimoForma(FlaskForm):
#     el_pastas = StringField('El. paštas', validators=[DataRequired(), Email()])
#     submit = SubmitField('Gauti')

#     def validate_email(self, el_pastas):
#         user = app.Vartotojas.query.filter_by(el_pastas=el_pastas.data).first()
#         if user is None:
#             raise ValidationError('Nėra paskyros, registruotos šiuo el. pašto adresu. Registruokitės.')
# Šiame etape pasiimamas tik vartotojo el. pašto adresas. Bet patikrinama, ar yra vartotojas su tokiu el. pašto adresu.

# Pridedame el. laiško siuntimo funkciją:
# (Jame siunčiama slaptažodžio atnaujinimo nuoroda)

# from flask_mail import Message, Mail

# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = MAIL_USERNAME
# app.config['MAIL_PASSWORD'] = MAIL_PASSWORD

# mail = Mail(app)

# def send_reset_email(user):
#     token = user.get_reset_token()
#     msg = Message('Slaptažodžio atnaujinimo užklausa',
#                   sender='el@pastas.lt',
#                   recipients=[user.el_pastas])
#     msg.body = f'''Norėdami atnaujinti slaptažodį, paspauskite nuorodą:
#     {url_for('reset_token', token=token, _external=True)}
#     Jei jūs nedarėte šios užklausos, nieko nedarykite ir slaptažodis nebus pakeistas.
#     '''
#     mail.send(msg)
# Paaiškinimai:

# Iš flask_mail importuojami reikiami dalykai
# Inicijuojamas mail objektas
# Per app sukonfiguruojamas el. pašto serveris (el. pašto dėžutė, per kurią bus siunčiami laiškai). Jei tai gmail dėžutė, nepamirškite įjungti leidimo mažiau saugioms programoms (žr. paskaitą apie el. laiškų siuntimą per python). Taip pat gali būti, kad pašto serveris laiškus iš jūsų programos blokuos.
# Per vartotojo metodą get_reset_token() sugeneruojamas unikalus atnaujinimo žetonas, kuris bus naudojamas slaptažodžio atnaujinimo nuorodai suformuoti.
# Sugeneruojamas el. laiškas su nuorodą į kitą Flask funkciją reset_token() bei gautu žetonu.
# Laiškas išsiunčiamas per mail objektą.
# SVARBU: mail = Mail(app) objektą inicijuokite po konfiguracijos nustatymo, o ne prieš (nes kitaip siuntimas neveiks).
# Žetono (token) sugeneravimo metodas:
# from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

# class Vartotojas(db.Model, UserMixin):
#     __tablename__ = "vartotojas"
#     id = db.Column(db.Integer, primary_key=True)
#     vardas = db.Column("Vardas", db.String(20), unique=True, nullable=False)
#     el_pastas = db.Column("El. pašto adresas", db.String(120), unique=True, nullable=False)
#     nuotrauka = db.Column(db.String(20), nullable=False, default='default.jpg')
#     slaptazodis = db.Column("Slaptažodis", db.String(60), unique=True, nullable=False)

#     def get_reset_token(self, expires_sec=1800):
#         s = Serializer(app.config['SECRET_KEY'], expires_sec)
#         return s.dumps({'user_id': self.id}).decode('utf-8')
# Iš itsdangerous importuojame serializatorių
# Jam paduodame mūsų programos SECRET_KEY ir laiką, kurį žetonas bus aktyvus
# Gražiname sugeneruotą kodą (žetoną), kuris bus įdedamas į laikiną nuorodą pašte
# Kai vartotojas paspaudžia nuorodą laiške
# Slaptažodžio nunulinimo Flask metodas:
# @app.route("/reset_password/<token>", methods=['GET', 'POST'])
# def reset_token(token):
#     if current_user.is_authenticated:
#         return redirect(url_for('home'))
#     user = Vartotojas.verify_reset_token(token)
#     if user is None:
#         flash('Užklausa netinkama arba pasibaigusio galiojimo', 'warning')
#         return redirect(url_for('reset_request'))
#     form = forms.SlaptazodzioAtnaujinimoForma()
#     if form.validate_on_submit():
#         hashed_password = bcrypt.generate_password_hash(form.slaptazodis.data).decode('utf-8')
#         user.slaptazodis = hashed_password
#         db.session.commit()
#         flash('Tavo slaptažodis buvo atnaujintas! Gali prisijungti', 'success')
#         return redirect(url_for('prisijungti'))
#     return render_template('reset_token.html', title='Reset Password', form=form)
# Iš vartotojo klasės kviečiamas metodas verify_reset_token(token), kuris patikrina, ar vartotojo nuorodos žetonas dar aktyvus ir gražina susijusio vartotojo objektą.
# Jei ši funkcija objekto negražina, rodoma klaida, kad nuoroda pasibaigus arba negalioja ir vėl nukreipiama į slaptažodžio atnaujinimo puslapį.
# Inicijuojama slaptažodžio atnaujinimo forma ir vartotojas nukreipiamas į reset_token.html puslapį, iš kurio pasiimamas naujas slaptažodis.
# Jei naujas slaptažodis patvirtinamas, jis vėl encryptinamas ir pakeičiamas to vartotojo slaptažodis duomenų bazėje.
# Žetono patvirtinimo metodas Vartotojo klasėje:
# verify_reset_token(token):

# class Vartotojas(db.Model, UserMixin):
#     __tablename__ = "vartotojas"
#     id = db.Column(db.Integer, primary_key=True)
#     vardas = db.Column("Vardas", db.String(20), unique=True, nullable=False)
#     el_pastas = db.Column("El. pašto adresas", db.String(120), unique=True, nullable=False)
#     nuotrauka = db.Column(db.String(20), nullable=False, default='default.jpg')
#     slaptazodis = db.Column("Slaptažodis", db.String(60), unique=True, nullable=False)

#     def get_reset_token(self, expires_sec=1800):
#         s = Serializer(app.config['SECRET_KEY'], expires_sec)
#         return s.dumps({'user_id': self.id}).decode('utf-8')

#     @staticmethod
#     def verify_reset_token(token):
#         s = Serializer(app.config['SECRET_KEY'])
#         try:
#             user_id = s.loads(token)['user_id']
#         except:
#             return None
#         return Vartotojas.query.get(user_id)
# Statinis metodas verify_reset_token(token) inicijuoja serializatorių.
# Iš jo bandomas gauti vartotojo ID
# Jei pavyksta, gražinamas vartotojo objektas (rastas pagal ID), jei ne (pvz. jei žetono galiojimas pasibaigęs) - gražinama None.
# Slaptažodžio nunulinimo forma:
# class SlaptazodzioAtnaujinimoForma(FlaskForm):
#     slaptazodis = PasswordField('Slaptažodis', validators=[DataRequired()])
#     patvirtintas_slaptazodis = PasswordField('Pakartokite slaptažodį', validators=[DataRequired(), EqualTo('slaptazodis')])
#     submit = SubmitField('Atnaujinti Slaptažodį')
# Joje reikia tik patvirtinto slaptažodžio
# Slaptažodžio nunulinimo puslapio html:
# {% extends "base.html" %}
# {% block content %}
#     <div class="content-section">
#         <form method="POST" action="">
#             {{ form.hidden_tag() }}
#             <fieldset class="form-group">
#                 <legend class="border-bottom mb-4">Slaptažodžio pakeitimas</legend>
#                 <div class="form-group">
#                     {{ form.slaptazodis.label(class="form-control-label") }}
#                     {% if form.slaptazodis.errors %}
#                         {{ form.slaptazodis(class="form-control form-control-lg is-invalid") }}
#                         <div class="invalid-feedback">
#                             {% for error in form.slaptazodis.errors %}
#                                 <span>{{ error }}</span>
#                             {% endfor %}
#                         </div>
#                     {% else %}
#                         {{ form.slaptazodis(class="form-control form-control-lg") }}
#                     {% endif %}
#                 </div>
#                 <div class="form-group">
#                     {{ form.patvirtintas_slaptazodis.label(class="form-control-label") }}
#                     {% if form.patvirtintas_slaptazodis.errors %}
#                         {{ form.patvirtintas_slaptazodis(class="form-control form-control-lg is-invalid") }}
#                         <div class="invalid-feedback">
#                             {% for error in form.patvirtintas_slaptazodis.errors %}
#                                 <span>{{ error }}</span>
#                             {% endfor %}
#                         </div>
#                     {% else %}
#                         {{ form.patvirtintas_slaptazodis(class="form-control form-control-lg") }}
#                     {% endif %}
#                 </div>
#             </fieldset>
#             <div class="form-group">
#                 {{ form.submit(class="btn btn-outline-info") }}
#             </div>
#         </form>
#     </div>
# {% endblock content %}
# Klaidų (404, 403, 500) puslapių kūrimas
# Sukuriame klaidų sugaudymo Flask funkcijas
# @app.errorhandler(404)
# def klaida_404(klaida):
#     return render_template("404.html"), 404

# @app.errorhandler(403)
# def klaida_403(klaida):
#     return render_template("403.html"), 403

# @app.errorhandler(500)
# def klaida_500(klaida):
#     return render_template("500.html"), 500
# Ant funkcijų turi būti spec. dekoratorius su paduotu klaidos kodu. Gražinamas klaidos html puslapis ir klaidos kodas.

# Sukuriame html puslapius, kurie bus rodomi įvykus tam tikrai klaidai:
# 404:

# {% extends "base.html" %}

# {% block content %}
#     <div class="content-section">
#         <h1>Oops. Puslapis nerastas (404)</h1>
#         <p>Šis puslapis neegzistuoja. Pabandykite įvesti kitą adresą</p>.
#     </div>
# {% endblock %}
# 403:

# {% extends "base.html" %}

# {% block content %}
#     <div class="content-section">
#         <h1>Jūs neturite teisių atlikti šio veiksmo (403)</h1>
#         <p>Patikrinkite savo paskyrą ir bandykite dar kartą</p>.
#     </div>
# {% endblock %}
# 500:

# {% extends "base.html" %}

# {% block content %}
#     <div class="content-section">
#         <h1>Kažkas negerai (500)</h1>
#         <p>Serveris laikinai neveikia. Bandykite vėliau</p>.
#     </div>
# {% endblock %}
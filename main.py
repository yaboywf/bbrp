from flask import Flask, render_template, request, redirect, session, abort, current_app, render_template_string, flash, Markup, make_response, send_from_directory
import bcrypt, re, uuid, pytz
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from flask_talisman import Talisman
from datetime import datetime as dt
from urllib.parse import urlparse
from flask_cors import CORS
from googletrans import Translator

app = Flask(__name__,static_folder='static', static_url_path='/static')
link = "bb21.pythonanywhere.com"
translator = Translator()
CORS(app)
blocked_ips_file = "/home/BB21/mysite/text/blacklist.txt"
max_login_attempts = 4
Main_code = "Admin_BB21@BBRP"
email_code = "kmrm dulw hxhy hgpt"
guest_code = "Guest_BB21"
check_guest_password = "/home/BB21/mysite/text/password.txt"
key1 = "fBlCO7_OTJXUHY8tFsE4Lr_HgOLs8_b2ske-xMDE1kk="
app.secret_key = "1234567890!@#$%^&*()QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm"
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'dylanyeo918@gmail.com'
app.config['MAIL_PASSWORD'] = email_code
app.config['MAIL_USE_TLS'] = True
mail = Mail(app)
global_shop_open = False
cipher = Fernet(key1)
talisman = Talisman(app,

content_security_policy={
	'default-src': '\'self\'',
	'script-src': ['\'self\'', 'https://cdn.jsdelivr.net', '\'unsafe-inline\''],
	'style-src': ['\'self\'', 'https://fonts.googleapis.com', 'https://cdn.jsdelivr.net', '\'unsafe-inline\''],
	'font-src': ['\'self\'', 'https://fonts.googleapis.com/css', 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-solid-900.ttf', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-solid-900.woff2', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-v4compatibility.ttf', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-v4compatibility.woff2', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-brands-400.woff2', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-brands-400.ttf', 'https://fonts.gstatic.com'],
	'img-src': ['\'self\'', 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css',],
	'media-src': '\'self\'',
	'base-uri': ['\'self\'', 'https://www.bb.org.sg', 'https://www.instagram.com/bb21coy', "https://shorturl.at/kmtG0", "https://members.bb.org.sg", "https://shorturl.at/eqsFY", "https://shorturl.at/ptJWY"],
	'object-src': ['\'self\'', "https://shorturl.at/kmtG0"],
},
session_cookie_secure=True,
session_cookie_http_only=True,
referrer_policy='same-origin',
force_https=True)

@app.after_request
def add_headers(response):
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cache-Control'] = 'public, must-revalidate, max-age=31536000'
    return response

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

def generate_unique_cookie_id():
    unique_id = str(uuid.uuid4().int)[:7]
    return unique_id

@app.route('/')
def index():
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    user_id = request.cookies.get('user_id')
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        if user_id is None:
            user_id = generate_unique_cookie_id()
        response = make_response(render_template('index.html', mobile=mobile, pc=pc))
        response.set_cookie('user_id', user_id, max_age=31536000, secure=True, httponly=True)
        return response
    else:
        return "Forked website. Do not use!"

@app.route('/about')
def information():
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('information.html', mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not use!"

@app.route('/results')
def results():
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('results.html', mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not use!"

def check_vulgarity(user_input):
    file_path = "/home/BB21/mysite/text/vulgarities.txt"
    with open(file_path, "r") as file:
        vulgarities = file.read()
    for line in vulgarities.split('\n'):
        vulgar_word = line.strip().lower()
        pattern = r'\b' + re.escape(vulgar_word) + r'\b'
        user_input = re.sub(pattern, '*' * len(vulgar_word), user_input)
    return user_input

def translate_to_english(text):
    try:
        translation = translator.translate(text, dest="en")
        return translation.text
    except Exception as e:
        print(f"Translation Error: {e}")
        return text

@app.route('/send_feedback', methods=['GET', 'POST'])
def send_feedback():
    if request.method == 'POST':
        name = request.form['feedback_name']
        message = request.form["message"]
        filtered_message = check_vulgarity(message)
        filtered_name = check_vulgarity(name)
        translated_message = translate_to_english(filtered_message)
        recipients = ['dylanyeowf@gmail.com', 'imnotjessicachan@gmail.com']
        subject = 'BB Resource Page feedback'
        msg = Message(subject=subject, sender=app.config['MAIL_USERNAME'], recipients=recipients, reply_to=None)
        html_body = f'''
            <html>
            <body>
                <h2>A feedback has been sent.</h2>
                <h4>Name: {filtered_name}</h4>
                <h4>Feedback:</h4>
                <p>{translated_message}</p>
                <br>
                <p>This is an automated message, please do not reply.</p>
                <hr>
                <footer>21st Company | GMSS</footer>
            </body>
            </html>
        '''
        msg.html = render_template_string(html_body)
        msg.extra_headers = {'X-Mailgun-Tag': 'no-reply'}
        mail.send(msg)
    return redirect("/")

@app.route('/instruction')
def instruction():
	user_agent = request.headers.get('User-Agent').lower()
	mobile = any(device in user_agent for device in ['iphone','android','ipad'])
	pc = any(device in user_agent for device in ['windows','macintosh','cros'])
	requested_url = urlparse(request.url).hostname
	if requested_url == link:
		if not pc and not mobile:
			return "This device is not supported"
		else:
			return render_template('instructions.html', mobile=mobile, pc=pc)
	else:
		return "Forked website. Do not use!"

@app.route('/admin_login')
def admin():
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('admin_login.html', mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not use!"

def lines_30():
    try:
        with open("/home/BB21/mysite/text/login_time.txt", 'r') as file:
            lines = file.readlines()
        trimmed_lines = lines[-30:]
        with open("/home/BB21/mysite/text/login_time.txt", 'w') as file:
            file.writelines(trimmed_lines)
    except Exception as e:
        print(f"An error occurred: {e}")

def record_logout(user_type):
    sg_timezone = pytz.timezone("Asia/Singapore")
    current_datetime = dt.now(sg_timezone)
    datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    with open("/home/BB21/mysite/text/login_time.txt", "ab") as file:
        encrypted_line = cipher.encrypt(f"{user_type} logout: {datetime}".encode())
        file.write(encrypted_line + b'\n')
        file.close()

with open(check_guest_password , 'rb') as file:
	lines = file.readlines()
	guest_password = lines[0].strip() if lines else b''

@app.route('/check_password', methods=['POST', 'GET'])
def check_password():
    if request.method == "POST":
        client_ip = request.cookies.get('user_id')
        user_password = request.form['password']
        if is_ip_blocked(client_ip)[0]:
            blocked, blocked_id = is_ip_blocked(client_ip)
            flash(Markup(f'Too many incorrect login attempts. Your IP address has been blocked.<br><br>User ID: {blocked_id}'))
            return redirect('/admin_login')

        if user_password == Main_code:
            record_login("Admin")
            lines_30()
            session.pop('login_attempts', None)
            session['user_type'] = "admin"
            session['authenticated'] = True
            return redirect('/admin_tools')

        if guest_password and bcrypt.checkpw(user_password.encode('utf-8'), guest_password):
            record_login("Guest")
            lines_30()
            session.pop('login_attempts', None)
            session['user_type'] = "guest"
            session['authenticated'] = True
            return redirect('/admin_tools')

        else:
            increment_login_attempts(client_ip)

            if get_login_attempts(client_ip) >= max_login_attempts:
                new_id = block_ip(client_ip)
                flash(Markup(f'Too many incorrect login attempts.<br>Your IP address has been blocked.<br>User ID: {new_id}'))
                return redirect('/admin_login')

            elif get_login_attempts(client_ip) == 3:
                flash('One additional unsuccessful password attempt will result in an lockout.')
                return redirect('/admin_login')

            else:
                flash("Incorrect password. Please try again.")
                return redirect('/admin_login')
    return redirect('/admin_login')

def decrypt_file1(file_path):
    with open(file_path, 'rb') as file:
        encrypted_lines = file.readlines()
    decrypted_lines = [cipher.decrypt(line.strip()).decode("utf-8") for line in encrypted_lines]
    return decrypted_lines

@app.route('/admin_tools')
def admin_tools():
    if ('authenticated' not in session):
        return redirect("/admin_login")
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    session_lifetime = current_app.config['PERMANENT_SESSION_LIFETIME']
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('admin_tools.html', session_lifetime=session_lifetime, mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not use!"

@app.route('/admin_login_time')
def log():
    decrypted_content = decrypt_file1('/home/BB21/mysite/text/login_time.txt')
    session_lifetime = current_app.config['PERMANENT_SESSION_LIFETIME']
    if ('authenticated' not in session):
        return redirect("/admin_login")
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('admin_log.html', session_lifetime=session_lifetime, login_records=decrypted_content, mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not use!"

@app.route('/inventory_management')
def inventory():
    if ('authenticated' not in session):
        return redirect("/admin_login")
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    data = load_data()
    session_lifetime = current_app.config['PERMANENT_SESSION_LIFETIME']
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('admin_inventory.html', data=data, session_lifetime=session_lifetime, pc=pc, mobile=mobile)
    else:
        return "Forked website. Do not use!"

def load_data():
    with open("/home/BB21/mysite/text/inventory.txt", "r") as file:
        lines = file.readlines()
        data = [line.strip().split(",") for line in lines]
    data = [(item.strip(), price.strip(), current_qty.strip(), total_qty.strip()) for item, price, current_qty, total_qty in data]
    return data

def save_data(data):
    with open("/home/BB21/mysite/text/inventory.txt", "w") as file:
        for item in data:
            file.write(",".join(item) + "\n")
    file.close()

@app.route("/logout")
def logout():
    if ('authenticated' not in session) or (session['user_type'] != "admin"):
        return redirect("/admin_login")
    record_logout("Admin")
    session.pop('authenticated', None)
    lines_30()
    return redirect("/admin_login")

@app.route("/logout1")
def logout1():
    if ('authenticated' not in session) or (session['user_type'] != "guest"):
        return redirect("/admin_login")
    record_logout("Guest")
    session.pop('authenticated', None)
    lines_30()
    return redirect("/admin_login")

@app.route('/process', methods=['POST'])
def process():
	global global_shop_open
	global_shop_open = False
	if request.method == "POST":
		name = request.form.get('name')
		selected_item = request.form.get('item')
		quantity = int(request.form.get('quantity'))
		password1 = request.form.get('password')
		verifier = request.form.get('verifier')
		email = request.form.get('email')
		items, max_quantity = load_items()
		selected_item_price = items[selected_item]['price']
		available_quantity = items[selected_item]['current_qty']
		total_price = selected_item_price * quantity
		sg_timezone = pytz.timezone("Asia/Singapore")
		formatted_total_price = f"${total_price:.2f}"
		current_datetime = dt.now(sg_timezone)
		datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
		if (password1 == Main_code) and (quantity <= available_quantity):
			items[selected_item]['current_qty'] -= quantity
			items[selected_item]['total_qty'] -= quantity
			with open("/home/BB21/mysite/text/name.txt", 'ab') as file:
				encrypted_full = cipher.encrypt(f"{datetime}, {selected_item}, {name}, {quantity}, {formatted_total_price}, {verifier},?, no \n".encode())
				file.write(encrypted_full + b'\n')
				file.close()
			with open("/home/BB21/mysite/text/inventory.txt", 'w') as file:
				for item, details in items.items():
					file.write(f"{item}, {details['price']}, {details['current_qty']}, {details['total_qty']}\n")
			file.close()
			if 'email' in request.form.keys() and request.form['email'] != '':
				recipient = email
				subject = 'Purchase Confirmation'
				message = Message(subject=subject, sender=app.config['MAIL_USERNAME'], recipients=[recipient], reply_to=None)
				html_body = f'''
					<html>
					<body>
						<p>Dear {name},</p>
						<br>
						<p>At {datetime}, You have bought the following item:
						<p>Item: {selected_item}</p>
						<p>Quantity: {quantity}</p>
						<p>Total price: {formatted_total_price}</p>
						<p>Verified by: {verifier}</p>
						<br>
						<p>As such, a consequence would be given. <a href="rp.bb21gm.repl.co/purchase_history">Click here.</a><p>
						<br>
						<p>If you think there is an error, please inform the following people:</p>
						<ul>
							<li>CSM</li>
							<li>DY CSM</li>
							<li>Logistics SGT</li>
							<li>Awards SGT</li>
						</ul>
						<br>
						<p>This is an automated message, please do not reply.</p>
						<hr>
						<footer>21st Company | GMSS</footer>
					</body>
					</html>
				'''
				rendered_html = render_template_string(html_body)
				message.html = rendered_html
				mail.send(message)
				print("pass")
				session["results"] = "success"
				return redirect("/results")
			else:
				session["results"] = "success"
				return redirect("/results")
		else:
			session["results"] = "fail"
			return redirect("/results")
	return redirect("/buy")

@app.route('/update_quantity_all', methods=['POST'])
def update_quantity_all():
    if 'authenticated' not in session:
        return redirect("/admin_login")
    new_data = request.json.get('data')
    data = load_data()
    for i in range(len(data)):
        current_qty = int(new_data[i]['current_quantity'])
        total_qty = int(new_data[i]['total_quantity'])
        item_list = list(data[i])
        item_list[2] = str(current_qty)
        item_list[3] = str(total_qty)
        data[i] = tuple(item_list)
    save_data(data)
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    if not pc and not mobile:
        return "This device is not supported"
    return render_template('admin_inventory.html', data=data, mobile=mobile, pc=pc)

@app.route('/purchase_history')
def punishment():
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    decrypted_lines = decrypt_file1("/home/BB21/mysite/text/name.txt")
    stripped_lines = [line.strip().split(',') for line in decrypted_lines]
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('purchase_history.html', stripped_lines=stripped_lines, pc=pc, mobile=mobile)
    else:
        return "Forked website. Do not use!"

def get_login_attempts(ip_address):
    return session.get('login_attempts', {}).get(ip_address, 0)

def increment_login_attempts(ip_address):
    if 'login_attempts' not in session:
        session['login_attempts'] = {}
    session['login_attempts'][ip_address] = get_login_attempts(ip_address) + 1

def block_ip(ip_address):
    existing_ids = set()
    with open(blocked_ips_file, 'rb') as file:
        for line in file:
            existing_id = line.strip()
            existing_ids.add(int(existing_id))

    encrypted_line = cipher.encrypt(f"{ip_address}".encode())

    with open(blocked_ips_file, 'ab') as file:
        file.write(encrypted_line + b'\n')
        file.close()

def is_ip_blocked(ip_address):
    decrypted_lines = decrypt_file1(blocked_ips_file)
    blocked_ips_list = set(decrypted_lines)

    for ip_id in blocked_ips_list:
        if ip_id == ip_address:
            return True, ip_address

    return False, None

def record_login(user_type):
    sg_timezone = pytz.timezone("Asia/Singapore")
    current_datetime = dt.now(sg_timezone)
    datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    file_path = "/home/BB21/mysite/text/login_time.txt"
    with open(file_path, "ab") as file:
        encrypted_line = cipher.encrypt(f"{user_type} login: {datetime}\n".encode())
        file.write(encrypted_line + b'\n')
        file.close()

@app.route('/feedback_form')
def feedback():
    session["results"] = "feedback"
    return redirect("/results")

def shop():
    sg_timezone = pytz.timezone("Asia/Singapore")
    current_datetime = dt.now(sg_timezone)
    current_hour = current_datetime.hour
    current_minute = current_datetime.minute
    day_of_week = current_datetime.weekday()
    if ((day_of_week == 2 or day_of_week == 4) and (current_hour == 6 and 45 <= current_minute <= 59) or (current_hour == 7 and current_minute <= 15)) or (day_of_week == 6 and (current_hour == 7 and 45 <= current_minute <= 59) or (current_hour == 8 and current_minute <= 15)):
        return True
    else:
        return False

@app.route('/bypass')
def bypass():
    global global_shop_open
    global_shop_open = True
    return redirect('/buy')

def load_items():
    items = {}
    max_quantity = {}
    with open("/home/BB21/mysite/text/inventory.txt", 'r') as file:
        for line in file:
            data = line.strip().split(',')
            item = data[0]
            price = float(data[1])
            current_qty = int(data[2])
            total_qty = int(data[3])
            items[item] = {'price': price, 'current_qty': current_qty, 'total_qty': total_qty}
            max_quantity[item] = current_qty
    return items, max_quantity

@app.route('/buy')
def buy():
    global global_shop_open
    shop_open = global_shop_open or shop()
    items, max_quantity = load_items()
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('buy.html', items=items, shop_open=shop_open, max_quantity=max_quantity, mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not use!"

@app.route("/JS_disabled")
def JS_disabled():
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('no-script.html', mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not use!"

@app.errorhandler(404)
def page_not_found(error):
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('404.html', mobile=mobile, pc=pc), 404
    else:
        return "Forked website. Do not use!"

@app.errorhandler(405)
def method_not_allowed(error):
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('405.html', mobile=mobile, pc=pc), 405
    else:
        return "Forked website. Do not use!"

@app.route('/change_password_process', methods=['POST'])
def change_password_process():
    global guest_password
    if ('authenticated' not in session) or (session['user_type'] != "admin"):
        return redirect("/admin_login")
    if request.method == 'POST':
        current_password = request.form['current-password']
        new_password = request.form['new-password']
        if bcrypt.checkpw(current_password.encode('utf-8'), guest_password):
            new_password_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            with open('/home/BB21/mysite/text/password.txt', 'wb') as file:
                file.write(new_password_hashed)
            guest_password = new_password_hashed
            return redirect("/change_password_success")
        else:
            return "Incorrect Current Password. Action not performed."
    return redirect("/change_password")

@app.route("/change_password")
def change_password():
    if ('authenticated' not in session) or (session['user_type'] != "admin"):
        return redirect("/admin_login")
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('admin_password.html', mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not use!"

@app.route('/change_password_success')
def change_password_success():
    if ('authenticated' not in session) or (session['user_type'] != "admin"):
        return redirect("/admin_login")
    return "Password successfully changed!"

@app.route('/reset_password')
def reset_password():
    if ('authenticated' not in session) or (session["user_type"] != "admin"):
        return redirect("/admin_login")
    hashed_default_password = bcrypt.hashpw(guest_code.encode('utf-8'), bcrypt.gensalt())
    with open('/home/BB21/mysite/text/password.txt', 'wb') as file:
        file.write(hashed_default_password)
    return "Password reset to default Guest_BB21"

@app.route('/purchase_editor')
def purchase_editor():
    if 'authenticated' not in session:
        return redirect("/admin_login")
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    decrypted_types = decrypt_file1("/home/BB21/mysite/text/punishment types.txt")
    decrypted_lines = decrypt_file1("/home/BB21/mysite/text/name.txt")
    stripped_lines = [line.strip().split(',') for line in decrypted_lines]
    requested_url = urlparse(request.url).hostname
    session_lifetime = current_app.config['PERMANENT_SESSION_LIFETIME']
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('admin_purchase.html', stripped_lines=stripped_lines, decrypted_types=decrypted_types, pc=pc, mobile=mobile, session_lifetime=session_lifetime)
    else:
        return "Forked website. Do not use!"

@app.route('/purchase_editor_save', methods=["POST"])
def purchase_editor_save():
    if ('authenticated' not in session):
        return redirect("/admin_login")
    if request.method == "POST":
        decrypted_lines = decrypt_file1("/home/BB21/mysite/text/name.txt")
        selected_punishments = request.form.getlist("selected_punishments")
        selected_statuses = request.form.getlist("selected_status")
        encrypted_lines = []
        for i, decrypted_line in enumerate(decrypted_lines):
            parts = decrypted_line.strip().split(',')
            parts[6] = selected_punishments[i]
            parts[7] = selected_statuses[i]
            updated_line = ','.join(parts) + '\n'
            encrypted_line = cipher.encrypt(updated_line.encode())
            encrypted_lines.append(encrypted_line)
        with open("/home/BB21/mysite/text/name.txt", "wb") as file:
            file.write(b'\n'.join(encrypted_lines) + b'\n')
    return redirect("/purchase_editor")

@app.route('/punishment_types')
def punishment_types():
    # if ('authenticated' not in session) or (session["user_type"] != "admin"):
    #     return redirect("/admin_login")
    session_lifetime = current_app.config['PERMANENT_SESSION_LIFETIME']
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    decrypted_punishment_types = decrypt_file1("/home/BB21/mysite/text/punishment types.txt")
    requested_url = urlparse(request.url).hostname
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('admin_punishment_types.html', decrypted_punishment_types=decrypted_punishment_types, pc=pc, mobile=mobile, session_lifetime=session_lifetime)
    else:
        return "Forked website. Do not use!"

@app.route('/punishment_type_add', methods=["POST"])
def punishment_type_add():
    if ('authenticated' not in session) or (session["user_type"] != "admin"):
        return redirect("/admin_login")
    if request.method == "POST":
        punishment = request.form["punishment_type"]
        verify = request.form["purchase_editor_verify"]
        if verify == Main_code:
            with open("/home/BB21/mysite/text/punishment types.txt", "rb") as file:
                existing_punishments = [cipher.decrypt(line.strip()).decode('utf-8').lower() for line in file.readlines()]
            if punishment.lower() not in existing_punishments:
                keyed_punishment = cipher.encrypt(f"{punishment} \n".encode())
                with open("/home/BB21/mysite/text/punishment types.txt", "ab") as file:
                    file.write(keyed_punishment + b"\n")
                return redirect("/punishment_types")
            else:
                return "Punishment already exists"
        else:
            return "Password incorrect"
    return redirect("/punishment_types")

@app.route('/punishment_type_remove', methods=["POST"])
def punishment_type_remove():
    if ('authenticated' not in session) or (session["user_type"] != "admin"):
        return redirect("/admin_login")
    if request.method == "POST":
        punishment = request.form["punishment_type_r"]
        verify = request.form["purchase_editor_verify_r"]
        if verify == Main_code:
            with open("/home/BB21/mysite/text/punishment types.txt", "rb") as file:
                encrypted_lines = file.readlines()
            decrypted_lines = [cipher.decrypt(line.strip()) for line in encrypted_lines]
            modified_lines = [line for line in decrypted_lines if bytes(punishment, 'utf-8') not in line]
            encrypted_modified_content = "\n".join([cipher.encrypt(line).decode('utf-8') for line in modified_lines])
            with open("/home/BB21/mysite/text/punishment types.txt", "wb") as file:
                file.write(encrypted_modified_content.encode())
                file.close()
        else:
            return "Password incorrect"
    return redirect("/punishment_types")

@app.route("/borrow", methods=["POST"])
def borrow():
    if request.method == "POST":
        name = request.form["borrow_name"]
        item = request.form["borrow_item"]
        quantity = int(request.form["borrow_quantity"])
        return_date = request.form["borrow_return_date"]
        verifier = request.form["borrow_verifier"]
        keyed_password = request.form["borrow_verifier_password"]
        items, max_quantity = load_items()
        available_quantity = items[item]['current_qty']
        sg_timezone = pytz.timezone("Asia/Singapore")
        current_datetime = dt.now(sg_timezone)
        datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
        if (keyed_password == Main_code) and (quantity <= available_quantity):
            items[item]['current_qty'] -= quantity
            with open("/home/BB21/mysite/text/borrow.txt", "rb") as file:
                lines = file.readlines()
            if lines:
                last_line = lines[-1]
                decrypted_last_line = cipher.decrypt(last_line).decode().strip(",")
                existing_counter = int(decrypted_last_line.split(",")[8].strip())
                new_counter = existing_counter + 1
            else:
                new_counter = 1
            with open("/home/BB21/mysite/text/borrow.txt", "ab") as file:
                for item_name, details in items.items():
                    encrypted = cipher.encrypt(f"{datetime},{item},{name},{quantity},{verifier},{return_date},outstanding,?,{new_counter}".encode())
                    file.write(encrypted + b'\n')
                    break
            with open("/home/BB21/mysite/text/inventory.txt", 'w') as file:
                for item, details in items.items():
                    file.write(f"{item},{details['price']},{details['current_qty']},{details['total_qty']}\n")
            session["results"] = "success"
            return redirect("/results")
        else:
            session["results"] = "fail"
            return redirect("/results")
    return redirect("/borrow_and_return")

@app.route('/borrow_and_return')
def borrow_and_return():
    items, max_quantity = load_items()
    data = []
    with open("/home/BB21/mysite/text/borrow.txt", 'rb') as file:
        encrypted_lines = file.readlines()
    decrypted_lines = [cipher.decrypt(line.strip()).decode("utf-8") for line in encrypted_lines]
    data = [line.split(",") for line in decrypted_lines]
    outstanding_items = [item[2] for item in data if item[6].strip().lower() == 'outstanding']
    requested_url = urlparse(request.url).hostname
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('borrow.html', items=items, max_quantity=max_quantity, outstanding_items=outstanding_items, data=data, mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not website."

@app.route("/return", methods=["POST"])
def return_item():
    if request.method == "POST":
        selected_option = request.form["return_select"]
        selected_id = request.form["borrow_id"]
        error_message = "wrong"
        items, max_quantity = load_items()
        with open("/home/BB21/mysite/text/borrow.txt", "rb") as file:
            lines = file.readlines()
        for index, line in enumerate(lines):
            parts = cipher.decrypt(line).decode().split(',')
            part_1 = selected_option.split("_")[0]
            if (part_1 == parts[1]) and (selected_id == parts[8].strip()):
                quantity = int(parts[3])
                items[part_1]['current_qty'] += quantity
                sg_timezone = pytz.timezone("Asia/Singapore")
                current_datetime = dt.now(sg_timezone)
                return_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
                parts[7] = parts[7].replace("?", return_datetime)
                parts[6] = parts[6].replace("outstanding", "returned")
                lines[index] = cipher.encrypt(', '.join(parts).encode()) + b'\n'
                error_message = None
                break
        if error_message:
            return error_message
        with open("/home/BB21/mysite/text/borrow.txt", "wb") as file:
            file.writelines(lines)
            file.close()
        with open("/home/BB21/mysite/text/inventory.txt", 'w') as file:
            for item, details in items.items():
                file.write(f"{item},{details['price']},{details['current_qty']},{details['total_qty']}\n")
        return redirect("/borrow_and_return")
    return redirect("/borrow_and_return")

@app.route("/unban_tool")
def unban_tool():
    if ('authenticated' not in session) or (session["user_type"] != "admin"):
        return redirect("/admin_login")
    requested_url = urlparse(request.url).hostname
    user_agent = request.headers.get('User-Agent').lower()
    mobile = any(device in user_agent for device in ['iphone','android','ipad'])
    pc = any(device in user_agent for device in ['windows','macintosh','cros'])
    if requested_url == link:
        if not pc and not mobile:
            return "This device is not supported"
        else:
            return render_template('admin_unban_tool.html', mobile=mobile, pc=pc)
    else:
        return "Forked website. Do not website."

def id_exists(target_id):
    decrypted_lines = decrypt_file1(blocked_ips_file)
    ids_in_file = [line.strip() for line in decrypted_lines]
    target_id = target_id.strip()

    for id_in_file in ids_in_file:
        if target_id == id_in_file.strip():
            return True

    return False

def delete_row_by_id(target_id):
    decrypted_lines = decrypt_file1(blocked_ips_file)
    lines = decrypted_lines
    updated_lines = [line for line in lines if target_id not in line.strip()]

    with open(blocked_ips_file, 'wb') as file:
        encrypted_updated_lines = [cipher.encrypt(line.encode()) for line in updated_lines]
        file.writelines(encrypted_updated_lines)
    file.close()

@app.route("/unban_ip_process", methods=["POST"])
def unban_ip_process():
    if request.method == "POST":
        ip_to_delete = request.form["unban_tool_id_input"]
        if ip_to_delete:
            if id_exists(ip_to_delete):
                delete_row_by_id(ip_to_delete)
                flash(f'ID {ip_to_delete} Unbanned.')
            else:
                flash(f'ID {ip_to_delete} does not exist.')
        else:
            flash('Please enter an ID to unban.')

    return redirect("/unban_tool")

def item_exist(new_item_name):
    with open("/home/BB21/mysite/text/inventory.txt", "r") as file:
        for line in file:
            existing_item_name = line.split(",")[0].strip().lower()
            if existing_item_name == new_item_name:
                return True
    return False

@app.route("/IM_add", methods=["POST"])
def IM_add():
    if ("authenticated" not in session) or (session["user_type"] != "admin"):
        return redirect("/admin_login")
    if request.method == "POST":
        item_name = request.form["IM_add_item_name"].capitalize()
        price = request.form["IM_add_price"]
        current_quantity = request.form["IM_add_cq"]
        total_quantity = request.form["IM_add_tq"]
        if not item_exist(item_name):
            with open("/home/BB21/mysite/text/inventory.txt", "a") as file:
                file.write(f"{item_name},{price},{current_quantity},{total_quantity} \n")
                file.close()
        else:
            flash("Item already exist.")
    return redirect("/inventory_management")

def read_inventory_data():
    inventory_data = []
    with open("/home/BB21/mysite/text/inventory.txt", "r") as file:
        for line in file:
            item,cost,current_qty,total_qty = line.strip().split(",")
            inventory_data.append((item, cost, current_qty, total_qty))
    return inventory_data

def update_inventory_file(inventory_data, removed_row):
    # Update the text file with the modified inventory data
    with open("/home/BB21/mysite/text/inventory.txt", "w") as file:
        for item, cost, current_qty, total_qty in inventory_data:
            if (item, cost, current_qty, total_qty) != removed_row:
                file.write(f"{item},{cost},{current_qty},{total_qty}\n")

@app.route("/IM_remove", methods=["POST"])
def IM_remove():
    if ("authenticated" not in session) or (session["user_type"] != "admin"):
        return redirect("/admin_login")
    if request.method == "POST":
        row = int(request.form["IM_remove_row"])
        inventory_data = read_inventory_data()
        if 1 <= row <= len(inventory_data):
            removed_row = inventory_data.pop(row - 1)
            update_inventory_file(inventory_data, removed_row)
            return redirect("/inventory_management")
        else:
            flash("Row does not exist.")
    return redirect("/inventory_management")


if __name__ == '__main__':
    app.run(port=5005, host="0.0.0.0")

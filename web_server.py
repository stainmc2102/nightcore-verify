from flask import Flask, request, jsonify, render_template
import os
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY', '')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY', '')
API_SECRET = os.getenv('API_SECRET', '')

verified_users = set()
user_info_store = {}


def check_secret():
    if API_SECRET:
        return request.headers.get('X-API-Secret', '') == API_SECRET
    return True


def verify_recaptcha(token):
    if not RECAPTCHA_SECRET_KEY:
        return True
    try:
        resp = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
            'secret': RECAPTCHA_SECRET_KEY,
            'response': token
        })
        return resp.json().get('success', False)
    except Exception as e:
        print(f"Lỗi reCAPTCHA: {e}")
        return False


@app.route('/')
def home():
    return render_template('verify.html',
                           site_key=RECAPTCHA_SITE_KEY,
                           user_id=None,
                           user_info=None,
                           already_verified=False)


@app.route('/verify/<user_id>')
def verify_page(user_id):
    user_info = user_info_store.get(user_id)
    already_verified = user_id in verified_users
    return render_template('verify.html',
                           site_key=RECAPTCHA_SITE_KEY,
                           user_id=user_id,
                           user_info=user_info,
                           already_verified=already_verified)


@app.route('/api/register-user', methods=['POST'])
def register_user():
    if not check_secret():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    user_id = data.get('user_id')
    user_info = data.get('user_info')
    if not user_id or not user_info:
        return jsonify({'success': False, 'error': 'Thiếu dữ liệu'}), 400
    user_info_store[user_id] = user_info
    return jsonify({'success': True})


@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Invalid request'}), 400

    user_id = data.get('user_id', '')
    captcha_token = data.get('captcha_token', '')

    if not user_id:
        return jsonify({'success': False, 'error': 'Thiếu user_id'}), 400

    if user_id in verified_users:
        return jsonify({'success': True, 'already_verified': True})

    if not captcha_token:
        return jsonify({'success': False, 'error': 'Vui lòng hoàn thành captcha'}), 400

    if not verify_recaptcha(captcha_token):
        return jsonify({'success': False, 'error': 'Xác minh captcha thất bại. Vui lòng thử lại.'}), 400

    verified_users.add(user_id)
    print(f"Người dùng {user_id} đã xác minh thành công!")
    return jsonify({'success': True})


@app.route('/api/status/<user_id>')
def check_status(user_id):
    return jsonify({'user_id': user_id, 'verified': user_id in verified_users})


@app.route('/health')
def health():
    return jsonify({'status': 'ok'})


def run_flask_app():
    port = int(os.getenv('PORT', '3000'))
    print(f"Web server đang chạy tại cổng {port}")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)


if __name__ == '__main__':
    run_flask_app()

